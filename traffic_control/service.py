"""Application composition and adapters between the desktop UI and services."""
from __future__ import annotations

import json
import csv
import io
import os
from datetime import datetime
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

import httpx

from .core import AuditStore, PolicyEngine, PolicyRule
from .gateway import Gateway, GatewaySettings


def _app_dir() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AI Traffic Control"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _read_key() -> str:
    try:
        import keyring
        return keyring.get_password("AI Traffic Control", "provider_api_key") or ""
    except Exception:
        return ""


def save_key(value: str) -> None:
    """Store only in the operating-system keyring; never fall back to a file."""
    import keyring
    if value:
        keyring.set_password("AI Traffic Control", "provider_api_key", value)


class StoreFacade:
    """Small UI-friendly wrapper around the metadata-only SQLite store."""
    def __init__(self, store: AuditStore, settings: dict[str, Any], settings_path: Path):
        self._store = store
        self._settings = settings
        self._settings_path = settings_path
        self.gateway: GatewayController | None = None

    def list_requests(self, limit: int = 500, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        filters = filters or {}
        return self._store.list_requests(limit=limit, outcome=filters.get("outcome", ""),
                                         provider=filters.get("provider", ""), since=filters.get("since", ""))

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        row = self._store.get_request(request_id)
        if row and self.gateway is not None:
            payload = self.gateway.get_request_payload(request_id, False)
            if payload:
                messages = payload.get("messages", [])
                row["masked_prompt"] = "\n\n".join(
                    f"{message.get('role', 'message')}: {message.get('content', '') if isinstance(message.get('content'), str) else json.dumps(message.get('content'), ensure_ascii=False)}"
                    for message in messages if isinstance(message, dict))
        return row

    def get_request_payload(self, request_id: str, reveal: bool = False) -> dict[str, Any] | None:
        return self.gateway.get_request_payload(request_id, reveal) if self.gateway is not None else None

    def summary(self) -> dict[str, Any]:
        base = self._store.summary()
        outcomes = base.get("outcomes", {})
        today = datetime.now().astimezone().date().isoformat()
        rows_today = []
        for row in self._store.list_requests(limit=5000):
            try:
                if datetime.fromisoformat(str(row.get("timestamp", ""))).astimezone().date().isoformat() == today:
                    rows_today.append(row)
            except ValueError:
                continue
        return {**base, "today": len(rows_today),
                "allowed": sum(v for k, v in outcomes.items() if k == "forwarded"),
                "denied": sum(v for k, v in outcomes.items() if k in {"denied_by_policy", "review_denied", "review_timeout", "review_unavailable", "invalid_request", "policy_error", "gateway_stopped"}),
                "review": sum(v for k, v in outcomes.items() if k in {"review_pending", "review", "approved"})}

    def save_settings(self, settings: Mapping[str, Any]) -> None:
        # API keys are intentionally excluded even if a caller passes one.
        allowed = {k: settings[k] for k in ("bind_host", "port", "provider_url", "model", "client_label", "max_body_mb", "review_timeout_seconds") if k in settings}
        self._settings.clear()
        self._settings.update(allowed)
        self._settings_path.write_text(json.dumps(allowed, indent=2), encoding="utf-8")

    def list_cases(self) -> list[dict[str, Any]]:
        rows = self._store.list_cases()
        for row in rows:
            row["id"] = row.get("case_id")
            row["request_id"] = ", ".join(row.get("request_ids", []))
        return rows

    def create_case(self, request_id: str | None, title: str, note: str = "") -> str:
        related = [value.strip() for value in str(request_id or "").split(",") if value.strip()]
        return self._store.create_case(title, note, related)

    def update_case(self, case_id: str, status: str, note: str, *, title: str | None = None,
                    request_ids: str | list[str] | None = None) -> None:
        related = request_ids if isinstance(request_ids, list) else ([x.strip() for x in request_ids.split(",") if x.strip()] if request_ids is not None else None)
        self._store.update_case(case_id, title=title, notes=note, status=status, request_ids=related)

    def export_csv(self, path: str, filters: dict[str, Any] | None = None) -> bool:
        filters = filters or {}
        category = str(filters.get("outcome", "")).lower()
        rows = self._store.list_requests(limit=5000, since=filters.get("since", ""))
        def include(row: dict[str, Any]) -> bool:
            decision, outcome = str(row.get("decision", "")).lower(), str(row.get("outcome", "")).lower()
            if category in {"", "all outcomes"}: return True
            if category == "allow": return decision == "allow" and outcome == "forwarded"
            if category == "review": return decision == "review"
            if category == "deny": return decision == "deny" or outcome in {"review_denied", "review_timeout", "denied_by_policy"}
            if category == "error": return "error" in outcome or "timeout" in outcome
            return outcome == category or decision == category
        rows = [row for row in rows if include(row)]
        fields = ["timestamp", "request_id", "provider", "model", "client_label", "data_classes", "rule_ids", "decision", "outcome", "elapsed_ms", "upstream_status", "reason"]
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            safe = dict(row)
            for key in ("data_classes", "rule_ids"):
                safe[key] = json.dumps(safe.get(key, []), ensure_ascii=False)
            writer.writerow(safe)
        csv_text = buffer.getvalue()
        Path(path).write_text(csv_text, encoding="utf-8-sig", newline="")
        return True


class PolicyFacade:
    """Normalizes editable UI rule dictionaries into the policy engine model."""
    def __init__(self, engine: PolicyEngine):
        self.engine = engine

    @staticmethod
    def _rule_dict(rule: PolicyRule) -> dict[str, Any]:
        row = asdict(rule)
        row["id"] = rule.id
        row["provider"] = ", ".join(rule.providers)
        row["model"] = ", ".join(rule.models)
        row["client_label"] = ", ".join(rule.client_labels)
        row["exceptions"] = list(rule.exclusions)
        return row

    @staticmethod
    def _normalize(data: Mapping[str, Any], rule_id: str | None = None) -> dict[str, Any]:
        def values(key: str, singular: str) -> list[str]:
            value = data.get(key, data.get(singular, []))
            if isinstance(value, str):
                value = [p.strip() for p in value.split(",") if p.strip()]
            return list(value or [])
        return {
            "id": rule_id or str(data.get("id") or uuid4()),
            "name": str(data.get("name", "New rule")),
            "description": str(data.get("description", "")),
            "priority": int(data.get("priority", 100)),
            "action": str(data.get("action", "review")).lower(),
            "enabled": bool(data.get("enabled", True)),
            "data_classes": values("data_classes", "data_class"),
            "providers": values("providers", "provider"),
            "models": values("models", "model"),
            "client_labels": values("client_labels", "client_label"),
            "exclusions": values("exclusions", "exceptions"),
            "pattern": str(data.get("pattern", "")),
            "keyword": str(data.get("keyword", "")),
        }

    def list_rules(self) -> list[dict[str, Any]]:
        return [self._rule_dict(rule) for rule in self.engine.list_rules()]

    def add_rule(self, data: Mapping[str, Any]) -> bool:
        self.engine.add_rule(self._normalize(data))
        return True

    def update_rule(self, rule_id: str, data: Mapping[str, Any]) -> bool:
        self.engine.update_rule(rule_id, **self._normalize(data, rule_id))
        return True

    def delete_rule(self, rule_id: str) -> bool:
        self.engine.delete_rule(rule_id)
        return True

    def evaluate(self, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context or {}
        result = self.engine.evaluate({"messages": [{"role": "user", "content": text}]},
                                      provider=str(context.get("provider", "openai-compatible")),
                                      model=str(context.get("model", "offline-sample")),
                                      client_label=str(context.get("client_label", "")),
                                      endpoint=str(context.get("endpoint", context.get("provider", ""))))
        return result.to_dict()


class ReviewFacade:
    def __init__(self, gateway: Gateway):
        self.gateway = gateway

    def list_pending(self) -> list[dict[str, Any]]:
        return self.gateway.pending_reviews()

    def approve(self, request_id: str) -> bool:
        return self.gateway.resolve_review(request_id, True)

    def deny(self, request_id: str, reason: str = "Denied by reviewer") -> bool:
        return self.gateway.resolve_review(request_id, False)

    def get_payload(self, request_id: str, reveal: bool = False) -> dict[str, Any] | None:
        return self.gateway.get_review_payload(request_id, reveal)


class GatewayController:
    """UI adapter translating simple settings into the HTTP gateway config."""
    def __init__(self, gateway: Gateway, settings: dict[str, Any], settings_changed: Any = None):
        self.gateway = gateway
        self.settings = settings
        self.settings_changed = settings_changed

    def _typed(self, settings: Mapping[str, Any]) -> GatewaySettings:
        bind_host = str(settings.get("bind_host", "127.0.0.1"))
        if bind_host not in {"127.0.0.1", "localhost"}:
            raise ValueError("Only loopback bind addresses are supported.")
        return GatewaySettings(
            bind_host=bind_host,
            port=int(settings.get("port", 8765)),
            upstream_base_url=str(settings.get("provider_url", "https://api.openai.com/v1")).rstrip("/"),
            model=str(settings.get("model", "gpt-4o-mini")),
            client_label=str(settings.get("client_label", "")),
            api_key=_read_key(),
            max_body_bytes=max(1, int(settings.get("max_body_mb", 10))) * 1024 * 1024,
            review_timeout_seconds=int(settings.get("review_timeout_seconds", 120)),
        )

    def status(self) -> dict[str, Any]:
        return {**self.gateway.status, "provider_configured": bool(_read_key())}

    def start(self, settings: Mapping[str, Any] | None = None) -> bool:
        try:
            if settings:
                self.configure(settings)
            self.gateway.start()
            actual_port = self.gateway.settings.port
            if int(self.settings.get("port", 8765)) != actual_port:
                self.settings["port"] = actual_port
                if callable(self.settings_changed):
                    try:
                        self.settings_changed(self.settings)
                    except Exception:
                        pass
            self.gateway._last_error = None
            return True
        except Exception as exc:
            # Prefer the server's sanitized diagnostic, without echoing configuration or credentials.
            if not self.gateway._last_error:
                self.gateway._last_error = f"Gateway startup failed ({type(exc).__name__}: {str(exc)[:180]})."
            return False

    def stop(self) -> bool:
        try:
            self.gateway.stop()
            return True
        except Exception:
            return False

    def configure(self, settings: Mapping[str, Any]) -> None:
        settings = dict(settings)
        self.settings.clear()
        self.settings.update(settings)
        self.gateway.update_settings(self._typed(self.settings))

    def update_settings(self, settings: Mapping[str, Any]) -> None:
        self.configure(settings)

    def pending_reviews(self) -> list[dict[str, Any]]:
        return self.gateway.pending_reviews()

    def resolve_review(self, request_id: str, approve: bool) -> bool:
        return self.gateway.resolve_review(request_id, approve)

    def get_request_payload(self, request_id: str, reveal: bool = False) -> dict[str, Any] | None:
        return self.gateway.get_request_payload(request_id, reveal)

    def recent_requests(self) -> list[dict[str, Any]]:
        return self.gateway.recent_requests()

    def connection_check(self) -> tuple[bool, str]:
        """Explicit user initiated GET /models; errors never include credentials."""
        settings = self.gateway.settings
        if not settings.api_key:
            return False, "Save a provider API key in Settings first."
        url = settings.upstream_base_url.rstrip("/") + "/models"
        try:
            response = httpx.get(url, headers={"Authorization": f"Bearer {settings.api_key}"}, timeout=10.0)
            if response.status_code < 400:
                return True, f"Provider responded with HTTP {response.status_code}."
            return False, f"Provider responded with HTTP {response.status_code}. Check the endpoint, model access, and key."
        except httpx.TimeoutException:
            return False, "Provider connection timed out."
        except httpx.HTTPError:
            return False, "Could not connect to that provider endpoint."


class AppServices:
    """Owns local persistence, policies, gateway, and UI-facing adapters."""
    def __init__(self):
        self.directory = _app_dir()
        self.settings_path = self.directory / "settings.json"
        try:
            self.settings = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.settings = {}
        self.settings = {"bind_host": "127.0.0.1", "port": 8765, "provider_url": "https://api.openai.com/v1",
                         "model": "gpt-4o-mini", "client_label": "", "max_body_mb": 10,
                         "review_timeout_seconds": 120, **self.settings}
        self.audit = AuditStore()
        self.policy_engine = PolicyEngine(store=self.audit)
        self.policies = PolicyFacade(self.policy_engine)
        self.store = StoreFacade(self.audit, self.settings, self.settings_path)
        initial = GatewaySettings(
            bind_host=str(self.settings.get("bind_host", "127.0.0.1")), port=int(self.settings["port"]),
            upstream_base_url=str(self.settings["provider_url"]).rstrip("/"), model=str(self.settings["model"]),
            client_label=str(self.settings.get("client_label", "")),
            api_key=_read_key(), max_body_bytes=int(self.settings["max_body_mb"]) * 1024 * 1024,
            review_timeout_seconds=int(self.settings["review_timeout_seconds"]))
        self._gateway = Gateway(initial, self.policy_engine, recorder=self.audit)
        self.gateway = GatewayController(self._gateway, self.settings, settings_changed=self.store.save_settings)
        self.store.gateway = self.gateway
        self.reviews = ReviewFacade(self._gateway)

    def close(self) -> None:
        self._gateway.stop()

