"""Local OpenAI-compatible gateway with policy checks and in-memory review.

This module deliberately does not log request bodies or credentials. Persistence
is injected through a metadata-only recorder; request contents stay in memory
only for forwarding and any active human review.
"""

from __future__ import annotations

import asyncio
import json
import copy
import re
import socket
from collections import deque
import threading
import time
import uuid
from concurrent.futures import Future
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from .provider import OpenAICompatibleProvider, ProviderAdapter


def _open_listener(host: str, port: int, attempts: int = 32) -> tuple[socket.socket, int]:
    """Reserve a loopback listener before starting Uvicorn; scan nearby ports if needed."""
    last_error: OSError | None = None
    last_port = port
    for candidate in range(port, min(65536, port + max(1, attempts))):
        listener = socket.socket(socket.AF_INET6 if host == "::1" else socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind((host, candidate))
            listener.listen(socket.SOMAXCONN)
            listener.setblocking(False)
            return listener, int(listener.getsockname()[1])
        except OSError as exc:
            listener.close()
            last_error = exc
            last_port = candidate
            if getattr(exc, "winerror", None) not in (10013, 10048) and exc.errno not in (socket.EADDRINUSE, socket.EACCES):
                raise OSError(f"Could not bind loopback port {candidate}: {exc}") from exc
    if last_error is None:
        raise OSError(f"No available loopback port in range {port}-{last_port}.")
    raise OSError(f"Could not bind loopback ports {port}-{last_port}: {last_error}") from last_error


class PolicyEngine(Protocol):
    """Policy interface. The evaluator sees request content but must not persist it."""

    def evaluate_request(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...


class MetadataRecorder(Protocol):
    """Stores sanitized audit metadata only; never pass this object the payload."""

    def record_request(self, metadata: dict[str, Any]) -> None: ...


@dataclass
class GatewaySettings:
    """Runtime settings; the API key should come from the OS keyring."""

    bind_host: str = "127.0.0.1"
    port: int = 8765
    upstream_base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    client_label: str = ""
    api_key: str = field(default="", repr=False)
    request_timeout_seconds: float = 90.0
    max_body_bytes: int = 2 * 1024 * 1024
    review_timeout_seconds: int = 120

    @property
    def endpoint(self) -> str:
        return f"http://{self.bind_host}:{self.port}/v1"


@dataclass
class PendingReview:
    """One body held in memory pending an explicit reviewer decision."""

    request_id: str
    payload: dict[str, Any] = field(repr=False)
    trace: list[Any]
    findings: list[Any]
    created_at: float
    decision: Future[bool]
    provider: str = "configured provider"
    model: str = "unknown"
    client_label: str = ""
    resolution: str = "pending"
    size_bytes: int = 0


class Gateway:
    """Own the local HTTP server, provider forwarding, and live review queue."""

    def __init__(
        self,
        settings: GatewaySettings,
        policy_engine: PolicyEngine,
        recorder: MetadataRecorder | None = None,
        on_activity: Callable[[dict[str, Any]], None] | None = None,
        provider_factory: Callable[[GatewaySettings], ProviderAdapter] | None = None,
    ) -> None:
        self.settings = settings
        self.policy_engine = policy_engine
        self.recorder = recorder
        self.on_activity = on_activity
        self.provider_factory = provider_factory or OpenAICompatibleProvider
        self.provider_adapter = self.provider_factory(settings)
        self._lock = threading.RLock()
        self._pending: dict[str, PendingReview] = {}
        self._recent: deque[dict[str, Any]] = deque(maxlen=100)
        self._recent_bytes = 0
        self._pending_bytes = 0
        self._max_recent_bytes = 10 * 1024 * 1024
        self._max_retained_request_bytes = 1024 * 1024
        self._max_pending_bytes = 16 * 1024 * 1024
        self._thread: threading.Thread | None = None
        self._server: uvicorn.Server | None = None
        self._server_socket: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._started = threading.Event()
        self._last_error: str | None = None
        self._stopping = False
        self.app = self._build_app()

    def _build_app(self) -> FastAPI:
        app = FastAPI(title="AI Traffic Control Gateway", docs_url=None, redoc_url=None)

        @app.get("/health")
        async def health() -> dict[str, Any]:
            return {"status": "running", "endpoint": self.settings.endpoint}

        @app.get("/v1/models")
        async def models() -> Response:
            request_id = str(uuid.uuid4())
            started = time.monotonic()
            response = await self._proxy_models()
            elapsed = time.monotonic() - started
            self._record(request_id, "models", "models", [], [], "allow",
                         "forwarded" if response.status_code < 400 else "provider_error",
                         started, response.status_code, elapsed=elapsed,
                         trace=["Model list request forwarded to the configured provider."])
            return response

        @app.post("/v1/chat/completions")
        async def chat_completions(request: Request) -> Response:
            request_id = str(uuid.uuid4())
            started = time.monotonic()
            client_label = request.headers.get("x-client-label", "")[:100]
            body = await self._read_limited_body(request)
            if isinstance(body, Response):
                self._record(request_id, "unknown", "unknown", [], [], "deny", "invalid_request", started, None)
                return body
            body_size = len(body)
            try:
                payload = json.loads(body)
                if not isinstance(payload, dict):
                    raise ValueError("JSON root must be an object")
                if not isinstance(payload.get("messages"), list):
                    raise ValueError("messages must be a list")
                if payload.get("stream") is True:
                    client_model = str(payload.get("model", "unknown"))[:120]
                    self._record(request_id, client_model, client_model, [], [], "deny", "unsupported_streaming", started, None, client_label,
                                 trace=["Streaming is not supported by this local gateway; request was not forwarded."],
                                 reason="Streaming request rejected before provider forwarding.", payload=payload, payload_size=body_size)
                    return JSONResponse(
                        status_code=501,
                        content={"error": {"type": "unsupported_streaming", "message": "Streaming requests are not supported by this gateway yet. Set stream=false."}},
                    )
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError, RecursionError):
                self._record(request_id, "unknown", "unknown", [], [], "deny", "invalid_request", started, None,
                             client_label, trace=["Malformed request rejected before policy evaluation."], reason="Expected a JSON object with a messages array.")
                return JSONResponse(status_code=400, content={"error": {"type": "invalid_request_error", "message": "Expected a JSON object with a messages array."}})

            client_model = str(payload.get("model", "unknown"))[:120]
            client_label = client_label or self.settings.client_label
            context = {"request_id": request_id, "provider": self._provider_name(), "endpoint": self.settings.upstream_base_url,
                       "model": client_model, "client_label": client_label}
            try:
                result = self.policy_engine.evaluate_request(payload, context)
                if asyncio.iscoroutine(result):
                    result = await result
                if not isinstance(result, dict) or result.get("decision") not in {"allow", "review", "deny"}:
                    raise RuntimeError("Policy evaluator returned an invalid decision")
            except Exception:
                self._record(request_id, client_model, client_model, [], [], "deny", "policy_error", started, None,
                             client_label, trace=["Policy evaluation failed; request denied closed."], reason="The local policy engine could not evaluate this request.", payload=payload, payload_size=body_size)
                return JSONResponse(status_code=503, content={"error": {"type": "policy_error", "message": "The local policy engine could not evaluate this request. The request was not forwarded."}})

            decision = result["decision"]
            trace = result.get("trace", [])
            findings = result.get("findings", [])
            if decision == "deny":
                self._record(request_id, self.settings.model or client_model, client_model, findings, result.get("rule_ids", []), decision, "denied_by_policy", started, None,
                             client_label, trace=trace, reason=result.get("reason", "Denied by local policy."), payload=payload, payload_size=body_size)
                return JSONResponse(status_code=403, content={"error": {"type": "policy_denied", "message": "This request was blocked by a local data protection policy.", "request_id": request_id}})

            if decision == "review":
                pending = self._add_pending(request_id, payload, trace, findings, size_bytes=body_size,
                                            provider=self._provider_name(), model=client_model,
                                            client_label=client_label)
                if pending is None:
                    self._record(request_id, client_model, client_model, findings, result.get("rule_ids", []), "deny", "review_unavailable", started, None,
                                 client_label, trace=trace, reason=result.get("reason", "Review unavailable; denied closed."), payload=payload, payload_size=body_size)
                    return JSONResponse(status_code=503, content={"error": {"type": "review_unavailable", "message": "Human review is unavailable; the request was not forwarded."}})
                self._emit({"event": "review_pending", "request_id": request_id, "provider": pending.provider, "model": pending.model,
                            "client_label": pending.client_label, "findings": findings, "trace": trace,
                            "created_at": pending.created_at, "deadline": pending.created_at + self.settings.review_timeout_seconds})
                try:
                    approved = await asyncio.wait_for(asyncio.wrap_future(pending.decision), self.settings.review_timeout_seconds)
                except asyncio.TimeoutError:
                    approved = False
                    pending.resolution = "review_timeout"
                finally:
                    with self._lock:
                        removed = self._pending.pop(request_id, None)
                        if removed:
                            self._pending_bytes = max(0, self._pending_bytes - removed.size_bytes)
                if not approved:
                    review_outcome = pending.resolution if pending.resolution in {"review_denied", "review_timeout", "gateway_stopped"} else "review_denied"
                    self._record(request_id, self.settings.model or client_model, client_model, findings, result.get("rule_ids", []), "review", review_outcome, started, None,
                                 client_label, trace=trace, reason=f"Request was not forwarded: {review_outcome}.", payload=payload, payload_size=body_size)
                    return JSONResponse(status_code=403, content={"error": {"type": "review_denied", "message": "The request was denied or the review deadline expired.", "request_id": request_id}})

            # The model sent by the client is retained when configured model is blank;
            # normally the desktop setting selects the upstream model explicitly.
            outbound = dict(payload)
            if self.settings.model:
                outbound["model"] = self.settings.model
            response = await self._forward_chat(outbound)
            elapsed = time.monotonic() - started
            self._record(request_id, outbound.get("model", client_model), client_model, findings, result.get("rule_ids", []), decision,
                         "forwarded" if response.status_code < 400 else "provider_error", started, response.status_code, client_label,
                         elapsed, trace, result.get("reason", ""), payload, body_size)
            return response

        return app

    async def _read_limited_body(self, request: Request) -> bytes | Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.settings.max_body_bytes:
                    return JSONResponse(status_code=413, content={"error": {"type": "request_too_large", "message": "Request body exceeds the configured local gateway limit."}})
            except ValueError:
                return JSONResponse(status_code=400, content={"error": {"type": "invalid_request_error", "message": "Invalid Content-Length header."}})
        chunks: list[bytes] = []
        size = 0
        try:
            async for chunk in request.stream():
                size += len(chunk)
                if size > self.settings.max_body_bytes:
                    return JSONResponse(status_code=413, content={"error": {"type": "request_too_large", "message": "Request body exceeds the configured local gateway limit."}})
                chunks.append(chunk)
            return b"".join(chunks)
        except Exception:
            return JSONResponse(status_code=400, content={"error": {"type": "invalid_request_error", "message": "The request body could not be read safely."}})

    async def _forward_chat(self, payload: dict[str, Any]) -> Response:
        return await self.provider_adapter.chat_completions(payload)

    async def _proxy_models(self) -> Response:
        return await self.provider_adapter.list_models()

    def _provider_name(self) -> str:
        return self.provider_adapter.provider_name

    def _add_pending(self, request_id: str, payload: dict[str, Any], trace: list[Any], findings: list[Any],
                     *, size_bytes: int, provider: str = "configured provider", model: str = "unknown", client_label: str = "") -> PendingReview | None:
        with self._lock:
            if self._stopping or len(self._pending) >= 100 or self._pending_bytes + size_bytes > self._max_pending_bytes:
                return None
            item = PendingReview(request_id, payload, trace, findings, time.time(), Future(), provider, model, client_label, "pending", size_bytes)
            self._pending[request_id] = item
            self._pending_bytes += size_bytes
            return item

    def pending_reviews(self) -> list[dict[str, Any]]:
        """Return review snapshots with sensitive values masked by default."""
        with self._lock:
            return [{"request_id": p.request_id, "trace": p.trace,
                     "findings": p.findings, "data_classes": sorted({f.get("data_class", "") for f in p.findings if isinstance(f, dict)}),
                     "provider": p.provider, "model": p.model, "client_label": p.client_label, "created_at": p.created_at,
                     "deadline": p.created_at + self.settings.review_timeout_seconds}
                    for p in self._pending.values()]

    def get_review_payload(self, request_id: str, reveal: bool = False) -> dict[str, Any] | None:
        """Get one pending body; raw sensitive values require an explicit reveal."""
        with self._lock:
            item = self._pending.get(request_id)
            if item is None:
                return None
            if reveal:
                return copy.deepcopy(item.payload)
            return self._masked_payload(item.payload, item.findings)

    def recent_requests(self) -> list[dict[str, Any]]:
        """Return recent audit-safe metadata without request bodies."""
        with self._lock:
            return [copy.deepcopy(item["metadata"]) for item in self._recent]

    def get_request_payload(self, request_id: str, reveal: bool = False) -> dict[str, Any] | None:
        """Return one recent request body, masked unless reveal is explicit."""
        with self._lock:
            item = next((row for row in self._recent if row["metadata"].get("request_id") == request_id), None)
            if item is None:
                return None
            if reveal:
                return copy.deepcopy(item["payload"])
            return self._masked_payload(item["payload"], item["findings"])

    @staticmethod
    def _masked_payload(payload: dict[str, Any], findings: list[Any]) -> dict[str, Any]:
        """Mask detector spans in a copy, leaving the held request untouched."""
        try:
            cloned = copy.deepcopy(payload)
            grouped: dict[str, list[dict[str, Any]]] = {}
            for finding in findings or []:
                if isinstance(finding, dict):
                    location = str(finding.get("location", ""))
                    if not location.startswith("$."):
                        raise ValueError("Finding location is unavailable")
                    grouped.setdefault(location, []).append(finding)
            for path, matches in grouped.items():
                if not path.startswith("$."):
                    continue
                value = Gateway._path_value(cloned, path)
                if not isinstance(value, str):
                    raise ValueError("Finding location does not identify text")
                for match in sorted(matches, key=lambda item: int(item.get("start", -1)), reverse=True):
                    try:
                        start, end = int(match["start"]), int(match["end"])
                        masked = str(match["masked_value"])
                        if not (0 <= start < end <= len(value)):
                            raise ValueError("Finding span is invalid")
                        value = value[:start] + masked + value[end:]
                    except (KeyError, TypeError, ValueError):
                        raise ValueError("Finding could not be masked")
                Gateway._set_path_value(cloned, path, value)
            return cloned
        except Exception:
            # A masking failure must never fall back to exposing the original body.
            return {"error": "Unable to render safely masked request content."}

    @staticmethod
    def _path_value(root: Any, path: str) -> Any:
        try:
            parts = re.findall(r"\.([^.[\]]+)|\[(\d+)\]", path[1:])
            value = root
            for key, index in parts:
                value = value[int(index)] if index else value[key]
            return value
        except (IndexError, KeyError, TypeError, ValueError):
            return None

    @staticmethod
    def _set_path_value(root: Any, path: str, replacement: Any) -> None:
        try:
            parts = re.findall(r"\.([^.[\]]+)|\[(\d+)\]", path[1:])
            parent = root
            for key, index in parts[:-1]:
                parent = parent[int(index)] if index else parent[key]
            key, index = parts[-1]
            parent[int(index) if index else key] = replacement
        except (IndexError, KeyError, TypeError, ValueError):
            return

    def resolve_review(self, request_id: str, approve: bool) -> bool:
        """Resolve a pending request; only approval can release it upstream."""
        with self._lock:
            item = self._pending.get(request_id)
            if item is None or item.decision.done() or self._stopping:
                return False
            item.resolution = "approved" if approve else "review_denied"
            item.decision.set_result(bool(approve))
        self._emit({"event": "review_resolved", "request_id": request_id, "approved": bool(approve)})
        return True

    def _record(self, request_id: str, model: str, client_model: str, findings: list[Any], rule_ids: list[Any], decision: str, outcome: str, started: float, upstream_status: int | None, client_label: str = "", elapsed: float | None = None, trace: list[Any] | None = None, reason: str = "", payload: dict[str, Any] | None = None, payload_size: int = 0) -> None:
        duration = elapsed if elapsed is not None else max(0.0, time.monotonic() - started)
        classes = []
        for finding in findings or []:
            if isinstance(finding, dict):
                value = finding.get("data_class") or finding.get("class") or finding.get("name")
                if value and value not in classes:
                    classes.append(str(value))
        metadata = {"timestamp": time.time(), "request_id": request_id, "provider": self._provider_name(), "model": model, "client_model": client_model, "client_label": client_label, "data_classes": classes, "findings": findings or [], "rule_ids": rule_ids or [], "decision": decision, "outcome": outcome, "elapsed_ms": duration * 1000, "elapsed_seconds": duration, "upstream_status": upstream_status, "trace": trace or [], "decision_trace": trace or [], "reason": reason}
        if self.recorder:
            try:
                self.recorder.record_request(metadata)
            except Exception:
                pass
        if payload is not None and not self._stopping:
            size_bytes = payload_size
            with self._lock:
                if not self._stopping and size_bytes <= self._max_retained_request_bytes:
                    while self._recent and (len(self._recent) >= 100 or self._recent_bytes + size_bytes > self._max_recent_bytes):
                        removed = self._recent.popleft()
                        self._recent_bytes = max(0, self._recent_bytes - int(removed.get("size_bytes", 0)))
                    self._recent.append({"metadata": copy.deepcopy(metadata), "payload": copy.deepcopy(payload),
                                         "findings": copy.deepcopy(findings or []), "size_bytes": size_bytes})
                    self._recent_bytes += size_bytes
        self._emit({"event": "request_completed", **metadata, "findings": findings or []})

    def _emit(self, event: dict[str, Any]) -> None:
        if self.on_activity:
            try:
                self.on_activity(event)
            except Exception:
                pass

    def start(self, timeout: float = 8.0) -> None:
        """Start uvicorn on the configured interface in a daemon thread."""
        if self.is_running:
            return
        if self.settings.bind_host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("The gateway may bind only to localhost unless an explicit network exposure flow is implemented.")
        requested_port = self.settings.port
        listener, actual_port = _open_listener(self.settings.bind_host, requested_port)
        self._server_socket = listener
        self.settings.port = actual_port
        self._port_notice = (f"Port {requested_port} was unavailable; using {actual_port}. Update clients to the displayed endpoint."
                            if actual_port != requested_port else "")
        self._stopping = False
        self._started.clear()
        # A windowed PyInstaller app has no console streams; Uvicorn's default
        # dictConfig formatter fails when sys.stderr is None.
        config = uvicorn.Config(self.app, host=self.settings.bind_host, port=self.settings.port,
                                log_level="error", access_log=False, log_config=None)
        self._server = uvicorn.Server(config)

        def run() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(self._server.serve(sockets=[listener]))
            except Exception as exc:
                # Keep a useful local diagnostic while ensuring credentials are never echoed.
                detail = str(exc).strip()
                if self.settings.api_key:
                    detail = detail.replace(self.settings.api_key, "[redacted]")
                detail = detail[:180] or "No additional details."
                self._last_error = f"Gateway server failed ({type(exc).__name__}: {detail})."
            finally:
                try:
                    listener.close()
                except OSError:
                    pass
                self._server_socket = None
                self._loop.close()
                self._loop = None

        self._thread = threading.Thread(target=run, name="ai-traffic-control-gateway", daemon=True)
        self._thread.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._server.started:
                return
            if not self._thread.is_alive():
                break
            time.sleep(0.05)
        self._last_error = self._last_error or f"Gateway did not start on {self.settings.bind_host}:{self.settings.port} within {timeout:g} seconds."
        self.stop()
        raise RuntimeError(self._last_error)

    def stop(self, timeout: float = 8.0) -> None:
        """Stop accepting requests and fail all pending reviews closed."""
        self._stopping = True
        with self._lock:
            for pending in self._pending.values():
                if not pending.decision.done():
                    pending.resolution = "gateway_stopped"
                    pending.decision.set_result(False)
            self._pending.clear()
            self._pending_bytes = 0
            self._recent.clear()
            self._recent_bytes = 0
        if self._server:
            self._server.should_exit = True
        if self._server_socket and not self._thread:
            self._server_socket.close()
        if self._thread:
            self._thread.join(timeout)
        self._server = None
        self._thread = None

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self._server and not self._server.should_exit)

    @property
    def status(self) -> dict[str, Any]:
        return {"running": self.is_running, "endpoint": self.settings.endpoint, "pending_reviews": len(self.pending_reviews()), "error": self._last_error, "notice": getattr(self, "_port_notice", "")}

    def update_settings(self, settings: GatewaySettings) -> None:
        """Apply updated settings, restarting the listener if address/port changed."""
        old_address = (self.settings.bind_host, self.settings.port)
        new_address = (settings.bind_host, settings.port)
        was_running = self.is_running
        if was_running and old_address != new_address:
            self.stop()
        self.settings = settings
        self.provider_adapter = self.provider_factory(settings)
        if was_running and old_address != new_address:
            self.start()

