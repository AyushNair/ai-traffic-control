"""Local DLP, policy, review and metadata persistence for AI Traffic Control.

Sensitive request bodies are deliberately kept out of :class:`AuditStore`.
They exist only in the gateway request stack and, for review decisions, in
the bounded in-memory :class:`ReviewQueue` until resolved.
"""
from __future__ import annotations

import csv
import asyncio
from contextlib import contextmanager
import io
import json
import os
import re
import sqlite3
import threading
import time
import uuid
import regex as safe_regex
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .()-]?)?(?:\(?\d{3,4}\)?[ .-]?)\d{3,4}[ .-]?\d{3,4}(?!\w)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Bearer token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("Generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9_./+=-]{12,}")),
)
_PRIVATE_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _validate_regex(pattern: str, rule_name: str = "pattern") -> None:
    if not pattern or len(pattern) > 256:
        raise ValueError(f"{rule_name}: regular expression must contain 1 to 256 characters")
    if re.search(r"\([^)]*[+*][^)]*\)[+*{]", pattern):
        raise ValueError(f"{rule_name}: nested repetition is not allowed")
    try:
        safe_regex.compile(pattern)
    except safe_regex.error as exc:
        raise ValueError(f"{rule_name}: invalid regular expression: {exc}") from exc


def _mask(value: str) -> str:
    if len(value) < 5:
        return "•" * len(value)
    return value[:2] + "•" * min(max(4, len(value) - 4), 24) + value[-2:]


@dataclass(frozen=True)
class Finding:
    data_class: str
    name: str
    description: str
    severity: str
    confidence: float
    location: str
    start: int
    end: int
    masked_value: str
    # Excluded from repr and serialized views. Used only to render an
    # explicitly revealed, ephemeral request view.
    raw_value: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("raw_value", None)
        return d


@dataclass
class PolicyRule:
    id: str
    name: str
    description: str
    priority: int
    action: str
    enabled: bool = True
    data_classes: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    client_labels: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    # Optional custom detector applies to all content strings. Exactly one of
    # pattern/keyword can be provided. Regex validation occurs on construction.
    pattern: str = ""
    keyword: str = ""


@dataclass
class PolicyDecision:
    action: str
    findings: list[Finding]
    matched_rules: list[str]
    trace: list[str]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "findings": [f.to_dict() for f in self.findings],
            "matched_rules": list(self.matched_rules),
            "trace": list(self.trace),
            "reason": self.reason,
        }


class Detector:
    """Find known sensitive formats plus user-authored keyword/regex rules."""

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        self.custom: list[tuple[PolicyRule, re.Pattern[str] | None]] = []
        for rule in rules:
            if rule.pattern:
                _validate_regex(rule.pattern, rule.name)
                self.custom.append((rule, safe_regex.compile(rule.pattern, safe_regex.IGNORECASE)))
            elif rule.keyword:
                self.custom.append((rule, safe_regex.compile(safe_regex.escape(rule.keyword), safe_regex.IGNORECASE)))

    def scan(self, payload: Any) -> list[Finding]:
        found: list[Finding] = []
        examples: dict[str, int] = {}
        max_examples_per_detector = 5
        for location, text in _walk_strings(payload):
            specs: list[tuple[str, str, str, str, float, re.Pattern[str]]] = [
                ("email", "Email address", "Email address may identify a person.", "medium", .98, _EMAIL),
                ("phone", "Phone number", "Phone number may identify or contact a person.", "medium", .82, _PHONE),
                ("payment_card", "Payment card", "Card-like number passed a Luhn checksum.", "high", .99, _CARD),
                ("private_key", "Private key header", "A private-key PEM header was found.", "critical", 1.0, _PRIVATE_HEADER),
            ]
            specs.extend(("secret", title, "Credential or token format may grant account access.", "critical", .94, pat) for title, pat in _SECRET_PATTERNS)
            for klass, name, desc, sev, confidence, pattern in specs:
                detector_key = f"{klass}:{name}"
                if examples.get(detector_key, 0) >= max_examples_per_detector:
                    continue
                for m in pattern.finditer(text):
                    raw = m.group(0)
                    if klass == "payment_card" and not _luhn(raw):
                        continue
                    found.append(Finding(klass, name, desc, sev, confidence, location, m.start(), m.end(), _mask(raw), raw))
                    examples[detector_key] = examples.get(detector_key, 0) + 1
                    if examples[detector_key] >= max_examples_per_detector:
                        break
            for rule, pat in self.custom:
                detector_key = f"custom:{rule.id}"
                if pat is None or examples.get(detector_key, 0) >= max_examples_per_detector:
                    continue
                klass = rule.data_classes[0] if rule.data_classes else "custom"
                for m in pat.finditer(text, timeout=0.05):
                    raw = m.group(0)
                    found.append(Finding(klass, rule.name, rule.description or "Matched a user-defined pattern.", "medium", .9, location, m.start(), m.end(), _mask(raw), raw))
                    examples[detector_key] = examples.get(detector_key, 0) + 1
                    if examples[detector_key] >= max_examples_per_detector:
                        break
        # Suppress exact overlaps, keeping the higher confidence finding.
        found.sort(key=lambda f: (f.location, f.start, -(f.end - f.start), -f.confidence))
        out: list[Finding] = []
        for item in found:
            if any(prev.location == item.location and item.start < prev.end and prev.start < item.end for prev in out):
                continue
            out.append(item)
        return out


def _walk_strings(obj: Any, path: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, Mapping):
        for key, value in obj.items():
            yield from _walk_strings(value, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for i, value in enumerate(obj):
            yield from _walk_strings(value, f"{path}[{i}]")


def _luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    check = digits.pop()
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (total + check) % 10 == 0


def _contains(values: Sequence[str], target: str) -> bool:
    return not values or any(v.casefold() == target.casefold() or v == "*" for v in values)


class PolicyEngine:
    """Highest priority matching rules decide; ties choose stricter actions.

    Built-in secret denial has priority 1000; custom rules can supersede it only
    if explicitly assigned a higher priority. No findings means allow.
    """

    def __init__(self, rules: Iterable[PolicyRule] | None = None, store: AuditStore | None = None) -> None:
        self._lock = threading.RLock()
        self.store = store
        saved = store.load_policy_rules() if rules is None and store is not None else None
        self.rules = list(rules) if rules is not None else (saved if saved is not None else default_rules())
        self._validate_all()
        if store is not None and saved is None and rules is None:
            store.save_policy_rules(self.rules)

    def _validate_all(self) -> None:
        if len(self.rules) > 500:
            raise ValueError("A maximum of 500 enabled or disabled policy rules is supported.")
        ids: set[str] = set()
        for r in self.rules:
            if r.id in ids:
                raise ValueError(f"Duplicate rule ID: {r.id}")
            ids.add(r.id)
            if r.action not in {"allow", "review", "deny"}:
                raise ValueError(f"Rule {r.name}: action must be allow, review, or deny")
            if r.pattern:
                _validate_regex(r.pattern, f"Rule {r.name}")
            if r.keyword and r.pattern:
                raise ValueError(f"Rule {r.name}: choose either a keyword or regex")

    def set_rules(self, rules: Iterable[PolicyRule]) -> None:
        candidate = list(rules)
        with self._lock:
            old = self.rules
            self.rules = candidate
            try:
                self._validate_all()
            except Exception:
                self.rules = old
                raise
            if self.store is not None:
                self.store.save_policy_rules(self.rules)

    def list_rules(self) -> list[PolicyRule]:
        with self._lock:
            return [replace(r, data_classes=list(r.data_classes), providers=list(r.providers),
                            models=list(r.models), client_labels=list(r.client_labels),
                            exclusions=list(r.exclusions)) for r in self.rules]

    def add_rule(self, rule: PolicyRule | Mapping[str, Any]) -> PolicyRule:
        candidate = rule if isinstance(rule, PolicyRule) else PolicyRule(**dict(rule))
        self.set_rules([*self.list_rules(), candidate])
        return candidate

    def update_rule(self, rule_id: str, **changes: Any) -> PolicyRule:
        with self._lock:
            current = next((r for r in self.rules if r.id == rule_id), None)
            if current is None:
                raise KeyError(f"Policy rule not found: {rule_id}")
            updated = replace(current, **changes)
            rules = [updated if r.id == rule_id else r for r in self.rules]
        self.set_rules(rules)
        return updated

    def delete_rule(self, rule_id: str) -> None:
        rules = [r for r in self.list_rules() if r.id != rule_id]
        if len(rules) == len(self.rules):
            raise KeyError(f"Policy rule not found: {rule_id}")
        self.set_rules(rules)

    def evaluate(self, payload: Any, *, provider: str, model: str, client_label: str = "", endpoint: str = "") -> PolicyDecision:
        try:
            with self._lock:
                rules = [r for r in self.rules if r.enabled]
            detector = Detector(r for r in rules if r.pattern or r.keyword)
            findings = detector.scan(payload)
            trace = [f"Inspected request content locally; found {len(findings)} finding(s)."]
            if not findings:
                trace.append("No configured detector matched; default action is allow.")
                return PolicyDecision("allow", [], [], trace, "No findings matched a policy.")
            ordered = sorted(rules, key=lambda r: (-r.priority, r.id))
            matched: list[tuple[PolicyRule, Finding]] = []
            for rule in ordered:
                if rule.pattern or rule.keyword:
                    # The custom detector finding names the rule.
                    relevant = [f for f in findings if f.name == rule.name]
                else:
                    relevant = [f for f in findings if (not rule.data_classes or f.data_class in rule.data_classes)]
                destination_match = (not rule.providers or any(
                    value == "*" or value.casefold() in {provider.casefold(), endpoint.casefold()}
                    for value in rule.providers))
                if not destination_match or not _contains(rule.models, model) or not _contains(rule.client_labels, client_label):
                    continue
                if rule.exclusions:
                    content = " ".join(v for _, v in _walk_strings(payload)).casefold()
                    if any(x.casefold() in content for x in rule.exclusions):
                        trace.append(f"Rule '{rule.name}' skipped because an exclusion matched.")
                        continue
                if relevant:
                    matched.extend((rule, f) for f in relevant)
                    trace.append(f"Rule '{rule.name}' (priority {rule.priority}) matched {', '.join(sorted({f.data_class for f in relevant}))}; action={rule.action}.")
            if not matched:
                trace.append("Findings had no matching enabled rule; safe default is review.")
                return PolicyDecision("review", findings, [], trace, "Findings need review because no rule allowed them.")
            top_priority = max(rule.priority for rule, _ in matched)
            top = [(rule, f) for rule, f in matched if rule.priority == top_priority]
            rank = {"allow": 0, "review": 1, "deny": 2}
            action = max((rule.action for rule, _ in top), key=lambda a: rank[a])
            rule_ids = list(dict.fromkeys(rule.id for rule, _ in top if rule.action == action))
            trace.append(f"Precedence: highest priority wins; ties resolve deny > review > allow. Selected {action}.")
            names = ", ".join(rule.name for rule, _ in top if rule.action == action)
            return PolicyDecision(action, findings, rule_ids, trace, f"{action.title()} by {names}.")
        except Exception as exc:
            return PolicyDecision("deny", [], [], ["Policy evaluation failed; request denied closed."], f"Policy evaluation failed: {type(exc).__name__}")

    def evaluate_request(self, payload: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Gateway-friendly adapter. ``context`` accepts provider/model/client_label."""
        context = context or {}
        result = self.evaluate(payload, provider=str(context.get("provider", "openai-compatible")),
                               model=str(context.get("model", payload.get("model", "unknown"))),
                               client_label=str(context.get("client_label", "")),
                               endpoint=str(context.get("endpoint", "")))
        return {"decision": result.action, "findings": [f.to_dict() for f in result.findings],
                "trace": list(result.trace), "matched_rules": list(result.matched_rules),
                "rule_ids": list(result.matched_rules), "reason": result.reason, "policy_decision": result}


def default_rules() -> list[PolicyRule]:
    return [
        PolicyRule("builtin-secret-deny", "Block exposed credentials", "Credentials and private keys must not leave this device.", 1000, "deny", data_classes=["secret", "private_key"]),
        PolicyRule("builtin-card-review", "Review payment cards", "Payment card numbers require explicit approval.", 900, "review", data_classes=["payment_card"]),
        PolicyRule("builtin-pii-review", "Review personal details", "Emails and phone numbers require review before forwarding.", 800, "review", data_classes=["email", "phone"]),
        PolicyRule("builtin-custom-review", "Review custom matches", "User-defined detector matches require review by default.", 700, "review", data_classes=["custom"]),
    ]


@dataclass
class PendingReview:
    request_id: str
    created_at: float
    deadline: float
    body: Any = field(repr=False)
    decision: PolicyDecision
    resolved: threading.Event = field(default_factory=threading.Event, repr=False)
    approved: bool | None = None
    outcome: str = "pending"

    def masked_body(self) -> Any:
        # Mask by path and offset. Copy first so the in-memory body stays intact
        # for forwarding only after explicit approval.
        cloned = json.loads(json.dumps(self.body))
        paths: dict[str, list[Finding]] = {}
        for f in self.decision.findings:
            paths.setdefault(f.location, []).append(f)
        for path, findings in paths.items():
            value = _get_path(cloned, path)
            if not isinstance(value, str):
                continue
            for f in sorted(findings, key=lambda x: x.start, reverse=True):
                if f.start >= 0 and f.end <= len(value):
                    value = value[:f.start] + f.masked_value + value[f.end:]
            _set_path(cloned, path, value)
        return cloned

    def reveal_body(self) -> Any:
        """Return the original body for a deliberate, temporary reveal action."""
        return json.loads(json.dumps(self.body))


def _get_path(root: Any, path: str) -> Any:
    try:
        parts = re.findall(r"\.([^.[\]]+)|\[(\d+)\]", path[1:])
        cur = root
        for a, b in parts:
            cur = cur[int(b)] if b else cur[a]
        return cur
    except Exception:
        return None


def _set_path(root: Any, path: str, value: Any) -> None:
    try:
        parts = re.findall(r"\.([^.[\]]+)|\[(\d+)\]", path[1:])
        cur = root
        for a, b in parts[:-1]:
            cur = cur[int(b)] if b else cur[a]
        a, b = parts[-1]
        if b:
            cur[int(b)] = value
        else:
            cur[a] = value
    except Exception:
        return


class ReviewQueue:
    """Bounded, process-memory-only request queue. Waits fail closed."""

    def __init__(self, max_pending: int = 100) -> None:
        self.max_pending = max_pending
        self._lock = threading.RLock()
        self._items: dict[str, PendingReview] = {}
        self._stopping = False

    def enqueue(self, request_id: str, body: Any, decision: PolicyDecision, timeout_seconds: float = 120) -> PendingReview:
        with self._lock:
            if self._stopping:
                raise RuntimeError("Review queue is stopping; request denied")
            if len(self._items) >= self.max_pending:
                raise RuntimeError("Review queue is full; request denied")
            item = PendingReview(request_id, time.monotonic(), time.monotonic() + max(1, timeout_seconds), body, decision)
            self._items[request_id] = item
            return item

    async def add(self, request_id: str, payload: Any, trace: Any = None, timeout_seconds: float = 120) -> bool:
        """Gateway interface: add request and asynchronously wait for reviewer."""
        decision = trace if isinstance(trace, PolicyDecision) else PolicyDecision(
            "review", [], [], list(trace or []), "Awaiting explicit human review.")
        self.enqueue(request_id, payload, decision, timeout_seconds)
        return await asyncio.to_thread(self.wait, request_id)

    def wait(self, request_id: str) -> bool:
        with self._lock:
            item = self._items.get(request_id)
            if not item:
                return False
        remain = max(0, item.deadline - time.monotonic())
        item.resolved.wait(remain)
        with self._lock:
            if item.approved is None:
                item.approved = False
                item.outcome = "review_timeout" if not self._stopping else "gateway_stopped"
                item.resolved.set()
            self._items.pop(request_id, None)
            return bool(item.approved)

    def resolve(self, request_id: str, approve: bool) -> bool:
        with self._lock:
            item = self._items.get(request_id)
            if not item or item.resolved.is_set() or time.monotonic() >= item.deadline or self._stopping:
                return False
            item.approved = bool(approve)
            item.outcome = "approved" if approve else "denied_by_reviewer"
            item.resolved.set()
            return True

    def list_pending(self) -> list[PendingReview]:
        with self._lock:
            now = time.monotonic()
            for rid, item in list(self._items.items()):
                if now >= item.deadline and not item.resolved.is_set():
                    item.approved = False
                    item.outcome = "review_timeout"
                    item.resolved.set()
            return [i for i in self._items.values() if not i.resolved.is_set()]

    def pending(self) -> list[dict[str, Any]]:
        """UI-safe pending rows. Prompt is masked; raw request remains in memory only."""
        return [{"request_id": item.request_id, "created_at": item.created_at,
                 "deadline": item.deadline, "payload": item.masked_body(),
                 "decision": item.decision.action, "findings": [f.to_dict() for f in item.decision.findings],
                 "trace": list(item.decision.trace), "reason": item.decision.reason}
                for item in self.list_pending()]

    def stop(self) -> None:
        with self._lock:
            self._stopping = True
            for item in self._items.values():
                if not item.resolved.is_set():
                    item.approved = False
                    item.outcome = "gateway_stopped"
                    item.resolved.set()


class AuditStore:
    """SQLite metadata store. Never accepts or saves request content."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        if path is None:
            base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AI Traffic Control"
            base.mkdir(parents=True, exist_ok=True)
            path = base / "audit.sqlite3"
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    @contextmanager
    def _connection(self):
        """Commit/rollback and close one short-lived SQLite connection."""
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def _init(self) -> None:
        with self._connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS requests(
                  request_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, provider TEXT NOT NULL,
                  model TEXT NOT NULL, client_label TEXT NOT NULL, data_classes TEXT NOT NULL,
                  rule_ids TEXT NOT NULL, decision TEXT NOT NULL, outcome TEXT NOT NULL,
                  elapsed_ms REAL, upstream_status INTEGER, reason TEXT NOT NULL DEFAULT '', trace TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS cases(
                  case_id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL,
                  notes TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_requests(
                  case_id TEXT NOT NULL, request_id TEXT NOT NULL,
                  PRIMARY KEY(case_id,request_id), FOREIGN KEY(case_id) REFERENCES cases(case_id)
                );
                CREATE TABLE IF NOT EXISTS policy_rules(
                  rule_id TEXT PRIMARY KEY, rule_json TEXT NOT NULL
                );
            """)

    def record(self, *, request_id: str, provider: str, model: str, decision: PolicyDecision,
               outcome: str, elapsed_ms: float | None = None, upstream_status: int | None = None,
               client_label: str = "", reason: str = "") -> None:
        # Only safe metadata; even masked content examples are excluded from DB.
        classes = sorted({f.data_class for f in decision.findings})
        with self._lock, self._connection() as db:
            db.execute("""INSERT OR REPLACE INTO requests
                (request_id,timestamp,provider,model,client_label,data_classes,rule_ids,decision,outcome,elapsed_ms,upstream_status,reason,trace)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (request_id, _utcnow(), provider, model, client_label, json.dumps(classes),
                 json.dumps(decision.matched_rules), decision.action, outcome, elapsed_ms,
                 upstream_status, reason[:500], json.dumps(decision.trace)))

    def record_request(self, metadata: Mapping[str, Any]) -> None:
        """Gateway adapter which whitelists safe metadata and drops content fields."""
        decision_obj = metadata.get("policy_decision")
        findings = metadata.get("findings", [])
        if isinstance(decision_obj, PolicyDecision):
            decision = decision_obj
        else:
            action = str(metadata.get("decision", "deny"))
            if isinstance(decision_obj, Mapping):
                action = str(decision_obj.get("decision", decision_obj.get("action", action)))
            classes: list[str] = []
            for finding in findings if isinstance(findings, list) else []:
                if isinstance(finding, Finding):
                    classes.append(finding.data_class)
                elif isinstance(finding, Mapping) and finding.get("data_class"):
                    classes.append(str(finding["data_class"]))
            trace = metadata.get("trace", [])
            if isinstance(decision_obj, Mapping):
                trace = decision_obj.get("trace", trace)
            rule_ids = metadata.get("rule_ids", metadata.get("matched_rules", []))
            if isinstance(decision_obj, Mapping):
                rule_ids = decision_obj.get("rule_ids", decision_obj.get("matched_rules", rule_ids))
            decision = PolicyDecision(action, [Finding(c, c, "", "", 0, "", 0, 0, "") for c in classes],
                                      [str(r) for r in (rule_ids or [])],
                                      [str(t)[:300] for t in (trace or [])], str(metadata.get("reason", ""))[:500])
        self.record(request_id=str(metadata.get("request_id") or new_request_id()),
                    provider=str(metadata.get("provider", "unknown"))[:200],
                    model=str(metadata.get("model", "unknown"))[:200], decision=decision,
                    outcome=str(metadata.get("outcome", "unknown"))[:100],
                    elapsed_ms=_float_or_none(metadata.get("elapsed_ms")),
                    upstream_status=_int_or_none(metadata.get("upstream_status")),
                    client_label=str(metadata.get("client_label", ""))[:200],
                    reason=str(metadata.get("reason", ""))[:500])

    def list_requests(self, limit: int = 500, *, outcome: str = "", provider: str = "", since: str = "") -> list[dict[str, Any]]:
        query = "SELECT * FROM requests WHERE 1=1"
        args: list[Any] = []
        for col, val in (("outcome", outcome), ("provider", provider)):
            if val:
                query += f" AND {col}=?"; args.append(val)
        if since:
            query += " AND timestamp>=?"; args.append(since)
        query += " ORDER BY timestamp DESC LIMIT ?"; args.append(max(1, min(5000, limit)))
        with self._connection() as db:
            rows = [dict(row) for row in db.execute(query, args)]
        for row in rows:
            for key in ("data_classes", "rule_ids", "trace"):
                row[key] = json.loads(row[key] or "[]")
        return rows

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        rows = self.list_requests(limit=1)
        if rows and rows[0].get("request_id") == request_id:
            return rows[0]
        with self._connection() as db:
            row = db.execute("SELECT * FROM requests WHERE request_id=?", (request_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        for key in ("data_classes", "rule_ids", "trace"):
            out[key] = json.loads(out[key] or "[]")
        return out

    def counts(self) -> dict[str, int]:
        with self._connection() as db:
            rows = db.execute("SELECT outcome,count(*) n FROM requests GROUP BY outcome").fetchall()
        result = {str(r["outcome"]): int(r["n"]) for r in rows}
        result["total"] = sum(result.values())
        return result

    def summary(self) -> dict[str, Any]:
        counts = self.counts()
        return {"total": counts["total"], "outcomes": {k: v for k, v in counts.items() if k != "total"},
                "recent": self.list_requests(limit=10)}

    def save_policy_rules(self, rules: Sequence[PolicyRule]) -> None:
        """Persist policy definitions locally; no prompts or credentials included."""
        rows = [(r.id, json.dumps(asdict(r), ensure_ascii=False)) for r in rules]
        with self._lock, self._connection() as db:
            db.execute("DELETE FROM policy_rules")
            db.executemany("INSERT INTO policy_rules(rule_id,rule_json) VALUES(?,?)", rows)

    def load_policy_rules(self) -> list[PolicyRule] | None:
        with self._connection() as db:
            rows = db.execute("SELECT rule_json FROM policy_rules ORDER BY rule_id").fetchall()
        if not rows:
            return None
        return [PolicyRule(**json.loads(row[0])) for row in rows]

    def create_case(self, title: str, notes: str = "", request_ids: Sequence[str] = (), status: str = "open") -> str:
        if status not in {"open", "investigating", "resolved", "closed"}:
            raise ValueError("Invalid case status")
        cid, now = str(uuid.uuid4()), _utcnow()
        with self._lock, self._connection() as db:
            db.execute("INSERT INTO cases VALUES(?,?,?,?,?,?)", (cid, title[:200], status, notes[:10000], now, now))
            for rid in request_ids:
                exists = db.execute("SELECT 1 FROM requests WHERE request_id=?", (rid,)).fetchone()
                if exists:
                    db.execute("INSERT OR IGNORE INTO case_requests VALUES(?,?)", (cid, rid))
        return cid

    def update_case(self, case_id: str, *, title: str | None = None, notes: str | None = None,
                    status: str | None = None, request_ids: Sequence[str] | None = None) -> None:
        if status is not None and status not in {"open", "investigating", "resolved", "closed"}:
            raise ValueError("Invalid case status")
        with self._lock, self._connection() as db:
            row = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if not row:
                raise KeyError("Case not found")
            db.execute("UPDATE cases SET title=?,notes=?,status=?,updated_at=? WHERE case_id=?",
                       (title[:200] if title is not None else row["title"], notes[:10000] if notes is not None else row["notes"],
                        status or row["status"], _utcnow(), case_id))
            if request_ids is not None:
                db.execute("DELETE FROM case_requests WHERE case_id=?", (case_id,))
                for rid in request_ids:
                    if db.execute("SELECT 1 FROM requests WHERE request_id=?", (rid,)).fetchone():
                        db.execute("INSERT OR IGNORE INTO case_requests VALUES(?,?)", (case_id, rid))

    def list_cases(self) -> list[dict[str, Any]]:
        with self._connection() as db:
            cases = [dict(r) for r in db.execute("SELECT * FROM cases ORDER BY updated_at DESC")]
            for case in cases:
                case["request_ids"] = [r[0] for r in db.execute("SELECT request_id FROM case_requests WHERE case_id=?", (case["case_id"],))]
        return cases

    def export_csv(self, *, outcome: str = "", since: str = "", until: str = "") -> str:
        query = "SELECT timestamp,request_id,provider,model,client_label,data_classes,rule_ids,decision,outcome,elapsed_ms,upstream_status,reason FROM requests WHERE 1=1"
        args: list[Any] = []
        if outcome:
            query += " AND outcome=?"; args.append(outcome)
        if since:
            query += " AND timestamp>=?"; args.append(since)
        if until:
            query += " AND timestamp<=?"; args.append(until)
        query += " ORDER BY timestamp"
        buf = io.StringIO(newline="")
        with self._connection() as db:
            writer = csv.writer(buf)
            writer.writerow([d[0] for d in db.execute(query, args).description])
            for row in db.execute(query, args):
                writer.writerow(list(row))
        return buf.getvalue()


def new_request_id() -> str:
    return str(uuid.uuid4())

