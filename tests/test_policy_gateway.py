"""Offline regression tests for policy, audit privacy, and local gateway behavior."""
from __future__ import annotations

import json
import gc
import sqlite3
import socket
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path

from traffic_control.core import AuditStore, PolicyEngine, PolicyRule
from traffic_control.gateway import Gateway, GatewaySettings, _open_listener
from traffic_control.service import GatewayController


class PolicyTests(unittest.TestCase):
    def test_default_policy_allows_plain_text_and_reviews_email(self):
        engine = PolicyEngine()
        allowed = engine.evaluate({"messages": [{"content": "hello world"}]}, provider="fake", model="m")
        reviewed = engine.evaluate({"messages": [{"content": "reach me at person@example.org"}]}, provider="fake", model="m")
        self.assertEqual(allowed.action, "allow")
        self.assertEqual(reviewed.action, "review")
        self.assertTrue(reviewed.findings)
        self.assertNotIn("person@example.org", json.dumps(reviewed.to_dict()))

    def test_credentials_are_denied_and_masked(self):
        secret = "sk-" + "A" * 32
        decision = PolicyEngine().evaluate({"messages": [{"content": secret}]}, provider="fake", model="m")
        self.assertEqual(decision.action, "deny")
        self.assertNotIn(secret, json.dumps(decision.to_dict()))

    def test_invalid_custom_regex_is_rejected(self):
        with self.assertRaises(ValueError):
            PolicyEngine([PolicyRule("bad", "bad", "bad", 1, "deny", pattern="(")])

    def test_audit_store_drops_request_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.sqlite3"
            store = AuditStore(path)
            store.record_request({"request_id": "r1", "provider": "fake", "model": "m",
                                  "decision": "deny", "outcome": "denied_by_policy",
                                  "reason": "Denied by test policy", "payload": "sensitive-payload-marker",
                                  "authorization": "sensitive-payload-marker"})
            db = sqlite3.connect(path)
            try:
                persisted = " ".join(str(cell) for row in db.execute("SELECT * FROM requests") for cell in row)
            finally:
                db.close()
            self.assertNotIn("sensitive-payload-marker", persisted)
            del store
            gc.collect()


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.settings = GatewaySettings(model="test-model", api_key="never-used-by-fake")
        self.gateway = Gateway(self.settings, PolicyEngine())

    def test_gateway_exposes_only_implemented_routes(self):
        routes = {route.path for route in self.gateway.app.routes}
        self.assertTrue({"/health", "/v1/models", "/v1/chat/completions"}.issubset(routes))
        self.assertNotIn("/v1/responses", routes)

    def test_gateway_defaults_to_loopback(self):
        self.assertEqual(self.settings.bind_host, "127.0.0.1")
        self.assertEqual(self.settings.endpoint, "http://127.0.0.1:8765/v1")

    def test_conflicted_port_falls_forward_to_a_free_loopback_port(self):
        held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        held.bind(("127.0.0.1", 0))
        held.listen()
        busy_port = held.getsockname()[1]
        try:
            listener, selected = _open_listener("127.0.0.1", busy_port)
            try:
                self.assertNotEqual(selected, busy_port)
                self.assertEqual(listener.getsockname()[1], selected)
            finally:
                listener.close()
        finally:
            held.close()

    def test_controller_persists_the_selected_fallback_port(self):
        class PortSelectingGateway:
            settings = SimpleNamespace(port=8765)
            _last_error = None

            def start(self):
                self.settings.port = 8766

        settings = {"port": 8765}
        saved = []
        controller = GatewayController(PortSelectingGateway(), settings, settings_changed=lambda value: saved.append(dict(value)))
        self.assertTrue(controller.start())
        self.assertEqual(settings["port"], 8766)
        self.assertEqual(saved, [{"port": 8766}])


if __name__ == "__main__":
    unittest.main()
