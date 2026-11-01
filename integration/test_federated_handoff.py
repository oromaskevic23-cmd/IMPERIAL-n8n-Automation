"""Integration tests use the real checked-out IMPERIAL Skill and Plugins code.

Synthetic keys and an ephemeral SQLite DB only. No external calls or workers.
Run with PYTHONPATH=src:pinned-plugins/src:pinned-skill/src:integration.
"""
import copy
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from federated_handoff import record_approved_simulation
from imperial_n8n.gateway import Gateway, approve_request, sign_transport
from imperial_plugins.core import GuardianCore, sign_claims
from imperial_skill.manifest import validate_manifest as validate_skill

NOW = 1000
PASSPORT_SECRET = b"P" * 32
PLUGIN_APPROVAL_SECRET = b"Q" * 32
TRANSPORT_SECRET = b"T" * 32
GATEWAY_APPROVAL_SECRET = b"A" * 32
SKILL_PATH = Path(__file__).resolve().parents[1] / "pinned-skill/examples/skills/code-review.json"
PLUGIN = {
    "id": "imperial.guardian", "version": "0.2.0",
    "description": "Synthetic cross-repository policy compatibility check",
    "capabilities": ["read:public", "simulate:task"],
}


class FederatedHandoffTests(unittest.TestCase):
    def setUp(self):
        self.previous_switch = os.environ.get("IMPERIAL_OWNER_KILL_SWITCH")
        os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = "0"
        self.addCleanup(self._restore_switch)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "staging.db"
        self.gateway = Gateway(
            self.db, TRANSPORT_SECRET, GATEWAY_APPROVAL_SECRET, {"engineering-orch"}
        )
        self.guardian = GuardianCore(
            PASSPORT_SECRET, PLUGIN_APPROVAL_SECRET, kill_switch=False
        )
        self.skill = validate_skill(json.loads(SKILL_PATH.read_text("utf-8")))
        self.plugin = copy.deepcopy(PLUGIN)
        self.envelope = {
            "origin": "HANTER", "task_id": "TASK-100",
            "orchestrator": "engineering-orch", "agent_id": "NCA-424",
            "action": "simulate:task",
        }
        self.plugin_request = self._plugin_auth()

    def _restore_switch(self):
        if self.previous_switch is None:
            os.environ.pop("IMPERIAL_OWNER_KILL_SWITCH", None)
        else:
            os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = self.previous_switch

    def _plugin_auth(self):
        return {
            "agent_id": "NCA-424", "task_id": "TASK-100",
            "action": "simulate:task",
            "ai_passport": sign_claims({
                "agent_id": "NCA-424", "issuer": "IMPERIAL Core",
                "issued_at": NOW - 5, "expires_at": NOW + 200,
            }, PASSPORT_SECRET, "passport"),
            "approval": sign_claims({
                "issuer": "OWNER", "agent_id": "NCA-424",
                "task_id": "TASK-100", "action": "simulate:task",
                "expires_at": NOW + 100,
            }, PLUGIN_APPROVAL_SECRET, "approval"),
        }

    def _payload(self):
        payload = copy.deepcopy(self.envelope)
        payload["approval"] = {
            "expires_at": NOW + 100,
            "signature": approve_request(GATEWAY_APPROVAL_SECRET, payload, NOW + 100),
        }
        return payload

    def _encoded(self, payload=None, nonce="federatedtestingnonce1234"):
        raw = json.dumps(
            self._payload() if payload is None else payload,
            sort_keys=True, separators=(",", ":")
        ).encode()
        headers = {
            "X-IC-Timestamp": str(NOW), "X-IC-Nonce": nonce,
            "X-IC-Signature": sign_transport(
                TRANSPORT_SECRET, str(NOW), nonce, raw
            ),
        }
        return raw, headers

    def _send(self, raw=None, headers=None, **changes):
        if raw is None:
            raw, default_headers = self._encoded()
            if headers is None:
                headers = default_headers
        opts = dict(
            skill_descriptor=self.skill,
            plugin_descriptor=self.plugin,
            expected_tenant="imperial-internal",
            expected_orchestrator="engineering-orch",
            expected_domain="CODE_ENGINEERING",
            guardian=self.guardian,
            plugin_request=self.plugin_request,
            gateway=self.gateway,
            raw_body=raw,
            headers=headers,
            now=NOW,
        )
        opts.update(changes)
        return record_approved_simulation(**opts)

    def _rows(self):
        with sqlite3.connect(self.db) as db:
            return db.execute("SELECT count(*) FROM tasks").fetchone()[0]

    def test_all_three_real_packages_record_one_intent_only(self):
        code, body = self._send()
        self.assertEqual(code, 202)
        self.assertEqual(body, {"state": "RECORDED_ONLY_NO_EXECUTOR", "executed": False})
        self.assertEqual(self._rows(), 1)
        self.assertTrue(self.gateway.verify_audit())

    def test_repeated_intent_is_rejected_transactionally(self):
        self.assertEqual(self._send()[0], 202)
        self.assertEqual(self._send()[0], 409)
        self.assertEqual(self._rows(), 1)

    def test_cross_tenant_denied_without_storing(self):
        self.assertEqual(self._send(expected_tenant="different-tenant")[0], 403)
        self.assertEqual(self._rows(), 0)

    def test_wrong_orchestrator_denied_before_transport(self):
        self.assertEqual(self._send(expected_orchestrator="GLOBAL")[0], 403)
        self.assertEqual(self._rows(), 0)

    def test_wrong_agent_identity_denied(self):
        request = copy.deepcopy(self.plugin_request)
        request["agent_id"] = "NCA-999"
        self.assertEqual(self._send(plugin_request=request)[0], 403)
        self.assertEqual(self._rows(), 0)

    def test_missing_passport_denied(self):
        request = copy.deepcopy(self.plugin_request)
        request.pop("ai_passport")
        self.assertEqual(self._send(plugin_request=request)[0], 403)
        self.assertEqual(self._rows(), 0)

    def test_plugin_capability_not_authorized(self):
        plugin = copy.deepcopy(PLUGIN)
        plugin["capabilities"] = ["read:public"]
        self.assertEqual(self._send(plugin_descriptor=plugin)[0], 403)
        self.assertEqual(self._rows(), 0)

    def test_skill_capability_not_authorized(self):
        skill = copy.deepcopy(self.skill)
        skill["capabilities"] = ["read:public"]
        self.assertEqual(self._send(skill_descriptor=skill)[0], 403)
        self.assertEqual(self._rows(), 0)

    def test_payment_request_denied_even_with_matching_signatures(self):
        payload = self._payload()
        payload["action"] = "execute:payment"
        payload["approval"]["signature"] = approve_request(
            GATEWAY_APPROVAL_SECRET, payload, NOW + 100
        )
        raw, headers = self._encoded(payload)
        self.assertEqual(self._send(raw, headers)[0], 403)
        self.assertEqual(self._rows(), 0)

    def test_owner_kill_switch_fails_closed(self):
        os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = "1"
        self.assertEqual(self._send()[0], 403)
        self.assertEqual(self._rows(), 0)

    def test_gateway_independent_signature_still_required(self):
        raw, headers = self._encoded()
        headers["X-IC-Signature"] = "0" * 64
        self.assertEqual(self._send(raw, headers)[0], 401)
        self.assertEqual(self._rows(), 0)

    def test_duplicate_json_keys_rejected_before_accept(self):
        raw, headers = self._encoded()
        raw = raw.replace(b'"origin":"HANTER"', b'"origin":"HANTER","origin":"HANTER"')
        headers["X-IC-Signature"] = sign_transport(
            TRANSPORT_SECRET, str(NOW), headers["X-IC-Nonce"], raw
        )
        self.assertEqual(self._send(raw, headers)[0], 403)
        self.assertEqual(self._rows(), 0)


if __name__ == "__main__":
    unittest.main()
