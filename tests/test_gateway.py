import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from imperial_n8n.gateway import Gateway, approve_request, sign_transport

TRANSPORT = b"T" * 32
APPROVAL = b"A" * 32
NOW = 1000


def make_request(action="simulate:task", task_id="TASK-100"):
    p = {"origin": "HANTER", "task_id": task_id, "orchestrator": "ASTRA",
         "agent_id": "NCA-424", "action": action}
    p["approval"] = {"expires_at": NOW + 100,
                     "signature": approve_request(APPROVAL, p, NOW + 100)}
    return p


def encode(p, *, nonce="abcdefghijklmnop1234", timestamp=str(NOW)):
    raw = json.dumps(p, sort_keys=True).encode()
    headers = {"X-IC-Timestamp": timestamp, "X-IC-Nonce": nonce,
               "X-IC-Signature": sign_transport(TRANSPORT, timestamp, nonce, raw)}
    return raw, headers


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.old_switch = os.environ.get("IMPERIAL_OWNER_KILL_SWITCH")
        os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = "0"
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "gateway.db"
        self.gate = Gateway(self.path, TRANSPORT, APPROVAL, {"ASTRA", "ORION-OPS"})

    def tearDown(self):
        if self.old_switch is None:
            os.environ.pop("IMPERIAL_OWNER_KILL_SWITCH", None)
        else:
            os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = self.old_switch

    def send(self, p=None, *, nonce="abcdefghijklmnop1234"):
        raw, headers = encode(p or make_request(), nonce=nonce)
        return self.gate.accept(raw, headers, now=NOW)

    def test_valid_request_is_recorded_only(self):
        status, result = self.send()
        self.assertEqual(status, 202)
        self.assertFalse(result["executed"])
        self.assertEqual(result["state"], "RECORDED_ONLY_NO_EXECUTOR")
        self.assertTrue(self.gate.verify_audit())

    def test_kill_switch_by_default(self):
        os.environ.pop("IMPERIAL_OWNER_KILL_SWITCH", None)
        self.assertEqual(self.send()[0], 423)

    def test_replay_nonce(self):
        self.assertEqual(self.send()[0], 202)
        self.assertEqual(self.send()[0], 409)

    def test_duplicate_task_new_nonce(self):
        self.assertEqual(self.send()[0], 202)
        self.assertEqual(self.send(nonce="anothernonce12345678")[0], 409)

    def test_bad_transport_signature(self):
        raw, h = encode(make_request())
        h["X-IC-Signature"] = "0" * 64
        self.assertEqual(self.gate.accept(raw, h, now=NOW)[0], 401)

    def test_modified_body_rejected(self):
        raw, h = encode(make_request())
        changed = raw.replace(b"ASTRA", b"ASXRA")
        self.assertEqual(self.gate.accept(changed, h, now=NOW)[0], 401)

    def test_old_timestamp_rejected(self):
        raw, h = encode(make_request(), timestamp="1")
        self.assertEqual(self.gate.accept(raw, h, now=NOW)[0], 401)

    def test_unknown_orchestrator_rejected(self):
        p = make_request()
        p["orchestrator"] = "GLOBAL"
        p["approval"]["signature"] = approve_request(APPROVAL, p, NOW + 100)
        self.assertEqual(self.send(p)[0], 403)

    def test_payments_denied(self):
        self.assertEqual(self.send(make_request("execute:payment"))[0], 403)

    def test_forged_approval_denied(self):
        p = make_request()
        p["approval"]["signature"] = "0" * 64
        self.assertEqual(self.send(p)[0], 403)

    def test_approval_for_different_task_denied(self):
        p = make_request()
        p["task_id"] = "TASK-999"
        self.assertEqual(self.send(p)[0], 403)

    def test_expired_approval_denied(self):
        p = make_request()
        p["approval"]["expires_at"] = NOW - 1
        p["approval"]["signature"] = approve_request(APPROVAL, p, NOW - 1)
        self.assertEqual(self.send(p)[0], 403)

    def test_missing_nonce(self):
        raw, h = encode(make_request())
        h.pop("X-IC-Nonce")
        self.assertEqual(self.gate.accept(raw, h, now=NOW)[0], 401)

    def test_invalid_schema_denied(self):
        p = make_request()
        p["unexpected"] = 1
        self.assertEqual(self.send(p)[0], 400)

    def test_ledger_tamper_detected(self):
        self.assertEqual(self.send()[0], 202)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE audit SET event_json='{}' WHERE seq=1")
        self.assertFalse(self.gate.verify_audit())

    def test_secrets_must_be_distinct(self):
        with self.assertRaises(ValueError):
            Gateway(self.path, TRANSPORT, TRANSPORT, {"ASTRA"})

    def test_denied_action_does_not_store_nonce(self):
        self.assertEqual(self.send(make_request("execute:payment"))[0], 403)
        self.assertEqual(self.send(make_request())[0], 202)


if __name__ == "__main__":
    unittest.main()
