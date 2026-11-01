"""Adversarial JSON regression tests for the signed recording-only gateway."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from imperial_n8n.gateway import Gateway, approve_request, sign_transport

TRANSPORT = b"T" * 32
APPROVAL = b"A" * 32
NOW = 1000
NONCE = "strictjsonnonce123456789"


class StrictInputTests(unittest.TestCase):
    def setUp(self):
        self.previous_switch = os.environ.get("IMPERIAL_OWNER_KILL_SWITCH")
        os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = "0"
        self.addCleanup(self._restore)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.gateway = Gateway(
            Path(self.tmp.name) / "tasks.db", TRANSPORT, APPROVAL, {"ASTRA"}
        )

    def _restore(self):
        if self.previous_switch is None:
            os.environ.pop("IMPERIAL_OWNER_KILL_SWITCH", None)
        else:
            os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = self.previous_switch

    def _valid_payload(self):
        payload = {
            "origin": "HANTER", "task_id": "TASK-100",
            "orchestrator": "ASTRA", "agent_id": "NCA-424",
            "action": "simulate:task",
        }
        payload["approval"] = {
            "expires_at": NOW + 100,
            "signature": approve_request(APPROVAL, payload, NOW + 100),
        }
        return payload

    def _send_bytes(self, raw):
        headers = {
            "X-IC-Timestamp": str(NOW),
            "X-IC-Nonce": NONCE,
            "X-IC-Signature": sign_transport(
                TRANSPORT, str(NOW), NONCE, raw
            ),
        }
        return self.gateway.accept(raw, headers, now=NOW)

    def test_signed_duplicate_top_level_field_rejected(self):
        raw = json.dumps(self._valid_payload(), separators=(",", ":")).encode()
        raw = raw.replace(b'"origin":"HANTER"', b'"origin":"HANTER","origin":"HANTER"')
        self.assertEqual(self._send_bytes(raw)[0], 400)
        self.assertEqual(self._send_bytes(
            json.dumps(self._valid_payload()).encode()
        )[0], 202, "rejected malformed request must not consume nonce")

    def test_signed_duplicate_nested_approval_rejected(self):
        raw = json.dumps(self._valid_payload(), separators=(",", ":")).encode()
        raw = raw.replace(b'"expires_at":1100', b'"expires_at":1100,"expires_at":1100')
        self.assertIn(b'"expires_at":1100,"expires_at":1100', raw)
        self.assertEqual(self._send_bytes(raw)[0], 400)

    def test_signed_nonfinite_number_rejected(self):
        raw = json.dumps(self._valid_payload(), separators=(",", ":")).encode()
        raw = raw.replace(b'"origin":"HANTER"', b'"origin":NaN')
        self.assertEqual(self._send_bytes(raw)[0], 400)

    def test_signed_infinity_rejected(self):
        raw = json.dumps(self._valid_payload(), separators=(",", ":")).encode()
        raw = raw.replace(b'"origin":"HANTER"', b'"origin":Infinity')
        self.assertEqual(self._send_bytes(raw)[0], 400)

    def test_empty_orchestrator_allowlist_configuration_rejected(self):
        with self.assertRaises(ValueError):
            Gateway(Path(self.tmp.name) / "empty.db", TRANSPORT, APPROVAL, set())


if __name__ == "__main__":
    unittest.main()
