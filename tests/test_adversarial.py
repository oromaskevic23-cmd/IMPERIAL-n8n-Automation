"""Adversarial local gateway regression tests (no external infrastructure)."""
import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from imperial_n8n.gateway import Gateway, approve_request, sign_transport

K = b"K" * 32
A = b"A" * 32
NOW = 10000


def request(task_id="TASK-1000", orchestrator="ASTRA", actor="NCA-424"):
    msg = {"origin": "HANTER", "task_id": task_id, "orchestrator": orchestrator,
           "agent_id": actor, "action": "simulate:task"}
    msg["approval"] = {"expires_at": NOW + 100,
                       "signature": approve_request(A, msg, NOW + 100)}
    return msg


def envelope(msg, nonce="nonce-unique-12345678", ts=str(NOW)):
    raw = json.dumps(msg, sort_keys=True).encode()
    return raw, {"X-IC-Timestamp": ts, "X-IC-Nonce": nonce,
                 "X-IC-Signature": sign_transport(K, ts, nonce, raw)}


class AdversarialTests(unittest.TestCase):
    def setUp(self):
        self.prev = os.environ.get("IMPERIAL_OWNER_KILL_SWITCH")
        os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = "0"
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dbpath = Path(self.temp.name) / "intake.db"
        self.gateway = Gateway(self.dbpath, K, A, {"ASTRA"})

    def tearDown(self):
        if self.prev is None:
            os.environ.pop("IMPERIAL_OWNER_KILL_SWITCH", None)
        else:
            os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = self.prev

    def accept(self, msg=None, nonce="nonce-unique-12345678"):
        return self.gateway.accept(*envelope(msg or request(), nonce), now=NOW)

    def test_simultaneous_duplicate_replays_only_one_accepted(self):
        raw, headers = envelope(request())
        def send(_):
            return self.gateway.accept(raw, headers, now=NOW)[0]
        with ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(send, range(12)))
        self.assertEqual(codes.count(202), 1)
        self.assertEqual(codes.count(409), 11)
        self.assertTrue(self.gateway.verify_audit())

    def test_distinct_concurrent_intents(self):
        def send(index):
            return self.accept(request(task_id=f"TASK-{index+1000}"),
                               nonce=f"nonce-for-task-{index+1000000}")[0]
        with ThreadPoolExecutor(max_workers=6) as pool:
            codes = list(pool.map(send, range(9)))
        self.assertEqual(codes, [202] * 9)
        self.assertTrue(self.gateway.verify_audit())
        with sqlite3.connect(self.dbpath) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM tasks").fetchone()[0], 9)

    def test_origin_spoof_without_reissuing_signature_denied(self):
        p = request()
        p["origin"] = "FORGED"
        self.assertEqual(self.accept(p)[0], 403)

    def test_rejection_does_not_consume_nonce(self):
        p = request(orchestrator="UNKNOWN")
        self.assertEqual(self.accept(p)[0], 403)
        self.assertEqual(self.accept(request())[0], 202)

    def test_cross_orchestrator_approval_rejected(self):
        p = request()
        p["orchestrator"] = "ANOTHER"
        self.assertEqual(self.accept(p)[0], 403)

    def test_cross_agent_approval_rejected(self):
        p = request()
        p["agent_id"] = "NCA-777"
        self.assertEqual(self.accept(p)[0], 403)

    def test_unapproved_scope_cannot_reach_storage(self):
        p = request()
        p["action"] = "route:internal"
        self.assertEqual(self.accept(p)[0], 403)

    def test_boolean_expiry_not_valid(self):
        p = request()
        p["approval"]["expires_at"] = True
        self.assertEqual(self.accept(p)[0], 403)

    def test_far_future_approval_not_valid(self):
        p = request()
        p["approval"]["expires_at"] = NOW + 100000
        p["approval"]["signature"] = approve_request(A, p, NOW + 100000)
        self.assertEqual(self.accept(p)[0], 403)

    def test_none_origin_rejected(self):
        p = request()
        p["origin"] = None
        self.assertEqual(self.accept(p)[0], 403)

    def test_malformed_json_with_correct_signature(self):
        raw = b'{"not_valid":'
        ts, nonce = str(NOW), "nonce12345678901234"
        h = {"X-IC-Timestamp": ts, "X-IC-Nonce": nonce,
             "X-IC-Signature": sign_transport(K, ts, nonce, raw)}
        self.assertEqual(self.gateway.accept(raw, h, now=NOW)[0], 400)

    def test_body_length_boundary(self):
        self.assertEqual(self.gateway.accept(b"x" * 65537, {}, now=NOW)[0], 413)

    def test_nonce_persists_across_restart(self):
        self.assertEqual(self.accept()[0], 202)
        restarted = Gateway(self.dbpath, K, A, {"ASTRA"})
        raw, h = envelope(request())
        self.assertEqual(restarted.accept(raw, h, now=NOW)[0], 409)

    def test_empty_allowlist_denies(self):
        # Fail at configuration time, before the gateway can accept requests.
        with self.assertRaisesRegex(ValueError, "invalid federated allowlist"):
            Gateway(self.dbpath, K, A, set())


if __name__ == "__main__":
    unittest.main()
