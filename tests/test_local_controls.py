"""Local transactional stop and capacity tests; no remote authority claimed."""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from imperial_n8n.gateway import Gateway, approve_request, sign_transport

TRANSPORT = b"T" * 32
APPROVAL = b"A" * 32
NOW = 10000


class LocalControlTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"IMPERIAL_OWNER_KILL_SWITCH": "0"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "gateway.db"
        self.gate = Gateway(self.path, TRANSPORT, APPROVAL, {"ASTRA"})

    def envelope(self, suffix="1"):
        payload = {"origin": "HANTER", "task_id": "TASK-CONTROL-" + suffix,
                   "orchestrator": "ASTRA", "agent_id": "NCA-424", "action": "simulate:task"}
        payload["approval"] = {"expires_at": NOW + 100,
                               "signature": approve_request(APPROVAL, payload, NOW + 100)}
        raw = json.dumps(payload, sort_keys=True).encode()
        nonce = "nonce-for-control-" + suffix.zfill(8)
        stamp = str(NOW)
        return raw, {"X-IC-Timestamp": stamp, "X-IC-Nonce": nonce,
                     "X-IC-Signature": sign_transport(TRANSPORT, stamp, nonce, raw)}

    def counts(self):
        with sqlite3.connect(self.path) as db:
            return tuple(db.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
                         for name in ("nonces", "tasks", "audit"))

    def test_stop_persists_and_is_idempotent_across_restart(self):
        self.assertEqual(self.gate.accept(*self.envelope(), now=NOW)[0], 202)
        self.assertEqual(self.gate.engage_local_stop(),
                         (200, {"state": "LOCAL_STOP_LATCHED", "executed": False}))
        self.gate.engage_local_stop()
        restarted = Gateway(self.path, TRANSPORT, APPROVAL, {"ASTRA"})
        self.assertEqual(restarted.accept(*self.envelope("2"), now=NOW),
                         (423, {"state": "LOCAL_STOP_LATCHED", "executed": False}))
        self.assertEqual(self.counts(), (1, 1, 2))
        self.assertTrue(restarted.verify_audit())

    def test_environment_change_before_commit_rolls_back_all_writes(self):
        raw, headers = self.envelope()
        calls = []
        def mutate_after_last_approval_check(*args):
            signed = approve_request(*args)
            calls.append(1)
            if len(calls) == 2:
                os.environ["IMPERIAL_OWNER_KILL_SWITCH"] = "1"
            return signed
        with patch("imperial_n8n.gateway.approve_request", side_effect=mutate_after_last_approval_check):
            self.assertEqual(self.gate.accept(raw, headers, now=NOW)[0], 423)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_missing_persistent_control_fails_closed_even_after_restart(self):
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM local_control")
        restarted = Gateway(self.path, TRANSPORT, APPROVAL, {"ASTRA"})
        self.assertEqual(restarted.accept(*self.envelope(), now=NOW)[0], 503)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_stop_from_separate_local_process_fences_existing_gateway(self):
        code = ("import sys; from imperial_n8n.gateway import Gateway; "
                "g=Gateway(sys.argv[1],b'T'*32,b'A'*32,{'ASTRA'}); "
                "print(g.engage_local_stop()[1]['state'])")
        child = subprocess.run([sys.executable, "-c", code, str(self.path)],
                               capture_output=True, text=True, timeout=5)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stdout.strip(), "LOCAL_STOP_LATCHED")
        self.assertEqual(self.gate.accept(*self.envelope(), now=NOW)[0], 423)
        self.assertEqual(self.counts(), (0, 0, 1))
        self.assertTrue(self.gate.verify_audit())

    def test_stop_audit_failure_does_not_claim_success(self):
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TRIGGER fail_local_stop BEFORE INSERT ON audit
                WHEN NEW.event_json LIKE '%local_stop_engaged%'
                BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END""")
        with self.assertRaises(sqlite3.Error):
            self.gate.engage_local_stop()
        self.assertEqual(self.gate.accept(*self.envelope(), now=NOW)[0], 423)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT stop_latched FROM local_control").fetchone()[0], 0)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_capacity_rejects_without_consuming_nonce_or_audit(self):
        with patch("imperial_n8n.gateway.MAX_RECORDED_TASKS", 1):
            self.assertEqual(self.gate.accept(*self.envelope(), now=NOW)[0], 202)
            self.assertEqual(self.gate.accept(*self.envelope("2"), now=NOW),
                             (429, {"state": "LOCAL_RECORDING_CAP_REACHED", "executed": False}))
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assertTrue(self.gate.verify_audit())

    def test_stop_and_admission_have_a_single_transaction_order(self):
        stopper = Gateway(self.path, TRANSPORT, APPROVAL, {"ASTRA"})
        in_recording, allow_recording, stop_attempted = (threading.Event() for _ in range(3))
        original_append = self.gate._append_audit
        original_db = stopper._db
        results, errors = [], []

        def hold_recording(db, event):
            if event["event"] == "intake_recorded":
                in_recording.set()
                if not allow_recording.wait(3):
                    raise RuntimeError("test synchronization timeout")
            return original_append(db, event)

        def watched_stop_db():
            db = original_db()
            db.set_trace_callback(lambda sql: stop_attempted.set() if sql == "BEGIN IMMEDIATE" else None)
            return db

        def run(label, call):
            try:
                results.append((label, call()))
            except Exception as exc:
                errors.append(repr(exc))

        with patch.object(self.gate, "_append_audit", side_effect=hold_recording), \
             patch.object(stopper, "_db", side_effect=watched_stop_db):
            admission = threading.Thread(target=run, args=("admission", lambda: self.gate.accept(*self.envelope(), now=NOW)))
            admission.start()
            try:
                self.assertTrue(in_recording.wait(3))
                stop = threading.Thread(target=run, args=("stop", stopper.engage_local_stop))
                stop.start()
                try:
                    self.assertTrue(stop_attempted.wait(3))
                finally:
                    allow_recording.set()
                stop.join(5)
                self.assertFalse(stop.is_alive())
            finally:
                allow_recording.set()
                admission.join(5)
        self.assertFalse(admission.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(dict(results)["admission"][0], 202)
        self.assertEqual(dict(results)["stop"][0], 200)
        self.assertEqual(self.gate.accept(*self.envelope("2"), now=NOW)[0], 423)
        self.assertEqual(self.counts(), (1, 1, 2))
        self.assertTrue(self.gate.verify_audit())

    def test_stop_winning_lock_denies_waiting_admission(self):
        stopper = Gateway(self.path, TRANSPORT, APPROVAL, {"ASTRA"})
        in_stop, allow_stop, admission_attempted = (threading.Event() for _ in range(3))
        original_append = stopper._append_audit
        original_db = self.gate._db
        results, errors = [], []

        def hold_stop(db, event):
            if event["event"] == "local_stop_engaged":
                in_stop.set()
                if not allow_stop.wait(3):
                    raise RuntimeError("test synchronization timeout")
            return original_append(db, event)

        def watched_admission_db():
            db = original_db()
            db.set_trace_callback(lambda sql: admission_attempted.set() if sql == "BEGIN IMMEDIATE" else None)
            return db

        def run(label, call):
            try:
                results.append((label, call()))
            except Exception as exc:
                errors.append(repr(exc))

        with patch.object(stopper, "_append_audit", side_effect=hold_stop), \
             patch.object(self.gate, "_db", side_effect=watched_admission_db):
            stop = threading.Thread(target=run, args=("stop", stopper.engage_local_stop))
            stop.start()
            try:
                self.assertTrue(in_stop.wait(3))
                admission = threading.Thread(target=run, args=("admission", lambda: self.gate.accept(*self.envelope(), now=NOW)))
                admission.start()
                try:
                    self.assertTrue(admission_attempted.wait(3))
                finally:
                    allow_stop.set()
                admission.join(5)
                self.assertFalse(admission.is_alive())
            finally:
                allow_stop.set()
                stop.join(5)
        self.assertFalse(stop.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(dict(results)["stop"][0], 200)
        self.assertEqual(dict(results)["admission"][0], 423)
        self.assertEqual(self.counts(), (0, 0, 1))
        self.assertTrue(self.gate.verify_audit())


if __name__ == "__main__":
    unittest.main()
