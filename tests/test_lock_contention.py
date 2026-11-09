"""Offline authorization races against a real SQLite write lock.

Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).
"""
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from imperial_n8n.gateway import Gateway, approve_request, sign_transport

TRANSPORT = b"T" * 32
APPROVAL = b"A" * 32
NOW = 10000


class LockContentionTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"IMPERIAL_OWNER_KILL_SWITCH": "0"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "gateway.db"
        self.gate = Gateway(self.path, TRANSPORT, APPROVAL, {"ASTRA"})

    def envelope(self, *, expiry=NOW + 100, timestamp=NOW):
        payload = {"origin": "HANTER", "task_id": "TASK-CONTENTION",
                   "orchestrator": "ASTRA", "agent_id": "NCA-424",
                   "action": "simulate:task"}
        payload["approval"] = {"expires_at": expiry,
                               "signature": approve_request(APPROVAL, payload, expiry)}
        raw = json.dumps(payload, sort_keys=True).encode()
        nonce, stamp = "nonce-lock-test-12345", str(timestamp)
        headers = {"X-IC-Timestamp": stamp, "X-IC-Nonce": nonce,
                   "X-IC-Signature": sign_transport(TRANSPORT, stamp, nonce, raw)}
        return raw, headers

    def contended_accept(self, raw, headers, during_wait):
        """Block the request inside BEGIN IMMEDIATE, then change a precondition."""
        locker = sqlite3.connect(str(self.path), isolation_level=None)
        locker.execute("BEGIN IMMEDIATE")
        attempted = threading.Event()
        original_db = self.gate._db

        def watched_db():
            db = original_db()
            db.set_trace_callback(lambda sql: attempted.set() if sql == "BEGIN IMMEDIATE" else None)
            return db

        results = []
        failures = []
        def send():
            try:
                results.append(self.gate.accept(raw, headers))
            except Exception as exc:
                failures.append(repr(exc))

        with patch.object(self.gate, "_db", side_effect=watched_db):
            thread = threading.Thread(target=send)
            thread.start()
            try:
                self.assertTrue(attempted.wait(timeout=3), "request did not reach the database lock")
                during_wait()
            finally:
                locker.rollback()
                locker.close()
                thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 1)
        return results[0]

    def assert_not_recorded(self):
        with sqlite3.connect(self.path) as db:
            for table in ("nonces", "tasks", "audit"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_owner_stop_during_lock_wait_denies_admission(self):
        with patch("imperial_n8n.gateway.time.time", return_value=NOW):
            code, result = self.contended_accept(
                *self.envelope(),
                lambda: os.environ.__setitem__("IMPERIAL_OWNER_KILL_SWITCH", "1"),
            )
        self.assertEqual((code, result["state"]), (423, "OWNER_KILL_SWITCH_ENGAGED"))
        self.assert_not_recorded()

    def test_valid_request_after_lock_wait_is_recorded_once(self):
        with patch("imperial_n8n.gateway.time.time", return_value=NOW):
            code, result = self.contended_accept(*self.envelope(), lambda: None)
        self.assertEqual((code, result["state"]), (202, "RECORDED_ONLY_NO_EXECUTOR"))
        with sqlite3.connect(self.path) as db:
            for table in ("nonces", "tasks", "audit"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 1)

    def test_invalid_replacement_key_fails_closed(self):
        with patch("imperial_n8n.gateway.time.time", return_value=NOW):
            code, result = self.contended_accept(
                *self.envelope(), lambda: setattr(self.gate, "approval_secret", b"short"))
        self.assertEqual((code, result["state"]), (503, "AUTH_CONFIGURATION_INVALID"))
        self.assert_not_recorded()

    def test_approval_expired_during_lock_wait_is_denied(self):
        current = [NOW]
        with patch("imperial_n8n.gateway.time.time", side_effect=lambda: current[0]):
            code, result = self.contended_accept(
                *self.envelope(), lambda: current.__setitem__(0, NOW + 101))
        self.assertEqual((code, result["state"]), (403, "APPROVAL_INVALID"))
        self.assert_not_recorded()

    def test_transport_expired_during_lock_wait_is_denied(self):
        current = [NOW]
        with patch("imperial_n8n.gateway.time.time", side_effect=lambda: current[0]):
            code, result = self.contended_accept(
                *self.envelope(timestamp=NOW - 299), lambda: current.__setitem__(0, NOW + 2))
        self.assertEqual((code, result["state"]), (401, "TIMESTAMP_INVALID"))
        self.assert_not_recorded()

    def test_wall_clock_rollback_during_lock_wait_is_denied(self):
        current = [NOW]
        with patch("imperial_n8n.gateway.time.time", side_effect=lambda: current[0]):
            code, result = self.contended_accept(
                *self.envelope(), lambda: current.__setitem__(0, NOW - 1))
        self.assertEqual((code, result["state"]), (401, "CLOCK_MOVED_BACKWARDS"))
        self.assert_not_recorded()

    def test_orchestrator_revoked_during_lock_wait_is_denied(self):
        with patch("imperial_n8n.gateway.time.time", return_value=NOW):
            code, result = self.contended_accept(
                *self.envelope(), lambda: setattr(self.gate, "allowed_orchestrators", frozenset()))
        self.assertEqual((code, result["state"]), (403, "ORCHESTRATOR_NOT_ALLOWED"))
        self.assert_not_recorded()

    def test_rotated_transport_key_during_lock_wait_is_denied(self):
        with patch("imperial_n8n.gateway.time.time", return_value=NOW):
            code, result = self.contended_accept(
                *self.envelope(), lambda: setattr(self.gate, "transport_secret", b"R" * 32))
        self.assertEqual((code, result["state"]), (401, "SIGNATURE_INVALID"))
        self.assert_not_recorded()

    def test_rotated_approval_key_during_lock_wait_is_denied(self):
        with patch("imperial_n8n.gateway.time.time", return_value=NOW):
            code, result = self.contended_accept(
                *self.envelope(), lambda: setattr(self.gate, "approval_secret", b"R" * 32))
        self.assertEqual((code, result["state"]), (403, "APPROVAL_INVALID"))
        self.assert_not_recorded()

    def test_frozen_clock_does_not_extend_approval(self):
        with patch("imperial_n8n.gateway.time.time", return_value=NOW):
            code, result = self.contended_accept(
                *self.envelope(expiry=NOW + 1), lambda: time.sleep(1.2))
        self.assertEqual((code, result["state"]), (403, "APPROVAL_INVALID"))
        self.assert_not_recorded()


if __name__ == "__main__":
    unittest.main()
