"""Local HANTER ingress: fail-closed, replay-safe, recorded-only.

Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).

No remote workers, no LLM dispatch, no payment execution, no credential store.
HMAC is a single trust-domain prototype, not Ed25519 identity or AI Passport.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,96}$")
MAX_SKEW = 300
MAX_BODY = 65536
MAX_RECORDED_TASKS = 1000
GENESIS = "0" * 64


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """Reject ambiguous JSON in both the envelope and nested approval."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> None:
    raise ValueError("NON_FINITE_JSON_NUMBER")


def sign_transport(secret: bytes, timestamp: str, nonce: str, raw_body: bytes) -> str:
    if len(secret) < 32:
        raise ValueError("secret too short")
    return hmac.new(secret, timestamp.encode() + b"." + nonce.encode() + b"." + raw_body,
                    hashlib.sha256).hexdigest()


def approve_request(secret: bytes, payload: dict, expires_at: int) -> str:
    """Privileged Owner Approval Gateway signing function; never send secret to n8n."""
    if len(secret) < 32 or type(expires_at) is not int:
        raise ValueError("invalid approval issuer input")
    fields = {k: payload[k] for k in ("task_id", "orchestrator", "agent_id", "action")}
    fields["expires_at"] = expires_at
    return hmac.new(secret, b"approval:v1:" + canonical(fields), hashlib.sha256).hexdigest()


class Gateway:
    def __init__(self, db_path: str | Path, transport_secret: bytes,
                 approval_secret: bytes, allowed_orchestrators: set[str]):
        if (not isinstance(transport_secret, bytes) or not isinstance(approval_secret, bytes)
            or len(transport_secret) < 32 or len(approval_secret) < 32
            or hmac.compare_digest(transport_secret, approval_secret)):
            raise ValueError("distinct transport and approval secrets >=32 bytes required")
        self.db_path = str(db_path)
        self._local_stop_requested = threading.Event()
        self.transport_secret = transport_secret
        self.approval_secret = approval_secret
        if (not isinstance(allowed_orchestrators, set) or not allowed_orchestrators
            or any(not isinstance(o, str) or not ID_PATTERN.fullmatch(o)
                   for o in allowed_orchestrators)):
            raise ValueError("invalid federated allowlist")
        self.allowed_orchestrators = frozenset(allowed_orchestrators)
        db = self._db()
        try:
            db.executescript("""CREATE TABLE IF NOT EXISTS nonces(
               nonce TEXT PRIMARY KEY, seen_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks(
               task_id TEXT PRIMARY KEY,
               orchestrator TEXT NOT NULL,
               agent_id TEXT NOT NULL,
               state TEXT NOT NULL,
               received_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit(
               seq INTEGER PRIMARY KEY AUTOINCREMENT,
               previous_hash TEXT NOT NULL,
               event_json TEXT NOT NULL,
               hash TEXT NOT NULL UNIQUE
            );""")
            # Create the local stop latch only on first migration. A missing
            # row in an existing table is an error, never an implicit reset.
            db.execute("BEGIN IMMEDIATE")
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                "AND name='local_control'").fetchone()
            if exists is None:
                db.execute("""CREATE TABLE local_control(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    stop_latched INTEGER NOT NULL CHECK(stop_latched IN (0,1))
                )""")
                db.execute("INSERT INTO local_control(id,stop_latched) VALUES(1,0)")
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @staticmethod
    def _out(code: int, state: str) -> tuple[int, dict]:
        return code, {"state": state, "executed": False}

    @staticmethod
    def _append_audit(db: sqlite3.Connection, event: dict) -> None:
        last = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = last[0] if last else GENESIS
        event_json = canonical(event).decode()
        digest = hashlib.sha256((previous + event_json).encode()).hexdigest()
        db.execute("INSERT INTO audit(previous_hash,event_json,hash) VALUES(?,?,?)",
                   (previous, event_json, digest))

    def engage_local_stop(self) -> tuple[int, dict]:
        """Latch a local-only stop; caller must already control this process.

        The stop and its audit entry share the same SQLite write lock as
        admission. This is not an authenticated Owner or remote HANTER API.
        There is intentionally no resume API in this prototype.
        """
        # Deny further use of this Gateway instance even if persistence fails.
        self._local_stop_requested.set()
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT stop_latched FROM local_control WHERE id=1").fetchone()
            if row is None or type(row[0]) is not int or row[0] not in (0, 1):
                raise sqlite3.DatabaseError("LOCAL_CONTROL_INVALID")
            if row[0] == 0:
                db.execute("UPDATE local_control SET stop_latched=1 WHERE id=1")
                self._append_audit(db, {"event": "local_stop_engaged",
                    "at": int(time.time()), "scope": "LOCAL_LAB_ONLY"})
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return self._out(200, "LOCAL_STOP_LATCHED")

    def accept(self, raw_body: bytes, headers: dict, *, now: int | None = None) -> tuple[int, dict]:
        """Store only; no network, agent execution or external side effect."""
        if self._local_stop_requested.is_set():
            return self._out(423, "LOCAL_STOP_REQUESTED")
        if os.getenv("IMPERIAL_OWNER_KILL_SWITCH", "1") != "0":
            return self._out(423, "OWNER_KILL_SWITCH_ENGAGED")
        if not isinstance(raw_body, bytes) or not 0 < len(raw_body) <= MAX_BODY:
            return self._out(413, "BODY_INVALID")
        if not isinstance(headers, dict):
            return self._out(401, "AUTHENTICATION_REQUIRED")
        h = {str(k).lower(): str(v) for k, v in headers.items()}
        timestamp, nonce, signature = (h.get("x-ic-timestamp", ""),
                                        h.get("x-ic-nonce", ""),
                                        h.get("x-ic-signature", ""))
        # Explicit ``now`` is for deterministic offline tests. The HTTP server
        # uses the real clock and always rechecks after acquiring the DB lock.
        supplied_now = now
        started = time.monotonic()
        first_wall = time.time() if supplied_now is None else supplied_now
        now = int(first_wall)
        if not (timestamp.isascii() and timestamp.isdigit() and len(timestamp) <= 15
                and NONCE_PATTERN.fullmatch(nonce)
                and isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{64}", signature)):
            return self._out(401, "AUTHENTICATION_REQUIRED")
        if abs(now - int(timestamp)) > MAX_SKEW:
            return self._out(401, "TIMESTAMP_INVALID")
        expected = sign_transport(self.transport_secret, timestamp, nonce, raw_body)
        if not hmac.compare_digest(expected, signature):
            return self._out(401, "SIGNATURE_INVALID")
        try:
            payload = json.loads(
                raw_body.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            )
        except (UnicodeError, ValueError, RecursionError):
            return self._out(400, "JSON_INVALID")
        if not isinstance(payload, dict) or set(payload) != {
            "origin", "task_id", "orchestrator", "agent_id", "action", "approval"
        }:
            return self._out(400, "SCHEMA_INVALID")
        if payload["origin"] != "HANTER" or payload["action"] != "simulate:task":
            return self._out(403, "ACTION_NOT_ALLOWED")
        if any(not isinstance(payload.get(key), str) or not ID_PATTERN.fullmatch(payload[key])
               for key in ("task_id", "orchestrator", "agent_id")):
            return self._out(400, "IDENTIFIER_INVALID")
        if payload["orchestrator"] not in self.allowed_orchestrators:
            return self._out(403, "ORCHESTRATOR_NOT_ALLOWED")
        approval = payload["approval"]
        if not isinstance(approval, dict) or set(approval) != {"expires_at", "signature"}:
            return self._out(403, "APPROVAL_REQUIRED")
        expiry, signed = approval.get("expires_at"), approval.get("signature")
        if (type(expiry) is not int or not now < expiry <= now + MAX_SKEW
            or not isinstance(signed, str) or not re.fullmatch(r"[0-9a-f]{64}", signed)):
            return self._out(403, "APPROVAL_INVALID")
        expected_approval = approve_request(self.approval_secret, payload, expiry)
        if not hmac.compare_digest(expected_approval, signed):
            return self._out(403, "APPROVAL_INVALID")
        event = {"event": "intake_recorded", "task_id": payload["task_id"],
                 "orchestrator": payload["orchestrator"], "agent_id": payload["agent_id"],
                 "action": payload["action"], "at": now,
                 "state": "RECORDED_ONLY_NO_EXECUTOR"}
        try:
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                # The database can remain locked after transport and approval
                # validation. Revalidate before recording any nonce or task.
                locked_wall = time.time() if supplied_now is None else supplied_now
                locked_now = int(locked_wall)
                elapsed = time.monotonic() - started
                if os.getenv("IMPERIAL_OWNER_KILL_SWITCH", "1") != "0":
                    db.rollback()
                    return self._out(423, "OWNER_KILL_SWITCH_ENGAGED")
                control = db.execute("SELECT stop_latched FROM local_control WHERE id=1").fetchone()
                if control is None or type(control[0]) is not int or control[0] not in (0, 1):
                    db.rollback()
                    return self._out(503, "LOCAL_CONTROL_INVALID")
                if control[0] == 1:
                    db.rollback()
                    return self._out(423, "LOCAL_STOP_LATCHED")
                if locked_wall < first_wall:
                    db.rollback()
                    return self._out(401, "CLOCK_MOVED_BACKWARDS")
                if (abs(locked_now - int(timestamp)) > MAX_SKEW or
                        elapsed > int(timestamp) + MAX_SKEW - first_wall):
                    db.rollback()
                    return self._out(401, "TIMESTAMP_INVALID")
                if not locked_now < expiry <= locked_now + MAX_SKEW or elapsed >= expiry - first_wall:
                    db.rollback()
                    return self._out(403, "APPROVAL_INVALID")
                # A trusted operator may have replaced configuration while the
                # request was waiting; never record under the old authority.
                transport_key, approval_key = self.transport_secret, self.approval_secret
                routes = self.allowed_orchestrators
                if (not isinstance(transport_key, bytes) or len(transport_key) < 32
                    or not isinstance(approval_key, bytes) or len(approval_key) < 32
                    or hmac.compare_digest(transport_key, approval_key)
                    or not isinstance(routes, (set, frozenset))):
                    db.rollback()
                    return self._out(503, "AUTH_CONFIGURATION_INVALID")
                if payload["orchestrator"] not in routes:
                    db.rollback()
                    return self._out(403, "ORCHESTRATOR_NOT_ALLOWED")
                if not hmac.compare_digest(sign_transport(transport_key, timestamp, nonce, raw_body), signature):
                    db.rollback()
                    return self._out(401, "SIGNATURE_INVALID")
                if not hmac.compare_digest(approve_request(approval_key, payload, expiry), signed):
                    db.rollback()
                    return self._out(403, "APPROVAL_INVALID")
                now = locked_now
                event["at"] = now
                if db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] >= MAX_RECORDED_TASKS:
                    db.rollback()
                    return self._out(429, "LOCAL_RECORDING_CAP_REACHED")
                # Unique nonce and task ID are committed together. Crash => rollback.
                db.execute("INSERT INTO nonces(nonce,seen_at) VALUES(?,?)", (nonce, now))
                db.execute("""INSERT INTO tasks(task_id,orchestrator,agent_id,state,received_at)
                               VALUES(?,?,?,?,?)""", (
                    payload["task_id"], payload["orchestrator"], payload["agent_id"],
                    "RECORDED_ONLY_NO_EXECUTOR", now))
                self._append_audit(db, event)
                # This catches a change during database work, but environment
                # mutation itself is not serialized: use the local latch for
                # a transactionally ordered local stop.
                if os.getenv("IMPERIAL_OWNER_KILL_SWITCH", "1") != "0":
                    db.rollback()
                    return self._out(423, "OWNER_KILL_SWITCH_ENGAGED")
                if self._local_stop_requested.is_set():
                    db.rollback()
                    return self._out(423, "LOCAL_STOP_REQUESTED")
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        except sqlite3.IntegrityError:
            return self._out(409, "REPLAY_OR_DUPLICATE_TASK")
        except sqlite3.Error:
            return self._out(503, "STORAGE_UNAVAILABLE")
        return self._out(202, "RECORDED_ONLY_NO_EXECUTOR")

    def verify_audit(self) -> bool:
        db = self._db()
        try:
            rows = db.execute("SELECT seq,previous_hash,event_json,hash FROM audit ORDER BY seq").fetchall()
        finally:
            db.close()
        previous = GENESIS
        for expected_seq, (seq, link, body, digest) in enumerate(rows, 1):
            computed = hashlib.sha256((link + body).encode()).hexdigest()
            if seq != expected_seq or link != previous or not hmac.compare_digest(computed, digest):
                return False
            previous = digest
        return True
