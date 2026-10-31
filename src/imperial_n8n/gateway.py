"""Local HANTER ingress: fail-closed, replay-safe, recorded-only.

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
import time
from pathlib import Path

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,96}$")
MAX_SKEW = 300
MAX_BODY = 65536
GENESIS = "0" * 64


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


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
        self.transport_secret = transport_secret
        self.approval_secret = approval_secret
        if (not isinstance(allowed_orchestrators, set)
            or any(not isinstance(o, str) or not ID_PATTERN.fullmatch(o)
                   for o in allowed_orchestrators)):
            raise ValueError("invalid federated allowlist")
        self.allowed_orchestrators = allowed_orchestrators
        with self._db() as db:
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

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @staticmethod
    def _out(code: int, state: str) -> tuple[int, dict]:
        return code, {"state": state, "executed": False}

    def accept(self, raw_body: bytes, headers: dict, *, now: int | None = None) -> tuple[int, dict]:
        """Store only; no network, agent execution or external side effect."""
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
        now = int(time.time()) if now is None else int(now)
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
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeError, ValueError):
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
                # Unique nonce and task ID are committed together. Crash => rollback.
                db.execute("INSERT INTO nonces(nonce,seen_at) VALUES(?,?)", (nonce, now))
                db.execute("""INSERT INTO tasks(task_id,orchestrator,agent_id,state,received_at)
                               VALUES(?,?,?,?,?)""", (
                    payload["task_id"], payload["orchestrator"], payload["agent_id"],
                    "RECORDED_ONLY_NO_EXECUTOR", now))
                last = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
                previous = last[0] if last else GENESIS
                event_json = canonical(event).decode()
                digest = hashlib.sha256((previous + event_json).encode()).hexdigest()
                db.execute("INSERT INTO audit(previous_hash,event_json,hash) VALUES(?,?,?)",
                           (previous, event_json, digest))
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
