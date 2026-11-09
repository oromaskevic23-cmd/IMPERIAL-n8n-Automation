# HANTER Intake API — Prototype Specification v0.2

**This is a local reference only; it must not be considered an authorized production integration.**

## Method, path and payload

`POST /v1/intake` with `Content-Type: application/json` and at most 65,536 bytes.

```json
{
  "origin": "HANTER",
  "task_id": "SIM-EXAMPLE-001",
  "orchestrator": "ASTRA",
  "agent_id": "NCA-424",
  "action": "simulate:task",
  "approval": {
    "expires_at": 1234567890,
    "signature": "<owner-issued HMAC hex signature>"
  }
}
```

All identifiers are bounded and validated. Additional fields are rejected. The `expires_at` in this illustration is **not a live valid grant**.

## Authentication

Required headers: `X-IC-Timestamp` Unix seconds, `X-IC-Nonce` 16–96 ASCII URL-safe characters, and `X-IC-Signature` lowercase hex HMAC-SHA256 calculated over `timestamp + "." + nonce + "." + exact JSON bytes` with the *transport key*.

The **approval** HMAC uses an entirely separate Owner Approval Gateway key over a canonical object containing `task_id`, `orchestrator`, `agent_id`, `action` and `expires_at`, prefixed `approval:v1:`. Both keys must remain private and independently provisioned. HMAC does not prove asymmetric owner identity or non-repudiation.

The gateway checks timestamp freshness (±5 minutes) and approval expiry (within
5 minutes), then rechecks both after acquiring the SQLite write lock. It also
denies wall-clock rollback and uses elapsed monotonic time to prevent a frozen
clock from extending the request's lifetime. The environment-based local stop
setting, the route allowlist and both signatures are checked again after the
lock. The environment setting is also checked immediately before commit.
Nonce and task uniqueness are committed in the same transaction as the audit
record. Local admission is capped at 1,000 recorded tasks; the gateway denies
additional requests rather than deleting audit evidence. Retention and recovery
require a separately reviewed procedure.

These checks do not turn the environment variable into an authenticated remote
kill switch: changing a parent shell's environment cannot update an already
running process, and there is no transactional remote stop or worker termination
in this prototype. The prototype has no supported live key-rotation or route
revocation API; direct changes to in-process variables and the environment are
not serialized with an in-flight commit. A trusted local caller can invoke
`engage_local_stop()`: its persistent one-way stop latch and audit event use
the same SQLite write lock as admission. Requests ordered after a completed
local stop are denied, including after a process restart. This method is not
exposed by the HTTP server, does not authenticate the Owner, and does not stop
remote or already-running workers. If persistence fails, the invoking Gateway
instance refuses further requests, but other instances are not guaranteed to
stop; the stop call raises and must not be reported as successful. Production
revocation and stop still require an authenticated, transactionally coordinated
policy control plane.

## Results

- 202 `RECORDED_ONLY_NO_EXECUTOR`: stored in SQLite; **not dispatched**.
- 400 or 413: invalid input.
- 401: unauthenticated, invalid signature or timestamp, or clock moved backwards.
- 403: denied action, orchestrator or approval.
- 409: already-seen nonce or task.
- 429: local recording capacity reached.
- 423: environment stop or local stop latch enabled.
- 503: storage unavailable or local stop state invalid.

Each response includes `executed:false`. The local Audit Ledger hashes minimal metadata, not credentials.

## Integration gate

n8n Cloud/instance login is separate from n8n Community. Do not place Owner approval keys in n8n Code or HTTP Request nodes. A future secured private HANTER bridge will produce signed events, while n8n can consume restricted, separately authorized workflow triggers.
