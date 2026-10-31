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

The system checks timestamp freshness (±5 minutes), approval expiry (within 5 minutes), nonce uniqueness and task uniqueness transactionally.

## Results

- 202 `RECORDED_ONLY_NO_EXECUTOR`: stored in SQLite; **not dispatched**.
- 400 or 413: invalid input.
- 401: unauthenticated, invalid signature or timestamp.
- 403: denied action, orchestrator or approval.
- 409: already-seen nonce or task.
- 423: Owner Kill Switch enabled (default).
- 503: storage unavailable.

Each response includes `executed:false`. The local Audit Ledger hashes minimal metadata, not credentials.

## Integration gate

n8n Cloud/instance login is separate from n8n Community. Do not place Owner approval keys in n8n Code or HTTP Request nodes. A future secured private HANTER bridge will produce signed events, while n8n can consume restricted, separately authorized workflow triggers.
