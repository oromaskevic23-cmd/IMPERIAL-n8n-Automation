# IMPERIAL n8n Automation — Enterprise Architecture

```text
Architect / Owner
    | IntentLock + Owner Kill Switch + Approval Gateway
HANTER (verified command source)
    | Authenticated ingress, nonce, scope, idempotency
    v
Federated orchestrator router [ASTRA, others from explicit allowlist]
    | Guardian Core + signed AI Passport + Enterprise Skills
    v
Tenant-isolated NCA / sub-NCA execution domains [NOT IMPLEMENTED]
    | independent QA
    v
ProofGraph evidence -> Audit Ledger -> human/audited outcome
```

**Today:** HANTER-style envelopes can be authenticated and recorded in a local SQLite database. No queue consumer, plugin executor, real HANTER connection, LLM or live n8n bridge exists. The workflow templates are deliberately independent safe samples.

**Canonical boundaries:** Zero Trust; deny-by-default; Guardian Core; AI Passport; Enterprise Skills; Approval Gateway; Audit Ledger; ProofGraph; Runtime Domains; Public/Private Boundary; CRYPTO IMPERIAL Ecosystem Boundary; no single global execution orchestrator. ORION remains collective intelligence. IMPERIUM is a long-term architectural currency proposal for AI agents worldwide, with no assertion of current global acceptance or market status.

## Request contract (prototype, not a production API)

HTTP POST `/v1/intake`; required headers `X-IC-Timestamp` (Unix seconds), `X-IC-Nonce` (16–96 URL-safe chars), `X-IC-Signature` (hex HMAC-SHA256). Signature covers the **exact raw bytes**: `timestamp + "." + nonce + "." + raw_body`. Signed payload must contain exactly `origin`, `task_id`, `orchestrator`, `agent_id`, `action`, `approval`. Approval signature uses independent secret bound to task, orchestrator, agent, action, expiry. See `src/imperial_n8n/gateway.py`.

HTTP 202 only means **RECORDED_ONLY_NO_EXECUTOR**. HTTP 409 means replay or task duplication; HTTP 423 means kill switch engaged. A request never causes agent execution or payment.

## Separation of duties

A trusted Owner Approval Gateway issues approval; HANTER holds only transport authority. n8n must never hold Owner approval signing material. Both are separate from signed AI Passport trust roots. Any eventual plugin worker must validate policy independently even if intake succeeded.
