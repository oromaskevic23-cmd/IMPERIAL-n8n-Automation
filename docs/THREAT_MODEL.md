# Security design and residual risk

| Attack | Implemented defense | Still needed |
| --- | --- | --- |
| Unauthenticated command | HMAC over exact bytes | protected gateway credentials, TLS/mTLS |
| Replay | nonce uniqueness + freshness window | distributed store/HA |
| Duplicate tasks | unique task ID + transaction | cross-region coordination |
| Unapproved task | distinct scoped HMAC approval | real owner approval service and protected key |
| Unauthorized orchestrator | explicit allowlist | tenant scoping and least-privilege workers |
| Privilege escalation | only `simulate:task`, recording only | policy engine and sandbox |
| Emergency stop | kill switch on every call, fail closed | external control-plane enforcement |
| Ledger tamper | SHA-256 local hash chain | external immutable evidence and anchoring |
| Data exfiltration | no external calls / no secrets in templates | DLP, redaction, egress firewall |
| Supply chain | pinned checkout SHA + read-only CI | trusted builds, pinned dependencies, SBOM |

## Production blockers

Real authentication with AI Passport + Guardian Core; Owner Approval Gateway independent of HANTER; dedicated orchestrator/tenant isolation; isolated worker execution; durable distributed replay prevention; secure key storage/rotation; licensed n8n runtime deployment; observability and independent QA; backups, retention, external attestation and signed releases.

No production-grade security claim is made by this prototype.
