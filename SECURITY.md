# Security policy and operator warnings

- The **Owner Kill Switch defaults to engaged**. Only private, reviewed operator policy can disengage it. Even then intake records data only.
- Do not expose this reference HTTP server directly to the internet. It is bound to loopback by default and lacks TLS, rate limiting, HA, mTLS, centralized credential rotation and perimeter hardening.
- HANTER transport authentication is HMAC with nonce and timestamp; it is **not** AI Passport PKI, cryptographic license issuance or independent Owner identity. The separate plugin policy engine must be integrated prior to execution.
- Approval signing secret must remain under Owner-controlled protected service custody. Never put it in n8n workflow exports, email, GitHub Actions artifacts, frontend code or public repos.
- SQLite hash chaining is tamper evident against simple edits but **not immutable** against a fully privileged DB attacker. Back up/audit externally.
- Workflows under `workflows/` are inactive, locally calculated templates. Import, inspect and test against your licensed n8n instance before enabling any n8n workflow. They do not authorize remote work.
- No crypto transfers, wallet actions, exchange-listing claims, unauthorized platform automation or customer data processing are implemented.
- Use private vulnerability reporting rather than public issues for vulnerabilities; preserve evidence and revoke credentials on compromise.
