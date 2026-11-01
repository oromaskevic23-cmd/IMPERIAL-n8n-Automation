# HANTER × Enterprise Skill × IMPERIAL Plugins × n8n: Offline Integration Gate

**Owner / Architect:** Alexander Nikolaevich Romaskevich (RomaskevicH)  
**Classification:** source-level staging and independent CI contract tests; **NO PRODUCTION DEPLOYMENT**.

## Verified scope and evidence discipline

The new `integration/federated_handoff.py` imports **actual** code from three
repositories, with `IMPERIAL-Skill` and `IMPERIAL-Plugins` checked out at
**exact immutable commit SHA pins** in `.github/workflows/ci.yml`.

1. Read, validate and bind an Enterprise Skill descriptor to a specific tenant,
   federated orchestrator and Runtime Domain.
2. Validate a restricted plugin manifest; permit only the intersection of
   `simulate:task` capabilities.
3. Check that task, agent and action are identical across the untrusted
   transport and plugin Guardian Core approval request.
4. Verify synthetic HMAC AI Passport and Guardian/Owner policy decisions using
   the real IMPERIAL Plugins reference, before any database write.
5. Verify **separate** n8n signed transport and approval envelopes, nonce
   uniqueness, task-id deduplication and append-only SQLite hash chain.
6. Return `202 RECORDED_ONLY_NO_EXECUTOR`, `executed=false` on accepted
   simulations; deny any unauthorized requests without recording a job.
7. Run negative tests for wrong tenant/orchestrator/agent, missing passport,
   withheld capability, payment action, revoked control, forged signatures,
   JSON ambiguities and replay.

Local reproduction after obtaining the three checkouts at their reviewed
revision pins:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 tools/validate_workflows.py
PYTHONPATH=src:pinned-plugins/src:pinned-skill/src:integration \
  python3 -m unittest discover -s integration -p 'test_*.py' -v
```

**A CI workflow file or a commit is not a CI PASS.** Review the GitHub Actions
status on the exact PR head before merging or announcing verified success.

## Deliberately excluded production capabilities

- This is a **test adapter**, not a network-facing Gateway release. Existing
  n8n HTTP handlers do not automatically call this adapter.
- Test keys are static synthetic keys. HMAC is not production AI Passport PKI
  or Owner Ed25519 enrollment; signing keys MUST remain outside untrusted n8n
  workflows and plugins.
- Tenant and domain are protected by trusted adapter parameters but **not
  serialized into the current n8n transport contract**. A production protocol
  must bind tenant and domain cryptographically across all hops.
- The `202` response means one SQLite recorded intent. It does NOT run
  HANTER, VELION, NCA, an LLM, a sandbox, client work, a workflow on a
  deployed n8n service or a payment.
- SQLite hash chains are tamper-evident within their threat model, not
  immutable against DB administrators. No cross-region exactly-once guarantee.
- A valid Skill manifest and passed offline policy are NOT an individually
  approved NCA, independently evaluated professional competence or production
  approval. OWNER KILL SWITCH remains engaged by default in normal setup.

## Release blockers

Real Owner Ed25519 issuer enrollment and revocation; tenant/domain-signed
production envelope; authenticated service identities and protected signing
keys; real isolated persistent worker, independent QA, ProofGraph and Audit
Ledger; external immutable audit anchoring; recovery, observability and
security review; explicit Owner release.

**Fail closed. FREE_ONLY. Zero Trust.** Preserve Public/Private Boundary and
CRYPTO IMPERIAL Ecosystem Boundary. IMPERIUM is a long-term architectural
digital currency envisioned for AI agents worldwide, not a live market status.
