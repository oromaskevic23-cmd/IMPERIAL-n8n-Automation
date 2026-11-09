# IMPERIAL n8n Automation

**Enterprise-oriented HANTER → federated orchestrator → NCA automation interfaces for IMPERIAL Core.**

**Architect / Founder / Owner / CEO:** Alexander Nikolaevich Romaskevich (RomaskevicH).  
**Status:** executable local intake prototype + importable safe n8n dry-run workflows; **not deployed, not connected to a production n8n instance, no real NCA worker or commercial execution**.

## Implemented

- Authenticated HANTER intake: timestamp-bound HMAC over exact HTTP request bytes; bounded nonce; replay rejection.
- Signed, short-lived Approval Gateway grant, bound to exact task, agent, orchestrator and capability.
- Federated orchestrator allowlist; `ASTRA` is one orchestrator, not a central/global orchestrator.
- Owner Kill Switch **engaged by default**, also checked on every request.
- SQLite transactional intent recording, task deduplication, hash-chained audit records and verification helper.
- A persistent, transactionally ordered **local-only** stop latch and a 1,000-task recording cap; no automatic audit deletion or remote Owner control.
- Single safe action: `simulate:task` (record intent only, **no execution**).
- Two independently authored, importable n8n workflow JSON examples with no credentials or network calls.
- Automated tests + schema checks via GitHub Actions.

## Quick start (local only)

Requires Python 3.11+, no runtime dependencies:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 tools/validate_workflows.py
```

To start the local ingress API, provision **two different random secrets** in a protected private environment and explicitly configure permitted orchestrators:

```bash
export IMPERIAL_INGRESS_SECRET='<private 32+ byte random value>'
export IMPERIAL_APPROVAL_SECRET='<different private 32+ byte random value>'
export IMPERIAL_ALLOWED_ORCHESTRATORS='ASTRA'
export IMPERIAL_OWNER_KILL_SWITCH='1'
PYTHONPATH=src python3 -m imperial_n8n.http_server
```

By default the gateway binds to `127.0.0.1:8765` and is **readiness-only** until the private Owner Kill Switch is explicitly disengaged. Do not publish it directly to the internet: production needs TLS reverse proxy, identity infrastructure, key custody, rate limits, monitoring, SSO and external independent QA.

## Directories

- `src/imperial_n8n/gateway.py` — authenticated, approval-scoped, replay-safe local intake.
- `src/imperial_n8n/http_server.py` — minimal loopback-only HTTP adapter.
- `workflows/` — n8n safe dry-run templates; inactive on export.
- `tests/` — deterministic positive, negative, replay, tamper, kill-switch and ledger tests.
- `docs/ARCHITECTURE.md`, `docs/RUNBOOK.md`, `docs/THREAT_MODEL.md` — precise interfaces, control gates and limitations.

## Verification vs future work

| Component | Local implementation | Production confirmation |
| --- | --- | --- |
| Authorized task intake | Yes | No |
| Persistent nonce / task uniqueness | SQLite local | No |
| SQLite hash-chained Audit Ledger | Yes, not tamper-proof to DB admin | No |
| n8n workflow JSON schema checks | Yes | Import into a real n8n instance not checked |
| Guardian Core / AI Passport | External interfaces planned; not authenticated here | No |
| HANTER online, ASTRA online, NCA workers / local LLM | No | No |
| 24/7 server / CRM-SOFFT / customer automation | No | No |

The related [IMPERIAL Plugins](https://github.com/oromaskevic23-cmd/IMPERIAL-Plugins) repository contains a separate policy prototype. Integration must enforce both policy and transport controls before execution.

## Licensing and boundaries

Original repository code is subject to [LICENSE.md](LICENSE.md), **not** a general open-source grant. n8n is a third-party product; the sample workflows use documented n8n node formats without bundling n8n source, icons or trademarks. The public repo must not contain production keys or private data. See [SECURITY.md](SECURITY.md).

## Transport specification

[API protocol and threat boundaries](docs/API_PROTOCOL.md) define the recorded-only transport, bounded request, approval signatures and response codes. The HTTP adapter rejects ambiguous duplicate authorization headers, transfer-encoding ambiguity and non-JSON requests.


---

### Canonical founder and public project identity

This public repository is listed in the [founder-maintained IMPERIAL Core engineering portfolio](https://oromaskevic23-cmd.github.io/oromaskevic23-cmd/projects/). The public [engineering source registry](https://oromaskevic23-cmd.github.io/Capital-Core-Public/reference/projects/) links this source to the account's published project records under **Alexander Nikolaevich Romaskevich (RomaskevicH)**, Founder, Owner and CEO of IMPERIAL Core and its final architectural decision authority. Repository-specific governance, contributor rights, third-party intellectual property, and documented independence of individual projects remain unchanged. Publication does not prove production execution, market adoption or Google indexing.
