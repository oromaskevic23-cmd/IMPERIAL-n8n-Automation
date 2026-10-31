# Secure operator runbook (local proof only)

1. Start with `IMPERIAL_OWNER_KILL_SWITCH=1` and confirm `GET http://127.0.0.1:8765/healthz` reports `execution: disabled`.
2. Generate and provision two unrelated, 32+ byte random keys in a private secret manager; never commit them. Set the orchestrator allowlist explicitly.
3. Run `PYTHONPATH=src python3 -m unittest discover -s tests -v` and `python3 tools/validate_workflows.py`. Check your current GitHub Actions run separately; do not infer it passed from configuration alone.
4. Import `workflows/01_simulation_dry_run.json` in your owned n8n instance, review Code node, and run it manually. Expect only a JSON simulation document.
5. Keep production execution **disabled**: never link this repository's demo credentials to customer accounts, financial services or commercial platforms.
6. To authorize real agent execution in a future release, first implement and separately verify protected issuer, AI Passport, Guardian Core, Approval Gateway, sandbox, replay DB, distributed audit, independent QA and rollback.
7. In an incident, set the Owner Kill Switch to `1`, isolate endpoint, preserve logs, rotate issuer keys, investigate Audit Ledger, and issue an Owner-approved recovery.

Current n8n Community forum membership does not establish n8n Cloud/instance access. A workspace URL and authorized integration are required for deployment; never infer them from forum login.
