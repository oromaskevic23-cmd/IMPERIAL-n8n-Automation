"""Non-production cross-repository federation handoff.

Binds a real IMPERIAL Skill descriptor, IMPERIAL Plugins GuardianCore verdict
and the n8n intake transport BEFORE a recorded-only task may be stored.

No signing keys are issued here. Callers supply already-signed test-domain
credentials. This module does not grant permission to execute a worker.
Production must enforce equivalent policy inside a protected service boundary.
"""
from __future__ import annotations

import json

from imperial_n8n.gateway import Gateway
from imperial_plugins.core import GuardianCore, validate_manifest as validate_plugin
from imperial_skill.manifest import (
    SkillValidationError,
    validate_manifest as validate_skill,
)


def _deny(reason: str) -> tuple[int, dict]:
    return 403, {"state": reason, "executed": False}


def _unique_json_keys(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("DUPLICATE_KEY")
        obj[key] = value
    return obj


def _reject_nonfinite(value: str) -> None:
    raise ValueError("NON_FINITE")


def record_approved_simulation(
    *,
    skill_descriptor: dict,
    plugin_descriptor: dict,
    expected_tenant: str,
    expected_orchestrator: str,
    expected_domain: str,
    guardian: GuardianCore,
    plugin_request: dict,
    gateway: Gateway,
    raw_body: bytes,
    headers: dict,
    now: int,
) -> tuple[int, dict]:
    """Deny unless every separately owned control agrees on one safe task.

    Only `simulate:task` is permitted, and Gateway stores an intent only.
    A successful 202 response is NOT a worker/execution authorization.
    """
    try:
        skill = validate_skill(skill_descriptor)
        plugin = validate_plugin(plugin_descriptor)
        envelope = json.loads(
            raw_body.decode("utf-8"),
            object_pairs_hook=_unique_json_keys,
            parse_constant=_reject_nonfinite,
        )
    except (SkillValidationError, ValueError, TypeError, UnicodeError,
            RecursionError, AttributeError):
        return _deny("INVALID_FEDERATED_CONTRACT")

    if type(envelope) is not dict or set(envelope) != {
        "origin", "task_id", "orchestrator", "agent_id", "action", "approval"
    }:
        return _deny("ENVELOPE_SCHEMA_DENIED")
    if (
        skill["tenant_id"] != expected_tenant
        or skill["orchestrator_id"] != expected_orchestrator
        or skill["runtime_domain"] != expected_domain
        or envelope["orchestrator"] != expected_orchestrator
    ):
        return _deny("FEDERATION_BOUNDARY_DENIED")
    if (
        envelope["origin"] != "HANTER"
        or envelope["action"] != "simulate:task"
        or "simulate:task" not in skill["capabilities"]
        or "simulate:task" not in plugin["capabilities"]
        or skill["external_effects"] is not False
        or skill["production_authorized"] is not False
    ):
        return _deny("CAPABILITY_OR_EFFECT_DENIED")
    if type(plugin_request) is not dict or any(
        plugin_request.get(field) != envelope.get(field)
        for field in ("agent_id", "task_id", "action")
    ):
        return _deny("TASK_IDENTITY_MISMATCH")

    verdict = guardian.evaluate(plugin, plugin_request, now=now)
    if verdict.get("allowed") is not True:
        return _deny("GUARDIAN_" + str(verdict.get("reason", "DENIED")).upper())

    # The independently signed transport/approval and durable replay defense
    # are still checked by the n8n Gateway, not delegated to this adapter.
    return gateway.accept(raw_body, headers, now=now)
