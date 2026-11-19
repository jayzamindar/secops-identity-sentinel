"""
Core MCP Capabilities, Tools, Prompts, and Resources Catalog.

Registers and dispatches tools, operational prompts, live resources, and
protocol version negotiation adhering to GEMINI.md Section 4 and TRD Section 5.3.
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from secops_identity_sentinel import __version__
from secops_identity_sentinel.guardrails.engine import GuardrailEngine
from secops_identity_sentinel.heuristics.catalog import (
    load_identity_catalog,
)
from secops_identity_sentinel.heuristics.engine import DeterministicHeuristicsEngine
from secops_identity_sentinel.ledger.audit_logger import get_audit_logger
from secops_identity_sentinel.ledger.db import get_ledger_db
from secops_identity_sentinel.mcp.protocol import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    JSONRPCRequest,
    JSONRPCResponse,
)
from secops_identity_sentinel.models.actions import VALID_ACTION_TYPES
from secops_identity_sentinel.models.audit import AuditEvent
from secops_identity_sentinel.reasoner.cascade import MultiModelCascadeRelay

logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOL_VERSIONS: list[str] = ["2024-11-05"]
ACTIVE_PROTOCOL_VERSION: str = "2024-11-05"

# ------------------------------------------------------------------------------
# Tool Specifications
# ------------------------------------------------------------------------------
TOOLS_SPEC = [
    {
        "name": "triage_security_incident",
        "description": (
            "Analyzes security telemetry and auth events, identifying compromises and anomalies."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "telemetry": {
                    "type": "string",
                    "description": "JSON string, JSONL batch, or raw telemetry payload to evaluate",
                }
            },
            "required": ["telemetry"],
        },
    },
    {
        "name": "generate_containment_plan",
        "description": "Produces signed containment and remediation plans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "Unique incident identifier",
                },
                "proposed_actions": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of proposed containment actions",
                },
                "risk_score": {
                    "type": "integer",
                    "description": "Assessed incident risk score (1-5)",
                },
                "idempotency_key": {
                    "type": "string",
                    "description": "Optional unique idempotency deduplication key",
                },
            },
            "required": ["incident_id", "proposed_actions", "risk_score"],
        },
    },
    {
        "name": "get_incident_audit_summary",
        "description": "Returns cumulative incident and containment ledger metrics.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "lookup_identity_blast_radius",
        "description": "Analyzes principal permissions and blast-radius exposure across resources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "principal_id": {
                    "type": "string",
                    "description": "Principal identifier (email or IAM role ARN)",
                }
            },
            "required": ["principal_id"],
        },
    },
]

# ------------------------------------------------------------------------------
# Prompt Specifications
# ------------------------------------------------------------------------------
PROMPTS_SPEC = [
    {
        "name": "sentinel_incident_triage_runbook",
        "description": "Step-by-step incident triage and containment runbook for agents.",
        "arguments": [
            {
                "name": "incident_id",
                "description": "Target incident ID to triage",
                "required": False,
            }
        ],
    },
    {
        "name": "containment_rollback_procedure",
        "description": "Emergency rollback and identity reinstatement execution prompt.",
        "arguments": [
            {
                "name": "plan_id",
                "description": "Target remediation plan ID to reverse",
                "required": True,
            }
        ],
    },
]

# ------------------------------------------------------------------------------
# Resource Specifications
# ------------------------------------------------------------------------------
RESOURCES_SPEC = [
    {
        "uri": "secops://audit/ledger",
        "name": "Audit Ledger Summary",
        "description": "Real-time cumulative audit metrics in JSON format.",
        "mimeType": "application/json",
    },
    {
        "uri": "secops://policies/risk-matrix",
        "name": "Risk Scoring Matrix",
        "description": "Safety scoring rules and mandatory mitigation criteria.",
        "mimeType": "application/json",
    },
    {
        "uri": "secops://config/identity-catalog",
        "name": "Authoritative Identity Catalog",
        "description": "Authoritative identity metadata, role tiers, and blast-radius policies.",
        "mimeType": "application/json",
    },
    {
        "uri": "secops://runbooks/incident-triage",
        "name": "Incident Triage Runbook",
        "description": "Markdown-formatted operational incident triage and containment runbook.",
        "mimeType": "text/markdown",
    },
]


class MCPHandler:
    """
    Dispatcher for JSON-RPC 2.0 requests across MCP tools, prompts, and resources.
    """

    def __init__(self, cascade_relay: MultiModelCascadeRelay | None = None) -> None:
        self.heuristics_engine = DeterministicHeuristicsEngine()
        self.cascade_relay = cascade_relay or MultiModelCascadeRelay(
            tertiary_engine=self.heuristics_engine
        )

    def handle_request(self, request: JSONRPCRequest) -> JSONRPCResponse | None:
        """
        Handle a parsed JSON-RPC request and return a JSON-RPC response,
        or None if request was a notification without an ID.
        """
        method = request.method
        req_id = request.id
        params = request.params or {}

        try:
            if method == "initialize":
                return self._handle_initialize(req_id, params)
            elif method == "notifications/initialized" or method == "initialized":
                # Notification: no response required
                return None
            elif method == "ping":
                return JSONRPCResponse.make_success(req_id, {})
            elif method == "tools/list":
                return JSONRPCResponse.make_success(req_id, {"tools": TOOLS_SPEC})
            elif method == "tools/call":
                return self._handle_tool_call(req_id, params)
            elif method == "prompts/list":
                return JSONRPCResponse.make_success(req_id, {"prompts": PROMPTS_SPEC})
            elif method == "prompts/get":
                return self._handle_prompt_get(req_id, params)
            elif method == "resources/list":
                return JSONRPCResponse.make_success(req_id, {"resources": RESOURCES_SPEC})
            elif method == "resources/read":
                return self._handle_resource_read(req_id, params)
            else:
                return JSONRPCResponse.make_error(
                    req_id,
                    METHOD_NOT_FOUND,
                    f"Method '{method}' not recognized",
                )
        except ValueError as val_err:
            return JSONRPCResponse.make_error(req_id, INVALID_PARAMS, str(val_err))
        except Exception as exc:
            logger.exception("Error executing MCP method '%s': %s", method, exc)
            return JSONRPCResponse.make_error(req_id, INTERNAL_ERROR, str(exc))

    def _handle_initialize(
        self, req_id: int | str | None, params: dict[str, Any] | list[Any]
    ) -> JSONRPCResponse:
        """
        Execute protocol version negotiation and capability advertisement.
        """
        client_version: str | None = None
        if isinstance(params, dict):
            client_version = params.get("protocolVersion")

        # Negotiate version: if client version provided and not supported, reject with -32602
        if client_version and client_version not in SUPPORTED_PROTOCOL_VERSIONS:
            # Check major version difference
            client_major = client_version.split("-")[0]
            server_major = ACTIVE_PROTOCOL_VERSION.split("-")[0]
            if client_major != server_major:
                return JSONRPCResponse.make_error(
                    req_id,
                    INVALID_PARAMS,
                    f"Incompatible MCP protocolVersion '{client_version}'. "
                    f"Supported versions: {SUPPORTED_PROTOCOL_VERSIONS}",
                )

        return JSONRPCResponse.make_success(
            req_id,
            {
                "protocolVersion": ACTIVE_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                    "prompts": {},
                    "resources": {},
                },
                "serverInfo": {
                    "name": "secops-identity-sentinel",
                    "version": __version__,
                },
            },
        )

    def _handle_tool_call(
        self, req_id: int | str | None, params: dict[str, Any] | list[Any]
    ) -> JSONRPCResponse:
        """
        Execute requested tool call by name.
        """
        if not isinstance(params, dict):
            return JSONRPCResponse.make_error(
                req_id, INVALID_PARAMS, "Tool call parameters must be an object"
            )

        name = params.get("name")
        arguments = params.get("arguments") or {}

        if not name:
            return JSONRPCResponse.make_error(
                req_id, INVALID_PARAMS, "Missing tool name in tool call"
            )

        if name == "triage_security_incident":
            raw_telemetry = arguments.get("telemetry")
            if not raw_telemetry:
                return JSONRPCResponse.make_error(
                    req_id, INVALID_PARAMS, "Missing 'telemetry' argument"
                )
            if not isinstance(raw_telemetry, str):
                raw_telemetry = json.dumps(raw_telemetry)

            analysis = self.cascade_relay.evaluate_telemetry(raw_telemetry)
            return JSONRPCResponse.make_success(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(analysis.model_dump(mode="json")),
                        }
                    ]
                },
            )

        elif name == "generate_containment_plan":
            incident_id = arguments.get("incident_id")
            proposed_actions = arguments.get("proposed_actions")
            risk_score = arguments.get("risk_score")
            idempotency_key = arguments.get("idempotency_key")

            if not incident_id or proposed_actions is None or risk_score is None:
                return JSONRPCResponse.make_error(
                    req_id,
                    INVALID_PARAMS,
                    "generate_containment_plan requires 'incident_id', "
                    "'proposed_actions', and 'risk_score'",
                )

            plan = GuardrailEngine.build_remediation_plan(
                incident_id=str(incident_id),
                proposed_actions=proposed_actions,
                risk_score=int(risk_score),
                idempotency_key=str(idempotency_key) if idempotency_key else None,
            )

            # Record audit events in SQLite ledger and JSONL log
            ledger_db = get_ledger_db()
            audit_logger = get_audit_logger()

            actions_to_log = plan.actions if not plan.quarantined else []
            if actions_to_log:
                for idx, action in enumerate(actions_to_log):
                    event = AuditEvent(
                        event_id=f"evt-{uuid.uuid4().hex[:12]}",
                        timestamp=plan.issued_at,
                        plan_id=plan.plan_id,
                        idempotency_key=f"{plan.idempotency_key}-{idx}",
                        principal_id=action.target_resource,
                        action_type=action.action_type,
                        target_resource=action.target_resource,
                        risk_score=action.safety_risk,
                        quarantined=False,
                        quarantine_reason=None,
                        plan_digest=plan.plan_digest,
                        plan_signature=plan.plan_signature,
                        raw_payload=action.model_dump_json(),
                    )
                    if ledger_db.record_audit_event(event):
                        audit_logger.write_event(event)
            else:
                event = AuditEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:12]}",
                    timestamp=plan.issued_at,
                    plan_id=plan.plan_id,
                    idempotency_key=f"{plan.idempotency_key}-quarantined",
                    principal_id="quarantine-principal",
                    action_type="ISOLATE_WORKLOAD",
                    target_resource="quarantine",
                    risk_score=plan.risk_score,
                    quarantined=True,
                    quarantine_reason=plan.quarantine_reason,
                    plan_digest=plan.plan_digest,
                    plan_signature=plan.plan_signature,
                    raw_payload=plan.model_dump_json(),
                )
                if ledger_db.record_audit_event(event):
                    audit_logger.write_event(event)

            return JSONRPCResponse.make_success(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": plan.model_dump_json(),
                        }
                    ]
                },
            )

        elif name == "get_incident_audit_summary":
            summary = get_ledger_db().get_audit_summary()
            return JSONRPCResponse.make_success(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(summary),
                        }
                    ]
                },
            )

        elif name == "lookup_identity_blast_radius":
            principal_id = arguments.get("principal_id")
            if not principal_id:
                return JSONRPCResponse.make_error(
                    req_id, INVALID_PARAMS, "Missing 'principal_id' argument"
                )

            catalog = load_identity_catalog()
            principal_entry = catalog.principals.get(str(principal_id))

            if principal_entry:
                data = {
                    "principal_id": principal_entry.principal_id,
                    "found": True,
                    "role": principal_entry.role,
                    "tier": principal_entry.tier,
                    "department": principal_entry.department,
                    "is_break_glass": principal_entry.is_break_glass,
                }
            else:
                data = {
                    "principal_id": principal_id,
                    "found": False,
                    "message": (
                        f"Principal '{principal_id}' not found in authoritative identity catalog."
                    ),
                }

            return JSONRPCResponse.make_success(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(data),
                        }
                    ]
                },
            )

        else:
            return JSONRPCResponse.make_error(req_id, METHOD_NOT_FOUND, f"Unknown tool '{name}'")

    def _handle_prompt_get(
        self, req_id: int | str | None, params: dict[str, Any] | list[Any]
    ) -> JSONRPCResponse:
        """
        Return structured operational prompt text and arguments.
        """
        if not isinstance(params, dict):
            return JSONRPCResponse.make_error(
                req_id, INVALID_PARAMS, "Prompt parameters must be an object"
            )

        name = params.get("name")
        arguments = params.get("arguments") or {}

        if not name:
            return JSONRPCResponse.make_error(req_id, INVALID_PARAMS, "Missing prompt name")

        if name == "sentinel_incident_triage_runbook":
            incident_id = arguments.get("incident_id", "<INCIDENT_ID>")
            text = (
                f"# Sentinel Operational Incident Triage Runbook (Incident: {incident_id})\n\n"
                "1. Telemetry Ingestion: Normalize incoming identity events and extract actor.\n"
                "2. Protection Check: Cross-reference principal against identity catalog.\n"
                "   - If tagged break-glass-admin or control-plane-root, quarantine immediately.\n"
                "3. Threat Analysis: Evaluate impossible-travel and privilege velocity.\n"
                "4. Containment Synthesis: Select minimal scoped ActionType from canonical list.\n"
                "5. Deterministic Overwriting: Generate rollback ITSM ticket or CLI reversal.\n"
                "6. Plan Sealing: Compute SHA-256 digest and HMAC-SHA256 signature with nonce.\n"
            )
            return JSONRPCResponse.make_success(
                req_id,
                {
                    "description": "Incident triage runbook execution guide",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": text,
                            },
                        }
                    ],
                },
            )

        elif name == "containment_rollback_procedure":
            plan_id = arguments.get("plan_id")
            if not plan_id:
                return JSONRPCResponse.make_error(
                    req_id, INVALID_PARAMS, "containment_rollback_procedure requires 'plan_id'"
                )

            text = (
                f"# Emergency Containment Rollback Procedure (Plan ID: {plan_id})\n\n"
                "1. Audit Ledger Lookup: Retrieve original signed remediation plan from ledger.\n"
                "2. Cryptographic Seal Verification: Verify HMAC-SHA256 signature and digest.\n"
                "3. Action Reversal: For each executed action in reverse chronological order:\n"
                "   - REVOKE_SESSION / ROTATE_API_KEY: Update ITSM incident ticket.\n"
                "   - QUARANTINE_IAM_ROLE: Detach DenyAll inline policy.\n"
                "   - BLOCK_CIDR: Remove security group / NACL deny rule.\n"
                "   - SUSPEND_SERVICE_ACCOUNT: Re-enable service account.\n"
                "   - ENFORCE_STEP_UP_MFA: Restore default MFA policy.\n"
                "   - ISOLATE_WORKLOAD: Restore original security group attachment.\n"
                "4. Post-Rollback Audit: Log rollback execution event to audit logs and ledger.\n"
            )
            return JSONRPCResponse.make_success(
                req_id,
                {
                    "description": "Emergency rollback procedure",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": text,
                            },
                        }
                    ],
                },
            )

        else:
            return JSONRPCResponse.make_error(req_id, METHOD_NOT_FOUND, f"Unknown prompt '{name}'")

    def _handle_resource_read(
        self, req_id: int | str | None, params: dict[str, Any] | list[Any]
    ) -> JSONRPCResponse:
        """
        Read live read-only resource contents by URI.
        """
        if not isinstance(params, dict):
            return JSONRPCResponse.make_error(
                req_id, INVALID_PARAMS, "Resource parameters must be an object"
            )

        uri = params.get("uri")
        if not uri:
            return JSONRPCResponse.make_error(req_id, INVALID_PARAMS, "Missing 'uri' parameter")

        if uri == "secops://audit/ledger":
            summary = get_ledger_db().get_audit_summary()
            return JSONRPCResponse.make_success(
                req_id,
                {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(summary, indent=2),
                        }
                    ]
                },
            )

        elif uri == "secops://policies/risk-matrix":
            risk_matrix = {
                "allowed_actions": sorted(VALID_ACTION_TYPES),
                "safety_risk_levels": {
                    "1": "Minimal risk (informational / audit logging only)",
                    "2": "Low risk (low blast radius, reversible user action)",
                    "3": "Moderate risk (mandatory automated rollback required)",
                    "4": "High risk (service disruption potential, mandatory rollback)",
                    "5": "Critical risk (immediate containment, strict mitigation required)",
                },
                "mandatory_mitigation_policy": (
                    "Any action with Risk >= 3 lacking explicit rollback is "
                    "quarantined fail-closed."
                ),
                "blast_radius_floors": {
                    "max_ipv4_block_size": "/16",
                    "max_ipv6_block_size": "/48",
                    "forbidden_subnets": [
                        "0.0.0.0/0",
                        "::/0",
                        "RFC1918 private",
                        "RFC6598 CGNAT",
                        "127.0.0.0/8 loopback",
                        "169.254.0.0/16 IMDS",
                    ],
                },
            }
            return JSONRPCResponse.make_success(
                req_id,
                {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps(risk_matrix, indent=2),
                        }
                    ]
                },
            )

        elif uri == "secops://config/identity-catalog":
            catalog_path = Path("config/identity_catalog.json")
            if not catalog_path.exists():
                return JSONRPCResponse.make_error(
                    req_id,
                    INTERNAL_ERROR,
                    "Identity catalog file 'config/identity_catalog.json' not found",
                )
            catalog_text = catalog_path.read_text(encoding="utf-8")
            return JSONRPCResponse.make_success(
                req_id,
                {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": catalog_text,
                        }
                    ]
                },
            )

        elif uri == "secops://runbooks/incident-triage":
            runbook_md = (
                "# Autonomous SecOps Incident Triage & Response Runbook\n\n"
                "## 1. Identity Triage\n"
                "Verify identity principal against catalog metadata.\n\n"
                "## 2. Risk Evaluation\n"
                "Calculate threat vectors: impossible travel, token velocity.\n\n"
                "## 3. Quarantine Guardrails\n"
                "Reject invalid actions. Overwrite payloads deterministically.\n"
            )
            return JSONRPCResponse.make_success(
                req_id,
                {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": runbook_md,
                        }
                    ]
                },
            )

        else:
            return JSONRPCResponse.make_error(
                req_id,
                METHOD_NOT_FOUND,
                f"Resource URI '{uri}' not found",
            )
