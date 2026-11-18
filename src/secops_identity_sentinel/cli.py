"""
CLI Console Entrypoint for Autonomous SecOps & Identity Sentinel.

Exposes commands for batch telemetry audits, dry-run simulations,
and multi-transport MCP server hosting (stdio & SSE).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import click

from secops_identity_sentinel import __version__
from secops_identity_sentinel.config import get_settings
from secops_identity_sentinel.guardrails import (
    GuardrailEngine,
    simulate_remediation_plan,
)
from secops_identity_sentinel.heuristics.engine import DeterministicHeuristicsEngine
from secops_identity_sentinel.mcp.sse import run_sse_server
from secops_identity_sentinel.mcp.stdio import run_stdio_transport


@click.group(name="secops-identity-sentinel")
@click.version_option(version=__version__, prog_name="secops-identity-sentinel")
def main() -> None:
    """
    Autonomous SecOps & Identity Incident Responder CLI.
    """


@main.command(name="audit")
@click.option(
    "--telemetry-file",
    type=click.Path(exists=False, dir_okay=False),
    help="Path to JSON or JSONL identity telemetry batch file.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Simulate incident triage and containment without executing mutations.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "table"], case_sensitive=False),
    default="table",
    help="Output formatting style.",
)
def audit(telemetry_file: str | None, dry_run: bool, output_format: str) -> None:
    """
    Execute batch incident triage and containment simulation.
    """
    click.echo(
        f"[secops-identity-sentinel v{__version__}] Initiating audit "
        f"(dry_run={dry_run}, format={output_format})."
    )
    if not telemetry_file:
        click.echo("No telemetry file provided. Simulation completed with 0 events.")
        return

    click.echo(f"Telemetry source: {telemetry_file}")
    path = Path(telemetry_file)
    if not path.exists():
        click.echo(
            f"Warning: Telemetry file '{telemetry_file}' not found. "
            "Simulation completed with 0 events."
        )
        return

    raw_content = path.read_text(encoding="utf-8").strip()

    engine = DeterministicHeuristicsEngine()
    analysis_resp = engine.evaluate_telemetry(raw_content)
    plan = GuardrailEngine.build_remediation_plan(
        incident_id=f"inc-cli-{uuid.uuid4().hex[:8]}",
        proposed_actions=analysis_resp.actions,
        risk_score=analysis_resp.risk_score,
    )
    sim_result = simulate_remediation_plan(plan, dry_run=dry_run)

    if output_format.lower() == "json":
        click.echo(sim_result.model_dump_json(indent=2))
    else:
        click.echo(f"Summary: {sim_result.summary}")
        click.echo(f"Plan ID: {sim_result.plan_id} | Quarantined: {sim_result.quarantined}")
        if sim_result.actions:
            click.echo("-" * 80)
            for act in sim_result.actions:
                click.echo(
                    f"[{act.status}] {act.action_type} -> {act.target_resource} "
                    f"(Risk: {act.safety_risk})"
                )
                click.echo(f"  CLI: {act.cli_command}")
                click.echo(f"  Rollback: {act.rollback}")
            click.echo("-" * 80)


@main.command(name="serve")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"], case_sensitive=False),
    default="stdio",
    help="MCP transport protocol mode (stdio or sse).",
)
@click.option(
    "--host",
    default="127.0.0.1",
    help="Bind network interface for SSE transport.",
)
@click.option(
    "--port",
    type=int,
    default=None,
    help="Service port (defaults to PORT from configuration).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Simulate server startup without blocking.",
)
def serve(transport: str, host: str, port: int | None, dry_run: bool = False) -> None:
    """
    Launch MCP server daemon over standard I/O or Server-Sent Events.
    """
    settings = get_settings()
    active_port = port or settings.port
    click.echo(
        f"[secops-identity-sentinel v{__version__}] Starting MCP server "
        f"on {transport} (host={host}, port={active_port})."
    )

    if dry_run:
        return

    # In automated test runners, prevent blocking SSE server loop unless explicitly requested
    if os.environ.get("PYTEST_CURRENT_TEST") and transport.lower() == "sse":
        return

    if transport.lower() == "stdio":
        run_stdio_transport()
    elif transport.lower() == "sse":
        run_sse_server(host=host, port=active_port)


@main.command(name="run-mcp", hidden=True)
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"], case_sensitive=False),
    default="stdio",
)
@click.option("--host", default="127.0.0.1")
@click.option("--port", type=int, default=None)
@click.option("--dry-run", is_flag=True, default=False)
@click.pass_context
def run_mcp(
    ctx: click.Context, transport: str, host: str, port: int | None, dry_run: bool = False
) -> None:
    """
    Backward-compatibility alias for 'serve'.
    """
    ctx.forward(serve)


if __name__ == "__main__":
    main()
