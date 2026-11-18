"""
Hierarchical PromptOps & Modular Prompt Registry.

Manages, indexes, verifies synchronization, and hierarchically composes runtime
prompt modules from prompts/modules/ and the centralized modular_prompt.md catalog
adhering strictly to GEMINI.md Section 3.11 and Section 3.7.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from secops_identity_sentinel.reasoner.prompt_compiler import (
    SYSTEM_DIRECTIVE_ENFORCEMENT,
    get_default_prompts_dir,
    load_prompt_file,
)

PromptModuleId = Literal[
    "identity",
    "auth",
    "network",
    "workload",
    "guardrails",
    "mcp_runbooks",
]

CANONICAL_PROMPT_MODULES: Final[dict[str, dict[str, str]]] = {
    "identity": {
        "title": "Identity Anomaly Evaluation Module",
        "file_path": "modules/identity.md",
        "description": (
            "Evaluation of cloud identity telemetry, dormant principal activation, "
            "IAM tampering, and credential abuse."
        ),
    },
    "auth": {
        "title": "Authentication & Access Anomaly Evaluation Module",
        "file_path": "modules/auth.md",
        "description": (
            "Brute-force, credential stuffing, and OAuth token refresh velocity detection."
        ),
    },
    "network": {
        "title": "Network & Geolocation Anomaly Evaluation Module",
        "file_path": "modules/network.md",
        "description": (
            "Impossible travel (>900 km/h), high-risk ASN ingress, and CIDR containment."
        ),
    },
    "workload": {
        "title": "Compute & Container Workload Anomaly Evaluation Module",
        "file_path": "modules/workload.md",
        "description": ("IMDS scraping, container privilege escalation, and workload isolation."),
    },
    "guardrails": {
        "title": "Guardrails, Safety Scoring & Mitigation Module",
        "file_path": "modules/guardrails.md",
        "description": (
            "Break-glass protection, 1-5 safety risk scoring, and mandatory deterministic "
            "rollback rules."
        ),
    },
    "mcp_runbooks": {
        "title": "MCP Protocol Runbooks & Tool Dispatch Module",
        "file_path": "modules/mcp_runbooks.md",
        "description": (
            "Tool invocation policies, 10MB payload ceiling, HMAC signing verification, "
            "and protocol safeguards."
        ),
    },
}


class PromptSyncError(RuntimeError):
    """
    Raised when runtime prompt modules fail synchronization against modular_prompt.md.
    """


class PromptModuleDefinition(BaseModel):
    """
    Typed, immutable representation of a runtime prompt module.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    module_id: str = Field(..., description="Canonical module identifier.")
    title: str = Field(..., description="Human-readable module title.")
    file_path: str = Field(..., description="Relative file path under prompts directory.")
    description: str = Field(..., description="Functional scope description.")
    content: str = Field(..., description="Raw markdown content of the module.")
    checksum: str = Field(..., description="SHA-256 digest of normalized module content.")


def get_default_modular_prompt_path() -> Path:
    """
    Return default absolute path to modular_prompt.md at the workspace root.
    """
    return Path("modular_prompt.md").resolve()


def compute_content_checksum(content: str) -> str:
    """
    Compute a normalized SHA-256 hex digest for prompt content comparison.
    """
    normalized = content.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class PromptRegistry:
    """
    Centralized PromptOps Registry coordinating modular prompts and master instructions.
    """

    def __init__(
        self,
        prompts_dir: str | Path | None = None,
        modular_prompt_path: str | Path | None = None,
    ) -> None:
        self._prompts_dir: Path = (
            Path(prompts_dir).resolve() if prompts_dir is not None else get_default_prompts_dir()
        )
        self._modular_prompt_path: Path = (
            Path(modular_prompt_path).resolve()
            if modular_prompt_path is not None
            else get_default_modular_prompt_path()
        )
        self._module_cache: dict[str, PromptModuleDefinition] = {}

    @property
    def prompts_dir(self) -> Path:
        """Absolute path to the base prompts directory."""
        return self._prompts_dir

    @property
    def modular_prompt_path(self) -> Path:
        """Absolute path to modular_prompt.md."""
        return self._modular_prompt_path

    def get_module(self, module_id: str, reload: bool = False) -> PromptModuleDefinition:
        """
        Load and return a specific prompt module by canonical module_id.

        Args:
            module_id: Canonical ID (e.g. 'identity', 'auth', 'network').
            reload: If True, bypass cache and reload from disk.

        Returns:
            PromptModuleDefinition

        Raises:
            KeyError: If module_id is not in CANONICAL_PROMPT_MODULES.
            PromptPathTraversalError: If file path traverses outside prompts_dir.
            FileNotFoundError: If runtime file is missing.
        """
        clean_id = module_id.strip().lower()
        if clean_id not in CANONICAL_PROMPT_MODULES:
            raise KeyError(
                f"Unknown prompt module ID '{module_id}'. Valid IDs: "
                f"{sorted(CANONICAL_PROMPT_MODULES.keys())}"
            )

        if not reload and clean_id in self._module_cache:
            return self._module_cache[clean_id]

        meta = CANONICAL_PROMPT_MODULES[clean_id]
        content = load_prompt_file(meta["file_path"], prompts_dir=self._prompts_dir)
        checksum = compute_content_checksum(content)

        defn = PromptModuleDefinition(
            module_id=clean_id,
            title=meta["title"],
            file_path=meta["file_path"],
            description=meta["description"],
            content=content,
            checksum=checksum,
        )
        self._module_cache[clean_id] = defn
        return defn

    def list_modules(self, reload: bool = False) -> list[PromptModuleDefinition]:
        """
        Return all canonical prompt module definitions in deterministic order.
        """
        modules: list[PromptModuleDefinition] = []
        for mod_id in sorted(CANONICAL_PROMPT_MODULES.keys()):
            modules.append(self.get_module(mod_id, reload=reload))
        return modules

    def load_all_modules(self, reload: bool = False) -> dict[str, PromptModuleDefinition]:
        """
        Return a dictionary mapping module_id -> PromptModuleDefinition for all modules.
        """
        return {defn.module_id: defn for defn in self.list_modules(reload=reload)}

    def compose_hierarchical_directive(
        self,
        module_ids: list[str] | None = None,
        include_system_directive: bool = True,
    ) -> str:
        """
        Compose a complete, hierarchical system directive from the master directive
        and specified domain prompt modules.

        Args:
            module_ids: List of module IDs to include. If None, includes all canonical modules.
            include_system_directive: Whether to prepend the base SYSTEM_DIRECTIVE_ENFORCEMENT.

        Returns:
            str: Composed hierarchical prompt string.
        """
        sections: list[str] = []

        if include_system_directive:
            sections.append(SYSTEM_DIRECTIVE_ENFORCEMENT.strip())

        target_ids = (
            [m.strip().lower() for m in module_ids]
            if module_ids is not None
            else sorted(CANONICAL_PROMPT_MODULES.keys())
        )

        for mod_id in target_ids:
            defn = self.get_module(mod_id)
            module_header = f"---\n# [PROMPT_MODULE: {defn.module_id.upper()}]"
            sections.append(f"{module_header}\n{defn.content.strip()}")

        return "\n\n".join(sections)

    def verify_registry_synchronization(
        self,
        modular_prompt_path: str | Path | None = None,
    ) -> bool:
        """
        Verify that modular_prompt.md is fully synchronized with runtime prompt modules.

        Enforces:
          1. Document existence and UTF-8 encoding.
          2. Inclusion of the master system directive.
          3. Indexing of all canonical module IDs.
          4. Verbatim matching of each module's core content block.

        Raises:
            PromptSyncError: If synchronization checks fail.

        Returns:
            bool: True if perfectly synchronized.
        """
        target_path = (
            Path(modular_prompt_path).resolve()
            if modular_prompt_path is not None
            else self._modular_prompt_path
        )

        if not target_path.exists():
            raise PromptSyncError(
                f"Prompt registry document '{target_path}' does not exist. "
                "Adhering to GEMINI.md Section 3.11, modular_prompt.md must be maintained."
            )

        if not target_path.is_file():
            raise PromptSyncError(
                f"Prompt registry document '{target_path}' is a directory, not a file."
            )

        doc_content = target_path.read_text(encoding="utf-8")
        doc_normalized = doc_content.replace("\r\n", "\n")

        # 1. Verify master directive inclusion
        norm_directive = SYSTEM_DIRECTIVE_ENFORCEMENT.replace("\r\n", "\n").strip()
        if norm_directive not in doc_normalized:
            raise PromptSyncError(
                "modular_prompt.md is missing or has an out-of-sync master system directive "
                "(SYSTEM_DIRECTIVE_ENFORCEMENT)."
            )

        # 2. Verify all canonical modules are present and content is synchronized
        for mod_id, meta in CANONICAL_PROMPT_MODULES.items():
            # Check table/index presence
            if f"`{mod_id}`" not in doc_normalized:
                raise PromptSyncError(
                    f"modular_prompt.md is missing canonical index entry for module '{mod_id}'."
                )

            # Check runtime file exists and matches
            defn = self.get_module(mod_id)
            norm_content = defn.content.replace("\r\n", "\n").strip()
            if norm_content not in doc_normalized:
                raise PromptSyncError(
                    f"modular_prompt.md content for module '{mod_id}' ({meta['file_path']}) "
                    "does not match runtime prompt module file."
                )

        return True

    def generate_registry_markdown(self) -> str:
        """
        Generate complete, synchronized modular_prompt.md markdown text from
        active runtime modules and master directives.
        """
        lines: list[str] = [
            "# Modular PromptOps & Agent Instruction Registry (`modular_prompt.md`)",
            "# ==============================================================================",
            "# secops-identity-sentinel — Centralized PromptOps & Modular Instruction Catalog",
            "# ==============================================================================",
            "# This registry defines, indexes, and maintains all master system directives,",
            "# domain-specific evaluation prompt modules, and MCP runbooks utilized by the",
            "# autonomous reasoning cascade (Gemini 3.8 Flash High, OpenRouter fallback,",
            "# and offline deterministic heuristics) adhering strictly to GEMINI.md Section 3.11.",
            "# ==============================================================================",
            "",
            "## 1. PromptOps Governance & Architectural Invariants",
            "",
            "Adhering to `GEMINI.md` Section 3.7 and Section 3.11, all reasoning prompts "
            "must satisfy the following non-negotiable standards:",
            "",
            "1. **Centralized Registry Invariant:** Never scatter unversioned or undocumented "
            "prompts inline inside Python source files. All system instructions, domain "
            "evaluation modules, and operational runbooks must be indexed and synchronized "
            "between this document (`modular_prompt.md`) and runtime module files under "
            "`prompts/modules/`.",
            "2. **Path Traversal & Cross-Platform UTF-8 I/O:** All prompt file loaders must "
            'strictly enforce `Path.is_relative_to(prompts_dir)` and specify `encoding="utf-8"`.',
            "3. **Strict Action Allowlist:** The prompt compiler explicitly commands the LLM "
            "to propose actions exclusively from the canonical `ActionType` allowlist:",
            "   - `REVOKE_SESSION`",
            "   - `QUARANTINE_IAM_ROLE`",
            "   - `BLOCK_CIDR`",
            "   - `ROTATE_API_KEY`",
            "   - `SUSPEND_SERVICE_ACCOUNT`",
            "   - `ENFORCE_STEP_UP_MFA`",
            "   - `ISOLATE_WORKLOAD`",
            "4. **Zero-Hallucination Guardrail:** The reasoning engine must never synthesize "
            "raw CLI commands or IAM JSON policies directly. All execution payloads are "
            "overwritten deterministically by the `GuardrailEngine`.",
            "5. **Absolute Prompt Injection Defense:** All untrusted telemetry, OAuth scopes, "
            "User-Agents, IdP claims, and external strings must be enclosed inside "
            "`<untrusted_telemetry_data>` XML-style delimiters and stripped of XML breakout tags. "
            "System instructions explicitly assert that untrusted telemetry data must be treated "
            "as hostile evidence and can never override system rules or containment policies.",
            "",
            "---",
            "",
            "## 2. Master System Directive (`SYSTEM_DIRECTIVE_ENFORCEMENT`)",
            "",
            "```text",
            SYSTEM_DIRECTIVE_ENFORCEMENT.strip(),
            "```",
            "",
            "---",
            "",
            "## 3. Canonical Prompt Modules Index",
            "",
            "| Module ID | Module Title | Runtime File Path | Primary Threat Domain |",
            "| :--- | :--- | :--- | :--- |",
        ]

        for mod_id in sorted(CANONICAL_PROMPT_MODULES.keys()):
            meta = CANONICAL_PROMPT_MODULES[mod_id]
            lines.append(
                f"| `{mod_id}` | {meta['title']} | `{meta['file_path']}` | {meta['description']} |"
            )

        lines.extend(
            [
                "",
                "---",
                "",
                "## 4. Runtime Prompt Module Specifications",
                "",
            ]
        )

        for mod_id in sorted(CANONICAL_PROMPT_MODULES.keys()):
            meta = CANONICAL_PROMPT_MODULES[mod_id]
            defn = self.get_module(mod_id)
            lines.extend(
                [
                    f"### Module: `{mod_id}` (`{meta['file_path']}`)",
                    "```markdown",
                    defn.content.strip(),
                    "```",
                    "",
                ]
            )

        lines.extend(
            [
                "---",
                "",
                "## 5. Hierarchical Prompt Composition Pipeline",
                "",
                "The `PromptRegistry` compiles hierarchical system instructions dynamically by:",
                "1. Loading the master constitutional directive (`SYSTEM_DIRECTIVE_ENFORCEMENT`).",
                "2. Reading requested runtime modules from `prompts/modules/*.md` "
                "with path traversal isolation and UTF-8 decoding.",
                "3. Assembling the modular sections in deterministic order:",
                "   - Base Directives $\\to$ Threat Evaluation Modules "
                "(`identity`, `auth`, `network`, `workload`) $\\to$ Safety Floors "
                "(`guardrails`) $\\to$ Operational Runbooks (`mcp_runbooks`).",
                "4. Injecting the resulting prompt into `GeminiReasonerClient` or "
                "`OpenRouterFallbackClient`.",
                "",
            ]
        )

        return "\n".join(lines)

    def sync_to_modular_prompt_md(self, output_path: str | Path | None = None) -> str:
        """
        Deterministically write or update modular_prompt.md ensuring 100% synchronization.

        Returns:
            str: Generated markdown content.
        """
        target = (
            Path(output_path).resolve() if output_path is not None else self._modular_prompt_path
        )
        content = self.generate_registry_markdown()
        target.write_text(content, encoding="utf-8")
        return content


__all__: list[str] = [
    "PromptModuleId",
    "CANONICAL_PROMPT_MODULES",
    "PromptSyncError",
    "PromptModuleDefinition",
    "PromptRegistry",
    "get_default_modular_prompt_path",
    "compute_content_checksum",
]
