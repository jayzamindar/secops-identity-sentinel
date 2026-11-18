"""
Unit tests for Hierarchical PromptOps & modular_prompt.md Registry.

Verifies runtime prompt module loading, PromptRegistry caching, hierarchical
directive composition, path traversal isolation, synchronization verification
with modular_prompt.md, and error cascade handling adhering to GEMINI.md Section 3.11.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secops_identity_sentinel.reasoner.prompt_compiler import (
    SYSTEM_DIRECTIVE_ENFORCEMENT,
    PromptPathTraversalError,
    get_default_prompts_dir,
)
from secops_identity_sentinel.reasoner.prompt_registry import (
    CANONICAL_PROMPT_MODULES,
    PromptModuleDefinition,
    PromptRegistry,
    PromptSyncError,
    compute_content_checksum,
    get_default_modular_prompt_path,
)


def test_canonical_prompt_modules_catalog_completeness() -> None:
    """Verify that CANONICAL_PROMPT_MODULES contains all 6 required enterprise domains."""
    expected_ids = {"identity", "auth", "network", "workload", "guardrails", "mcp_runbooks"}
    assert set(CANONICAL_PROMPT_MODULES.keys()) == expected_ids

    prompts_dir = get_default_prompts_dir()
    for mod_id, meta in CANONICAL_PROMPT_MODULES.items():
        assert "title" in meta
        assert "file_path" in meta
        assert "description" in meta
        # Ensure corresponding runtime markdown file exists on disk
        target_file = prompts_dir / meta["file_path"]
        assert target_file.is_file(), f"Missing runtime prompt file for {mod_id}: {target_file}"


def test_prompt_registry_initialization_defaults_and_properties() -> None:
    """Verify PromptRegistry initializes with repository defaults and exposes properties."""
    registry = PromptRegistry()
    assert registry.prompts_dir == get_default_prompts_dir()
    assert registry.modular_prompt_path == get_default_modular_prompt_path()


def test_prompt_registry_get_module_success_and_caching() -> None:
    """Verify get_module loads PromptModuleDefinition with SHA-256 checksum and caches it."""
    registry = PromptRegistry()
    mod = registry.get_module("identity")

    assert isinstance(mod, PromptModuleDefinition)
    assert mod.module_id == "identity"
    assert mod.title == "Identity Anomaly Evaluation Module"
    assert "Identity Anomaly Evaluation Module" in mod.content
    assert mod.checksum == compute_content_checksum(mod.content)

    # Verify cached return on second call
    mod2 = registry.get_module("identity")
    assert mod is mod2

    # Verify reload bypasses cache
    mod_reloaded = registry.get_module("identity", reload=True)
    assert mod_reloaded == mod
    assert mod_reloaded is not mod


def test_prompt_registry_get_module_invalid_id_raises_key_error() -> None:
    """Verify get_module raises KeyError with allowed IDs on unknown module name."""
    registry = PromptRegistry()
    with pytest.raises(KeyError, match="Unknown prompt module ID 'unknown_mod'"):
        registry.get_module("unknown_mod")


def test_prompt_registry_list_and_load_all_modules() -> None:
    """Verify list_modules and load_all_modules return all 6 canonical modules."""
    registry = PromptRegistry()
    module_list = registry.list_modules()
    assert len(module_list) == 6

    ids = [m.module_id for m in module_list]
    assert ids == sorted(CANONICAL_PROMPT_MODULES.keys())

    all_dict = registry.load_all_modules()
    assert len(all_dict) == 6
    for mod_id in ids:
        assert mod_id in all_dict
        assert all_dict[mod_id].module_id == mod_id


def test_prompt_registry_compose_hierarchical_directive_full() -> None:
    """Verify hierarchical prompt composition combines master directive and all modules."""
    registry = PromptRegistry()
    prompt = registry.compose_hierarchical_directive()

    assert SYSTEM_DIRECTIVE_ENFORCEMENT.strip() in prompt
    for mod_id in CANONICAL_PROMPT_MODULES:
        assert f"# [PROMPT_MODULE: {mod_id.upper()}]" in prompt


def test_prompt_registry_compose_hierarchical_directive_selective() -> None:
    """Verify hierarchical prompt composition with selective modules and no master directive."""
    registry = PromptRegistry()
    prompt = registry.compose_hierarchical_directive(
        module_ids=["auth", "network"],
        include_system_directive=False,
    )

    assert SYSTEM_DIRECTIVE_ENFORCEMENT.strip() not in prompt
    assert "# [PROMPT_MODULE: AUTH]" in prompt
    assert "# [PROMPT_MODULE: NETWORK]" in prompt
    assert "# [PROMPT_MODULE: IDENTITY]" not in prompt
    assert "# [PROMPT_MODULE: WORKLOAD]" not in prompt


def test_prompt_registry_verify_synchronization_live_repository() -> None:
    """Verify live repository modular_prompt.md passes 100% synchronization verification."""
    registry = PromptRegistry()
    assert registry.verify_registry_synchronization() is True


def test_prompt_registry_verify_synchronization_missing_file_raises(tmp_path: Path) -> None:
    """Verify verify_registry_synchronization raises PromptSyncError if file missing."""
    registry = PromptRegistry()
    nonexistent = tmp_path / "nonexistent_modular_prompt.md"

    with pytest.raises(PromptSyncError, match="does not exist"):
        registry.verify_registry_synchronization(modular_prompt_path=nonexistent)


def test_prompt_registry_verify_synchronization_directory_raises(tmp_path: Path) -> None:
    """Verify verify_registry_synchronization raises PromptSyncError if path is a directory."""
    registry = PromptRegistry()
    test_dir = tmp_path / "some_dir"
    test_dir.mkdir()

    with pytest.raises(PromptSyncError, match="is a directory, not a file"):
        registry.verify_registry_synchronization(modular_prompt_path=test_dir)


def test_prompt_registry_verify_synchronization_missing_system_directive_raises(
    tmp_path: Path,
) -> None:
    """Verify PromptSyncError is raised if modular_prompt.md is missing master directive."""
    registry = PromptRegistry()
    bad_file = tmp_path / "bad_modular_prompt.md"
    bad_file.write_text("# Corrupted Registry\nMissing system directive.", encoding="utf-8")

    err_match = "missing or has an out-of-sync master system directive"
    with pytest.raises(PromptSyncError, match=err_match):
        registry.verify_registry_synchronization(modular_prompt_path=bad_file)


def test_prompt_registry_verify_synchronization_missing_module_index_raises(
    tmp_path: Path,
) -> None:
    """Verify PromptSyncError is raised if a canonical module index is missing."""
    registry = PromptRegistry()
    bad_file = tmp_path / "bad_index.md"
    # Includes system directive but lacks module index
    content = f"# Test\n{SYSTEM_DIRECTIVE_ENFORCEMENT.strip()}\n"
    bad_file.write_text(content, encoding="utf-8")

    with pytest.raises(PromptSyncError, match="missing canonical index entry for module"):
        registry.verify_registry_synchronization(modular_prompt_path=bad_file)


def test_prompt_registry_verify_synchronization_tampered_module_content_raises(
    tmp_path: Path,
) -> None:
    """Verify PromptSyncError is raised if module content in modular_prompt.md was tampered."""
    registry = PromptRegistry()
    # Start with valid content
    valid_content = registry.generate_registry_markdown()
    # Tamper with identity module content in the generated markdown
    tampered_content = valid_content.replace(
        "Evaluate cloud identity telemetry",
        "TAMPERED_INLINE_PROMPT",
    )
    bad_file = tmp_path / "tampered.md"
    bad_file.write_text(tampered_content, encoding="utf-8")

    with pytest.raises(PromptSyncError, match="does not match runtime prompt module file"):
        registry.verify_registry_synchronization(modular_prompt_path=bad_file)


def test_prompt_registry_sync_to_modular_prompt_md(tmp_path: Path) -> None:
    """Verify sync_to_modular_prompt_md writes valid, synchronizable markdown to disk."""
    registry = PromptRegistry()
    out_file = tmp_path / "generated_modular_prompt.md"

    content = registry.sync_to_modular_prompt_md(output_path=out_file)
    assert out_file.is_file()
    assert out_file.read_text(encoding="utf-8") == content

    # Verify newly synced file passes full synchronization verification
    assert registry.verify_registry_synchronization(modular_prompt_path=out_file) is True


def test_prompt_registry_path_traversal_defense(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify PromptRegistry path traversal defense rejecting paths escaping prompts_dir."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret.md"
    secret_file.write_text("# Secret", encoding="utf-8")

    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    registry = PromptRegistry(prompts_dir=prompts_dir)

    # Monkeypatch identity module path to escape prompts_dir via directory traversal
    traversal_meta = dict(CANONICAL_PROMPT_MODULES["identity"])
    traversal_meta["file_path"] = "../outside/secret.md"
    monkeypatch.setitem(CANONICAL_PROMPT_MODULES, "identity", traversal_meta)

    with pytest.raises(PromptPathTraversalError, match="Path traversal detected"):
        registry.get_module("identity")
