"""
Identity Catalog Management & Break-Glass Identity Protection.

Handles loading and schema validation of authoritative identity catalog data,
raising CatalogNotFoundError if missing or invalid, and implements the
dual-check break-glass protection algorithm (tags + catalog) adhering to
GEMINI.md Section 3.5, Section 3.8, and TRD.md Section 2.4.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CatalogNotFoundError(FileNotFoundError):
    """
    Raised when config/identity_catalog.json is missing, unreadable, corrupted,
    or fails schema validation adhering to GEMINI.md Section 3.5.
    """


class IdentityCatalogPrincipal(BaseModel):
    """
    Authoritative catalog metadata for a known enterprise principal.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str = Field(..., min_length=1, max_length=256)
    role: str = Field(default="", max_length=128)
    tier: str = Field(default="", max_length=128)
    department: str = Field(default="", max_length=128)
    is_break_glass: bool = Field(default=False)


class IdentityCatalog(BaseModel):
    """
    Root contract for config/identity_catalog.json.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(default="1.0.0")
    principals: dict[str, IdentityCatalogPrincipal] = Field(default_factory=dict)


def get_default_catalog_path() -> Path:
    """
    Return default absolute path to config/identity_catalog.json.
    """
    return Path("config/identity_catalog.json").resolve()


def load_identity_catalog(
    catalog_path: str | Path | None = None,
) -> IdentityCatalog:
    """
    Load and validate the authoritative identity catalog from disk.

    Args:
        catalog_path: Path to identity_catalog.json (defaults to config/identity_catalog.json).

    Returns:
        IdentityCatalog: Validated Pydantic v2 catalog.

    Raises:
        CatalogNotFoundError: If file does not exist, is unreadable, is corrupt JSON,
            or fails Pydantic schema validation.
    """
    target = (
        Path(catalog_path).resolve() if catalog_path is not None else get_default_catalog_path()
    )

    if not target.exists() or not target.is_file():
        raise CatalogNotFoundError(
            f"Authoritative identity catalog not found at '{target}'. "
            "Adhering to GEMINI.md Section 3.5, execution must route to Tertiary Heuristics."
        )

    try:
        raw_text = target.read_text(encoding="utf-8")
        raw_json = json.loads(raw_text)
    except Exception as exc:
        raise CatalogNotFoundError(
            f"Failed to read or decode identity catalog at '{target}': {exc}"
        ) from exc

    if not isinstance(raw_json, dict):
        raise CatalogNotFoundError(
            f"Invalid identity catalog structure at '{target}': "
            f"expected JSON object, got {type(raw_json).__name__}."
        )

    try:
        return IdentityCatalog.model_validate(raw_json)
    except Exception as exc:
        raise CatalogNotFoundError(
            f"Identity catalog validation failed against schema at '{target}': {exc}"
        ) from exc


def _lookup_catalog_entry(
    norm_principal: str,
    catalog: IdentityCatalog | dict[str, Any],
) -> tuple[bool, str, str] | None:
    """
    Search catalog for principal metadata matching exact ID, case-insensitively,
    or via ARN resource short-names.
    """
    candidates = [norm_principal]
    if "/" in norm_principal:
        candidates.append(norm_principal.split("/")[-1])
    if ":" in norm_principal:
        candidates.append(norm_principal.split(":")[-1])

    if isinstance(catalog, IdentityCatalog):
        for cand in candidates:
            if cand in catalog.principals:
                p = catalog.principals[cand]
                return p.is_break_glass, p.role, p.tier
            for k, p in catalog.principals.items():
                if k.lower() == cand.lower():
                    return p.is_break_glass, p.role, p.tier
    elif isinstance(catalog, dict):
        principals_dict = catalog.get("principals", {})
        if isinstance(principals_dict, dict):
            for cand in candidates:
                if cand in principals_dict:
                    entry = principals_dict[cand]
                    if isinstance(entry, dict):
                        return (
                            bool(entry.get("is_break_glass", False)),
                            str(entry.get("role", "")),
                            str(entry.get("tier", "")),
                        )
                for k, entry in principals_dict.items():
                    if str(k).lower() == cand.lower() and isinstance(entry, dict):
                        return (
                            bool(entry.get("is_break_glass", False)),
                            str(entry.get("role", "")),
                            str(entry.get("tier", "")),
                        )
    return None


def is_protected_break_glass(
    principal_id: str,
    tags: dict[str, str] | None = None,
    catalog: IdentityCatalog | dict[str, Any] | None = None,
) -> bool:
    """
    Determine if a principal is protected under break-glass immunity.

    Dual-Check Pipeline (TRD.md Section 2.4 & GEMINI.md Section 3.8):
      1. Inbound tags: case-insensitive, whitespace-trimmed, exact string match:
         - role == 'break-glass-admin'
         - tier == 'control-plane-root'
      2. Authoritative Catalog lookup: cross-references canonical principal against
         catalog to defeat tag-stripping evasion.

    Returns:
        bool: True if identity is protected under break-glass rules.
    """
    norm_principal = principal_id.strip()

    # Check 1: Inbound telemetry tags
    if tags:
        for k, v in tags.items():
            k_norm = str(k).strip().lower()
            v_norm = str(v).strip().lower()
            if k_norm == "role" and v_norm == "break-glass-admin":
                return True
            if k_norm == "tier" and v_norm == "control-plane-root":
                return True
            if k_norm == "is_break_glass" and v_norm in ("true", "1", "yes"):
                return True

    # Check 2: Authoritative Catalog Lookup (resolve default catalog if None)
    if catalog is None:
        default_path = get_default_catalog_path()
        if default_path.is_file():
            try:
                catalog = load_identity_catalog(default_path)
            except Exception:
                catalog = None

    if catalog is not None:
        entry = _lookup_catalog_entry(norm_principal, catalog)
        if entry is not None:
            is_bg, role, tier = entry
            if is_bg:
                return True
            if role.strip().lower() == "break-glass-admin":
                return True
            if tier.strip().lower() in ("control-plane-root", "break-glass"):
                return True

    return False


__all__: list[str] = [
    "CatalogNotFoundError",
    "IdentityCatalogPrincipal",
    "IdentityCatalog",
    "get_default_catalog_path",
    "load_identity_catalog",
    "is_protected_break_glass",
]
