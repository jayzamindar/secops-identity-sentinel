"""
OpenAPI 3.0 Strict Schema Sanitizer for Google Gemini.

Transforms Pydantic v2 JSON schemas into Protobuf-compliant OpenAPI 3.0 schemas
by inlining definitions, collapsing anyOf nullables, filtering unsupported fields
via ALLOWED_GEMINI_FIELDS, and excluding deterministic execution payloads adhering
to GEMINI.md Section 3.9.
"""

from __future__ import annotations

import copy
from typing import Any

# Strict allowlist of OpenAPI 3.0 schema fields accepted by Google Gemini Protobuf C++ parser
ALLOWED_GEMINI_FIELDS: frozenset[str] = frozenset(
    {
        "type",
        "description",
        "nullable",
        "enum",
        "properties",
        "items",
        "required",
        "title",
    }
)

EXCLUDED_PAYLOAD_FIELDS: frozenset[str] = frozenset(
    {
        "execution_payload",
        "plan_signature",
        "plan_digest",
    }
)


def _inline_defs(schema: dict[str, Any], defs: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively dereference and inline $ref pointers from $defs or definitions.

    Supports arbitrarily deep nested references (A -> B -> C).
    """
    if not isinstance(schema, dict):
        return schema

    # If this node is a $ref, resolve it
    if "$ref" in schema:
        ref_path = schema["$ref"]
        ref_name = ref_path.split("/")[-1]
        if ref_name in defs:
            resolved = copy.deepcopy(defs[ref_name])
            if isinstance(resolved, dict):
                for k, v in schema.items():
                    if k != "$ref":
                        resolved[k] = v
            # Recursively resolve any further $refs in the inlined definition
            return _inline_defs(resolved, defs)
        return schema

    result: dict[str, Any] = {}
    for key, value in schema.items():
        if isinstance(value, dict):
            result[key] = _inline_defs(value, defs)
        elif isinstance(value, list):
            result[key] = [
                _inline_defs(item, defs) if isinstance(item, dict) else item for item in value
            ]
        else:
            result[key] = value
    return result


def _collapse_any_of(node: dict[str, Any]) -> dict[str, Any]:
    """
    Collapse Pydantic v2 `{'anyOf': [{'type': 'T'}, {'type': 'null'}]}` structures
    into OpenAPI 3.0 compliant `{'type': 'T', 'nullable': True}`.

    Also handles `oneOf` nullables identically.
    """
    for union_key in ("anyOf", "oneOf"):
        if union_key in node:
            branches = node[union_key]
            if isinstance(branches, list):
                non_null_types: list[dict[str, Any]] = [
                    branch
                    for branch in branches
                    if isinstance(branch, dict) and branch.get("type") != "null"
                ]
                has_null = any(
                    isinstance(branch, dict) and branch.get("type") == "null" for branch in branches
                )

                if len(non_null_types) == 1:
                    target = copy.deepcopy(non_null_types[0])
                    if has_null:
                        target["nullable"] = True
                    for peer_key in ("description", "title"):
                        if peer_key in node and peer_key not in target:
                            target[peer_key] = node[peer_key]
                    return target
    return node


def clean_gemini_schema(
    raw_schema: dict[str, Any],
    strip_execution_payload: bool = True,
) -> dict[str, Any]:
    """
    Sanitize a Pydantic JSON schema for Google Gemini responseSchema compliance.

    Transformations:
    1. Dereferences and inlines all $defs and $ref pointers.
    2. Collapses `anyOf` / `oneOf` nullables into `{'type': '...', 'nullable': True}`.
    3. Strips all unsupported fields not in ALLOWED_GEMINI_FIELDS.
    4. Excludes `execution_payload` from action models when strip_execution_payload is True.
    5. Re-injects `{'type': 'object'}` for variable mapping dictionary fields (dict[str, Any]).
    6. Prunes empty `properties: {}` or `required: []` structures for Protobuf compliance.
    """
    if not isinstance(raw_schema, dict):
        return {}

    cloned = copy.deepcopy(raw_schema)

    # Extract all definitions across Pydantic v1 / v2 and standard JSON schema keys
    defs: dict[str, Any] = {}
    if "$defs" in cloned and isinstance(cloned["$defs"], dict):
        defs.update(cloned.pop("$defs"))
    if "definitions" in cloned and isinstance(cloned["definitions"], dict):
        defs.update(cloned.pop("definitions"))

    inlined = _inline_defs(cloned, defs)

    def _sanitize_node(node: Any, is_properties_map: bool = False) -> Any:
        if isinstance(node, list):
            return [_sanitize_node(item) for item in node]
        if not isinstance(node, dict):
            return node

        # If this dictionary represents the map of properties {prop_name: prop_schema}:
        if is_properties_map:
            cleaned_props: dict[str, Any] = {}
            for prop_name, prop_schema in node.items():
                if strip_execution_payload and prop_name in EXCLUDED_PAYLOAD_FIELDS:
                    continue
                cleaned_props[prop_name] = _sanitize_node(prop_schema)
            return cleaned_props

        # Step 2a: Collapse anyOf / oneOf nullables
        node = _collapse_any_of(node)

        # Step 2b: Strip execution_payload from required
        if strip_execution_payload and "required" in node and isinstance(node["required"], list):
            node["required"] = [f for f in node["required"] if f not in EXCLUDED_PAYLOAD_FIELDS]

        cleaned_node: dict[str, Any] = {}
        for key, value in node.items():
            if key in ALLOWED_GEMINI_FIELDS:
                if key == "properties" and isinstance(value, dict):
                    cleaned_props_map = _sanitize_node(value, is_properties_map=True)
                    # Only keep non-empty properties map to satisfy Gemini Protobuf C++ parser
                    if cleaned_props_map:
                        cleaned_node["properties"] = cleaned_props_map
                else:
                    cleaned_node[key] = _sanitize_node(value)

        # Step 2c: If required became empty, remove it
        if (
            "required" in cleaned_node
            and isinstance(cleaned_node["required"], list)
            and not cleaned_node["required"]
        ):
            del cleaned_node["required"]

        # Step 2d: Re-inject explicit type token if missing (e.g. for dynamic dict[str, Any])
        if "type" not in cleaned_node:
            if "enum" in cleaned_node and isinstance(cleaned_node["enum"], list):
                if cleaned_node["enum"] and all(isinstance(x, str) for x in cleaned_node["enum"]):
                    cleaned_node["type"] = "string"
                elif cleaned_node["enum"] and all(isinstance(x, int) for x in cleaned_node["enum"]):
                    cleaned_node["type"] = "integer"
            elif "properties" in cleaned_node or "items" not in cleaned_node:
                cleaned_node["type"] = "object"

        return cleaned_node

    sanitized = _sanitize_node(inlined)
    if not isinstance(sanitized, dict):
        return {}
    if "type" not in sanitized:
        sanitized["type"] = "object"
    return sanitized


__all__: list[str] = [
    "ALLOWED_GEMINI_FIELDS",
    "EXCLUDED_PAYLOAD_FIELDS",
    "clean_gemini_schema",
]
