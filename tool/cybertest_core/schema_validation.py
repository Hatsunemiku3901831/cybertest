"""Small, dependency-free validator for Cybertest's repository schemas.

The project schemas deliberately use a conservative JSON Schema subset so
repository checks do not depend on third-party packages.  This module is not a
general replacement for a standards-complete JSON Schema implementation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when a document does not satisfy a repository schema."""


def load_json_document(path: str | Path) -> Any:
    """Load JSON, including JSON-compatible YAML 1.2 files."""

    document_path = Path(path)
    try:
        return json.loads(document_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaValidationError(
            f"cannot load JSON-compatible document {document_path}: {exc}"
        ) from exc


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _type_label(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


def validate_instance(instance: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Return deterministic validation errors for the supported schema subset."""

    errors: list[str] = []

    expected_type = schema.get("type")
    if expected_type is not None:
        expected_types = [expected_type] if isinstance(expected_type, str) else list(expected_type)
        if not any(_matches_type(instance, item) for item in expected_types):
            errors.append(
                f"{path}: expected type {'|'.join(expected_types)}, got {_type_label(instance)}"
            )
            return errors

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: value must equal {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value {instance!r} is not in the allowed enum")

    for branch in schema.get("allOf", []):
        errors.extend(validate_instance(instance, branch, path))

    if schema.get("anyOf"):
        branch_errors = [validate_instance(instance, branch, path) for branch in schema["anyOf"]]
        if all(branch_errors):
            errors.append(f"{path}: value does not satisfy anyOf")

    if schema.get("oneOf"):
        passing = sum(
            not validate_instance(instance, branch, path) for branch in schema["oneOf"]
        )
        if passing != 1:
            errors.append(f"{path}: value must satisfy exactly one oneOf branch")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")

        properties = schema.get("properties", {})
        for key, value in instance.items():
            child_path = f"{path}.{key}"
            if key in properties:
                errors.extend(validate_instance(value, properties[key], child_path))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{child_path}: additional property is not allowed")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors.extend(
                    validate_instance(value, schema["additionalProperties"], child_path)
                )

        minimum = schema.get("minProperties")
        if minimum is not None and len(instance) < minimum:
            errors.append(f"{path}: expected at least {minimum} properties")

    if isinstance(instance, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if minimum is not None and len(instance) < minimum:
            errors.append(f"{path}: expected at least {minimum} items")
        if maximum is not None and len(instance) > maximum:
            errors.append(f"{path}: expected at most {maximum} items")
        if schema.get("uniqueItems"):
            serialized = [json.dumps(item, ensure_ascii=False, sort_keys=True) for item in instance]
            if len(serialized) != len(set(serialized)):
                errors.append(f"{path}: array items must be unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, value in enumerate(instance):
                errors.extend(validate_instance(value, item_schema, f"{path}[{index}]"))

    if isinstance(instance, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if minimum is not None and len(instance) < minimum:
            errors.append(f"{path}: expected string length >= {minimum}")
        if maximum is not None and len(instance) > maximum:
            errors.append(f"{path}: expected string length <= {maximum}")
        pattern = schema.get("pattern")
        if pattern and re.search(pattern, instance) is None:
            errors.append(f"{path}: string does not match pattern {pattern!r}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and instance < minimum:
            errors.append(f"{path}: expected value >= {minimum}")
        if maximum is not None and instance > maximum:
            errors.append(f"{path}: expected value <= {maximum}")

    return errors


def assert_valid(instance: Any, schema: dict[str, Any], label: str = "document") -> None:
    """Raise :class:`SchemaValidationError` if validation fails."""

    errors = validate_instance(instance, schema)
    if errors:
        rendered = "\n".join(f"- {item}" for item in errors)
        raise SchemaValidationError(f"{label} failed schema validation:\n{rendered}")
