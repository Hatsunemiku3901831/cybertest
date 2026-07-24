"""Deterministic URL and candidate-instance normalization helpers."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlparse


DOMAIN_RE = re.compile(
    r"\b[a-z0-9][a-z0-9.-]+\.(?:com|cn|net|org|io|co|top|app|dev|cloud)\b",
    re.I,
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
RANDOM_SEGMENT_RE = re.compile(
    r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._~-]{12,}$"
)
DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_value(value: str) -> str:
    return value.strip().rstrip(".,;")


def normalize_host(host: str) -> str:
    """Normalize a DNS host or IP literal without inventing a scheme."""

    normalized = host.strip().strip("[]").rstrip(".").lower()
    return f"[{normalized}]" if ":" in normalized else normalized


def asset_for(value: str) -> str:
    """Return the legacy display asset used by candidate v1 output."""

    if "://" in value:
        parsed = urlparse(value)
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else value
    domain = DOMAIN_RE.search(value)
    return domain.group(0) if domain else ""


def path_for(value: str) -> str:
    if "://" in value:
        parsed = urlparse(value)
        path = parsed.path or "/"
        return path + (f"?{parsed.query}" if parsed.query else "")
    return value


def tokens(value: str) -> set[str]:
    return {token.lower() for token in re.split(r"[^A-Za-z0-9]+", value) if token}


def query_params(value: str) -> set[str]:
    if "?" not in value:
        return set()
    query = urlparse(value).query if "://" in value else value.split("?", 1)[1]
    return {
        key.strip().lower()
        for key, _ in parse_qsl(query, keep_blank_values=True)
        if key.strip()
    }


def normalized_asset_for(value: str) -> str:
    """Return a stable scheme/host/port origin for candidate identity."""

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.hostname:
        return asset_for(value).lower()

    scheme = parsed.scheme.lower()
    host = normalize_host(parsed.hostname)
    try:
        port = parsed.port
    except ValueError:
        return asset_for(value).lower()
    if port and port != DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _is_variable_segment(segment: str) -> str | None:
    decoded = unquote(segment)
    if decoded.isdigit() or UUID_RE.fullmatch(decoded):
        return "{id}"
    if RANDOM_SEGMENT_RE.fullmatch(decoded) or len(decoded) >= 32:
        return "{value}"
    return None


def normalize_route_template(value: str) -> str:
    """Normalize transient path IDs and retain sorted query parameter names."""

    parsed = urlparse(value)
    path = parsed.path or "/"
    segments = [
        _is_variable_segment(segment) or segment
        for segment in path.split("/")
        if segment
    ]
    normalized_path = "/" + "/".join(segments)
    query_names = sorted(query_params(value))
    if query_names:
        normalized_path += "?" + "&".join(query_names)
    return normalized_path


def stable_instance_key(
    value: str,
    method: str,
    business_object: str,
    operation_type: str,
    root_cause_family: str,
) -> str:
    """Build an identity that excludes query values, tokens and transient IDs."""

    return "|".join(
        (
            normalized_asset_for(value),
            method.strip().upper() or "GET",
            normalize_route_template(value),
            business_object,
            operation_type,
            root_cause_family,
        )
    )
