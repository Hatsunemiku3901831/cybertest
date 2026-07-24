"""Pure helpers that turn raw records into candidate semantics."""

from __future__ import annotations

import re
from typing import Any


def status_value(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("status_code") or value.get("status") or value.get("code")
    return str(value or "").strip()


def is_success_status(value: Any) -> bool:
    return re.match(r"^[23]\d\d(?:\D|$)", status_value(value)) is not None


def is_denied_status(value: Any) -> bool:
    return status_value(value) in {"401", "403"}


def extract_auth_experiment(record: dict[str, Any]) -> dict[str, Any] | None:
    experiment = record.get("auth_experiment")
    if not isinstance(experiment, dict):
        return None
    normalized: dict[str, str | None] = {}
    for field in (
        "missing_auth",
        "fixed_invalid_auth",
        "controlled_auth",
    ):
        if field not in experiment:
            continue
        value = experiment[field]
        normalized[field] = None if value is None else str(value).strip() or None
    return normalized or None


def observed_without_auth(experiment: dict[str, Any] | None) -> bool | None:
    if experiment is None:
        return None
    required = (
        "missing_auth",
        "fixed_invalid_auth",
        "controlled_auth",
    )
    if any(not status_value(experiment.get(field)) for field in required):
        return None
    return bool(
        is_success_status(experiment.get("missing_auth"))
        and is_denied_status(experiment.get("fixed_invalid_auth"))
        and is_success_status(experiment.get("controlled_auth"))
    )


def http_method_for(record: dict[str, Any]) -> str:
    return str(
        record.get("method")
        or record.get("http_method")
        or record.get("request_method")
        or "GET"
    ).upper()


def infer_business_object(
    words: set[str],
    params: set[str],
    candidate_type: str,
) -> str:
    values = words | params
    mappings = (
        ({"member"}, "member"),
        (
            {
                "user",
                "userid",
                "uid",
                "account",
                "accountid",
                "employee",
                "empid",
                "staff",
            },
            "user",
        ),
        (
            {
                "org",
                "orgid",
                "dept",
                "deptid",
                "corp",
                "corpid",
                "tenant",
                "tenantid",
            },
            "organization",
        ),
        (
            {"order", "orderid", "waybill", "waybillno", "bill", "billcode"},
            "order",
        ),
        (
            {"file", "fileid", "attachment", "attachmentid", "objectkey", "bucket"},
            "file",
        ),
        (
            {"payment", "pay", "refund", "withdraw", "invoice", "wallet", "balance"},
            "payment",
        ),
        ({"role", "permission", "admin", "manager"}, "authorization"),
    )
    for indicators, name in mappings:
        if values & indicators:
            return name
    if candidate_type == "SSRF":
        return "remote_resource"
    if candidate_type == "SQLi":
        return "query"
    return "endpoint"


def infer_business_capability(candidate_type: str) -> str:
    return {
        "SQLi": "query_execution",
        "SSRF": "remote_fetch",
        "IDOR/BOLA": "object_access",
        "OAuth/OIDC/SAML": "identity_authorization",
        "API Gateway/Open Platform": "api_access",
        "File/Upload/Download/Import/Export": "file_processing",
        "OSS/STS/Object Storage": "object_storage",
        "Admin/Management": "administration",
        "VHost/Host-SNI": "virtual_host_routing",
        "Open Redirect": "redirect",
        "Directory Brute": "route_discovery",
        "JS Attack Surface": "client_api_discovery",
    }.get(candidate_type, "endpoint_access")


def infer_operation_type(words: set[str], method: str) -> str:
    for indicators, operation in (
        ({"delete", "remove"}, "delete"),
        ({"approve", "audit"}, "approve"),
        ({"upload"}, "upload"),
        ({"import"}, "import"),
        ({"export"}, "export"),
        ({"download"}, "download"),
        ({"preview"}, "preview"),
        ({"update", "bind", "unbind", "reset", "create", "add"}, "write"),
    ):
        if words & indicators:
            return operation
    if method == "DELETE":
        return "delete"
    if method in {"POST", "PUT", "PATCH"}:
        return "write"
    return "read"


def trust_boundary_for(candidate_type: str) -> str:
    return {
        "IDOR/BOLA": "user_to_user",
        "Admin/Management": "user_to_admin",
        "VHost/Host-SNI": "public_to_internal",
        "API Gateway/Open Platform": "client_to_platform",
        "OAuth/OIDC/SAML": "user_to_identity_provider",
        "OSS/STS/Object Storage": "user_to_storage",
    }.get(candidate_type, "public_to_application")


def root_cause_for(candidate_type: str) -> str:
    return {
        "SQLi": "input_to_query_interpretation",
        "SSRF": "server_side_url_trust",
        "IDOR/BOLA": "object_authorization",
        "OAuth/OIDC/SAML": "identity_binding",
        "API Gateway/Open Platform": "api_trust_binding",
        "File/Upload/Download/Import/Export": "file_boundary_control",
        "OSS/STS/Object Storage": "storage_authorization",
        "Admin/Management": "function_authorization",
        "VHost/Host-SNI": "host_routing_trust",
        "Open Redirect": "redirect_target_validation",
        "Directory Brute": "route_exposure",
        "JS Attack Surface": "client_side_metadata_exposure",
        "Swagger/OpenAPI/Actuator": "diagnostic_surface_exposure",
        "Test/Pre/Dev/Staging": "nonproduction_surface_exposure",
        "Mobile API/Deep Link": "mobile_api_trust",
        "Core Business API": "business_authorization",
    }.get(candidate_type, "unclassified_control_gap")
