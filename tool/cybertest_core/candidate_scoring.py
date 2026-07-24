"""Pure candidate priority and evidence-confidence helpers."""

from __future__ import annotations

from typing import Any

from .signal_extraction import status_value


BASE_SCORES = {
    "SQLi": 75,
    "SSRF": 72,
    "IDOR/BOLA": 78,
    "OAuth/OIDC/SAML": 76,
    "API Gateway/Open Platform": 72,
    "File/Upload/Download/Import/Export": 70,
    "OSS/STS/Object Storage": 70,
    "Admin/Management": 68,
    "VHost/Host-SNI": 48,
    "Open Redirect": 42,
    "Directory Brute": 38,
    "JS Attack Surface": 35,
    "Swagger/OpenAPI/Actuator": 30,
    "Test/Pre/Dev/Staging": 46,
    "Mobile API/Deep Link": 45,
    "Core Business API": 52,
}
CONFIDENCE_RANK = {
    "unknown": 0,
    "weak": 1,
    "differential": 2,
    "independently_observed": 3,
    "reproducible": 4,
}
REACHABILITY_RANK = {
    "signal": 0,
    "route": 1,
    "handler": 2,
    "business_logic": 3,
    "object_read": 4,
    "state_change": 5,
    "impact": 6,
}
AUTH_EXPERIMENT_FIELDS = {
    "missing_auth",
    "fixed_invalid_auth",
    "controlled_auth",
}


def base_score(candidate_type: str) -> int:
    return BASE_SCORES.get(candidate_type, 20)


def priority_score(
    candidate_type: str,
    *,
    core_business: bool,
    has_test_environment: bool,
    has_edge_surface: bool,
    source: str,
    auth_proven: bool,
    status: Any,
    health_only: bool,
) -> tuple[int, list[str], list[str]]:
    """Score validation priority without deriving evidence confidence."""

    score = base_score(candidate_type)
    reasons = [f"{candidate_type} base"]
    downgrades: list[str] = []

    if core_business:
        score += 15
        reasons.append("核心业务对象或权限字段")
    if has_test_environment:
        score += 12
        reasons.append("测试/预发/灰度环境关键词")
    if has_edge_surface:
        score += 8
        reasons.append("边缘/后台/API/SSO/文件关键词")
    if source.startswith("gf:"):
        score += 8
        reasons.append(f"GF 命中 {source.split(':', 1)[1]}")
    if source == "nuclei":
        score += 8
        reasons.append("Nuclei 发现来源")
    if source in {"js", "katana", "history"}:
        score += 5
        reasons.append(f"{source} 攻击面来源")
    if auth_proven:
        score += 10
        reasons.append("明确认证矩阵证明未认证可达")

    normalized_status = status_value(status)
    if normalized_status in {"401", "403", "404"}:
        score -= 14
        downgrades.append(f"仅观察到 HTTP {normalized_status}")
    if (
        candidate_type
        in {"Swagger/OpenAPI/Actuator", "JS Attack Surface", "Open Redirect"}
        and not core_business
    ):
        score -= 10
        downgrades.append("当前更像信息项，需组合认证/业务影响")
    if health_only:
        score -= 15
        downgrades.append("无敏感 health/info 候选")

    return max(0, min(100, score)), reasons, downgrades


def evidence_confidence_for_auth(
    experiment: dict[str, Any] | None,
    *,
    signal_present: bool = True,
) -> str:
    """Assess evidence maturity independently from candidate priority."""

    if (
        experiment is not None
        and AUTH_EXPERIMENT_FIELDS.issubset(experiment)
        and all(status_value(experiment.get(field)) for field in AUTH_EXPERIMENT_FIELDS)
    ):
        return "differential"
    return "weak" if signal_present else "unknown"


def stronger_evidence_confidence(left: str, right: str) -> str:
    return (
        right
        if CONFIDENCE_RANK.get(right, -1) > CONFIDENCE_RANK.get(left, -1)
        else left
    )


def later_reachability_stage(left: str, right: str) -> str:
    return (
        right
        if REACHABILITY_RANK.get(right, -1) > REACHABILITY_RANK.get(left, -1)
        else left
    )


def queue_for(score: int) -> str:
    if score >= 75:
        return "P0"
    if score >= 58:
        return "P1"
    if score >= 38:
        return "P2"
    return "P3"
