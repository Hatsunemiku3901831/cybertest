#!/usr/bin/env python3
"""Generate a bug-bounty-oriented candidate queue from existing Cybertest outputs.

This tool is offline only: it reads scan/task artifacts and emits structured
P0/P1/P2/P3 candidates. It does not send network requests.
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .cybertest_core.candidate_scoring import (
        base_score,
        evidence_confidence_for_auth,
        later_reachability_stage,
        priority_score,
        queue_for,
        stronger_evidence_confidence,
    )
    from .cybertest_core.models import Candidate, RawSignal
    from .cybertest_core.signal_extraction import (
        extract_auth_experiment,
        http_method_for,
        infer_business_capability,
        infer_business_object,
        infer_operation_type,
        is_denied_status,
        is_success_status,
        observed_without_auth,
        root_cause_for,
        status_value,
        trust_boundary_for,
    )
    from .cybertest_core.url_normalization import (
        asset_for,
        normalize_route_template,
        normalize_value,
        normalized_asset_for,
        path_for,
        query_params,
        stable_instance_key,
        tokens,
    )
except ImportError:
    from cybertest_core.candidate_scoring import (
        base_score,
        evidence_confidence_for_auth,
        later_reachability_stage,
        priority_score,
        queue_for,
        stronger_evidence_confidence,
    )
    from cybertest_core.models import Candidate, RawSignal
    from cybertest_core.signal_extraction import (
        extract_auth_experiment,
        http_method_for,
        infer_business_capability,
        infer_business_object,
        infer_operation_type,
        is_denied_status,
        is_success_status,
        observed_without_auth,
        root_cause_for,
        status_value,
        trust_boundary_for,
    )
    from cybertest_core.url_normalization import (
        asset_for,
        normalize_route_template,
        normalize_value,
        normalized_asset_for,
        path_for,
        query_params,
        stable_instance_key,
        tokens,
    )

# Core helpers remain imported at module scope to preserve the existing
# bounty_candidate_queue function and model API while the CLI implementation
# moves to reusable modules.

URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.I)
PATH_RE = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?")
DOMAIN_RE = re.compile(r"\b[a-z0-9][a-z0-9.-]+\.(?:com|cn|net|org|io|co|top|app|dev|cloud)\b", re.I)

CORE_WORDS = {
    "user", "account", "member", "employee", "staff", "emp", "org", "dept", "corp",
    "tenant", "shop", "site", "network", "order", "waybill", "billcode", "bill",
    "payment", "pay", "refund", "withdraw", "invoice", "wallet", "balance",
    "role", "permission", "admin", "manager", "audit", "approve", "token",
}
TEST_ENV_WORDS = {"test", "pre", "dev", "staging", "uat", "beta", "gray", "sandbox", "demo"}
EDGE_WORDS = {
    "admin", "manager", "console", "internal", "gateway", "api", "open", "sso",
    "auth", "usercenter", "file", "dfs", "oss",
}
IDOR_PARAMS = {
    "userid", "uid", "accountid", "empid", "staffid", "orgid", "deptid", "corpid",
    "shopid", "siteid", "networkid", "orderid", "waybillno", "billcode", "fileid",
    "attachmentid", "parentid", "tenantid", "appid", "projectid", "documentid",
}
IDOR_ACTIONS = {
    "detail", "list", "export", "download", "preview", "update", "delete", "bind",
    "unbind", "reset", "approve", "audit", "import", "upload",
}
SSRF_PARAMS = {
    "url", "uri", "callback", "webhook", "redirect", "next", "target", "image",
    "avatar", "file", "import", "fetch", "render", "pdf", "preview", "notify",
    "link", "src", "source", "remote",
}
REDIRECT_PARAMS = {"redirect", "redirect_uri", "returnurl", "return_url", "next", "url", "target", "callback"}
SQLI_PARAMS = {
    "id", "q", "query", "keyword", "search", "sort", "order", "filter", "where",
    "name", "type", "category", "page", "size", "limit", "offset", "date",
}
FILE_WORDS = {
    "upload", "download", "import", "export", "preview", "convert", "attachment",
    "file", "files", "objectkey", "filekey", "fileurl", "bucket", "oss", "sts",
    "dfs", "sign", "policy",
}
DOC_WORDS = {"swagger", "openapi", "api-docs", "v3/api-docs", "actuator", "health", "config", "env"}
CATEGORY_BY_CANDIDATE_TYPE = {
    "SQLi": "injection",
    "SSRF": "ssrf",
    "IDOR/BOLA": "authorization",
    "Admin/Management": "authorization",
    "File/Upload/Download/Import/Export": "file",
    "OAuth/OIDC/SAML": "authentication",
    "API Gateway/Open Platform": "authentication",
    "OSS/STS/Object Storage": "authorization",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def iter_json_paths(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("*.json") if p.is_file() and "__pycache__" not in p.parts)


def is_generated_pipeline_output(path: Path, pipeline_root: Path) -> bool:
    """Exclude prior candidate/gate artifacts when a pipeline phase is retried."""

    try:
        relative = path.resolve().relative_to(pipeline_root.resolve())
    except ValueError:
        return False
    if relative.name in {"pipeline_state.json", "summary.json"} and len(relative.parts) == 1:
        return True
    phase_dir = relative.parts[0] if relative.parts else ""
    return (
        phase_dir.startswith("phase_")
        and (
            phase_dir.endswith("_candidate_queue")
            or phase_dir == "phase_candidate_queue"
            or phase_dir.endswith("_quality_gate")
            or phase_dir == "phase_quality_gate"
        )
    )


def load_text(path: Path, limit: int = 500_000) -> str:
    try:
        return path.read_bytes()[:limit].decode("utf-8", errors="replace")
    except OSError:
        return ""


def source_name(path: Path) -> str:
    text = " ".join(path.parts).lower()
    stem = path.stem.lower()
    suffix = path.suffix.lower()
    if suffix == ".js" or stem.endswith("-js-intel") or "js-intel" in text or "chunk" in stem:
        return "js"
    for name in ("gf", "nuclei", "katana", "history", "httpx", "ffuf", "dnsx", "tlsx", "nmap", "js", "asset"):
        if name in text:
            return name
    return path.stem


def collect_signals(paths: list[Path]) -> list[RawSignal]:
    signals: list[RawSignal] = []
    for path in paths:
        src = source_name(path)
        if path.suffix.lower() == ".json":
            data = read_json(path)
            collect_from_json(data, src, str(path), signals)
        elif path.suffix.lower() in {".txt", ".md", ".js", ".map"}:
            collect_from_text(load_text(path), src if path.suffix.lower() != ".js" else "js", str(path), signals)
    return signals


def collect_from_json(data: Any, source: str, source_file: str, signals: list[RawSignal], parent: dict[str, Any] | None = None) -> None:
    if isinstance(data, dict):
        if source == "gf" and isinstance(data.get("patterns"), list):
            for pat in data["patterns"]:
                if not isinstance(pat, dict):
                    continue
                pattern = str(pat.get("name") or pat.get("pattern") or "")
                for url in pat.get("matched_urls", []) if isinstance(pat.get("matched_urls"), list) else []:
                    if isinstance(url, str):
                        signals.append(RawSignal(url, f"gf:{pattern}", source_file, {"gf_pattern": pattern}))
        record = data
        for key, value in data.items():
            if isinstance(value, str):
                collect_from_text(value, source, source_file, signals, {**record, "_json_key": key})
            elif isinstance(value, (dict, list)):
                collect_from_json(value, source, source_file, signals, record)
    elif isinstance(data, list):
        for item in data:
            collect_from_json(item, source, source_file, signals, parent)
    elif isinstance(data, str):
        collect_from_text(data, source, source_file, signals, parent or {})


def collect_from_text(text: str, source: str, source_file: str, signals: list[RawSignal], record: dict[str, Any] | None = None) -> None:
    record = record or {}
    seen: set[str] = set()
    for regex in (URL_RE, PATH_RE, DOMAIN_RE):
        for match in regex.finditer(text):
            value = match.group(0).strip().rstrip(".,;")
            if len(value) < 4 or value in seen:
                continue
            if regex is PATH_RE and not interesting_path(value):
                continue
            seen.add(value)
            signals.append(RawSignal(value, source, source_file, record))


def interesting_path(value: str) -> bool:
    lower = value.lower()
    if lower.startswith(("//", "/*", "/>")):
        return False
    if len(value) > 220 or value.count("/") > 12:
        return False
    hints = CORE_WORDS | TEST_ENV_WORDS | EDGE_WORDS | IDOR_ACTIONS | SSRF_PARAMS | FILE_WORDS | DOC_WORDS | {"oauth", "oidc", "saml", "login", "callback"}
    return any(h in lower for h in hints) or "?" in value


def infer_types(signal: RawSignal) -> list[str]:
    value = normalize_value(signal.value)
    lower = value.lower()
    words = tokens(value)
    params = query_params(value)
    gf_pattern = str(signal.record.get("gf_pattern", "")).lower()
    types: list[str] = []

    if gf_pattern == "sqli" or params & SQLI_PARAMS:
        types.append("SQLi")
    if gf_pattern == "ssrf" or params & SSRF_PARAMS or words & {"webhook", "fetch", "render", "pdf", "callback"}:
        types.append("SSRF")
    if gf_pattern == "redirect" or params & REDIRECT_PARAMS or "redirect_uri" in lower:
        types.append("Open Redirect")
    if gf_pattern == "idor" or params & IDOR_PARAMS or words & IDOR_PARAMS or words & IDOR_ACTIONS:
        types.append("IDOR/BOLA")
    if words & FILE_WORDS:
        types.append("File/Upload/Download/Import/Export")
    if any(doc in lower for doc in DOC_WORDS):
        types.append("Swagger/OpenAPI/Actuator")
    if words & {"oauth", "oidc", "saml", "sso", "authorize", "token", "client", "clientid", "client_id", "systemcode"} or "redirect_uri" in lower:
        types.append("OAuth/OIDC/SAML")
    if words & {"oss", "sts", "bucket", "objectkey", "accesskey", "securitytoken"}:
        types.append("OSS/STS/Object Storage")
    if words & {"admin", "manager", "console", "root", "backend"}:
        types.append("Admin/Management")
    if words & TEST_ENV_WORDS:
        types.append("Test/Pre/Dev/Staging")
    if words & {"android", "ios", "apk", "ipa", "deeplink", "universal", "scheme", "mobile"}:
        types.append("Mobile API/Deep Link")
    if words & {"gateway", "open", "appkey", "secret", "signature", "nonce", "timestamp", "from", "to"}:
        types.append("API Gateway/Open Platform")
    if signal.source in {"dnsx", "tlsx", "httpx"} and (words & EDGE_WORDS or words & TEST_ENV_WORDS):
        types.append("VHost/Host-SNI")
    if signal.source == "ffuf" or "ffuf" in signal.source_file.lower():
        types.append("Directory Brute")
    source_file_lower = signal.source_file.lower()
    if signal.source == "js" or source_file_lower.endswith(".js") or "js-intel" in source_file_lower:
        types.append("JS Attack Surface")
    if words & CORE_WORDS:
        types.append("Core Business API")

    return list(dict.fromkeys(types))


def negative_controls_for(candidate_type: str) -> list[str]:
    controls = ["missing_auth", "fixed_invalid_auth"]
    if candidate_type == "IDOR/BOLA":
        controls.extend(["self_object", "nonexistent_object"])
    elif candidate_type == "SSRF":
        controls.extend(["non_resolving_url", "browser_prefetch_excluded"])
    return controls


def do_not_overclaim_for(candidate_type: str) -> str:
    return {
        "SQLi": "参数或状态差异不是注入结论；需稳定 oracle 或数据库层证据。",
        "SSRF": "页面报错或浏览器请求不是 SSRF；需服务端独立回连或等价证据。",
        "IDOR/BOLA": "路由可达或空结果不是越权；需跨主体对象差分。",
        "Admin/Management": "后台路径存在不是未授权；需认证和功能授权矩阵。",
        "Swagger/OpenAPI/Actuator": "公开文档或健康页本身不代表敏感信息泄露。",
    }.get(candidate_type, "扫描信号只代表待验证候选，不得直接作为漏洞或评级结论。")


def build_validation_contract(candidate_type: str, operation_type: str) -> dict[str, Any]:
    return {
        "next_action": next_action_for(candidate_type),
        "required_controls": negative_controls_for(candidate_type),
        "evidence_requirement": "single_variable_differential",
        "safe_validation_level": (
            "readonly"
            if operation_type in {"read", "download", "preview", "export"}
            else "test_object"
        ),
    }


def record_string_set(record: dict[str, Any], field: str) -> set[str]:
    value = record.get(field)
    if isinstance(value, str):
        return {value.strip()} if value.strip() else set()
    if not isinstance(value, list):
        return set()
    return {
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    }


def classify_signal(signal: RawSignal, candidate_type: str) -> Candidate:
    value = normalize_value(signal.value)
    words = tokens(value)
    params = query_params(value)
    status = status_value(
        signal.record.get("status_code")
        or signal.record.get("status")
        or signal.record.get("code")
    )
    asset = asset_for(value)
    endpoint = path_for(value)

    core = bool(words & CORE_WORDS or params & IDOR_PARAMS)
    anonymous_hint = is_success_status(status)
    auth_experiment = extract_auth_experiment(signal.record)
    observed_unauth = observed_without_auth(auth_experiment)
    unauth = observed_unauth is True
    candidate_priority, reasons, downgrades = priority_score(
        candidate_type,
        core_business=core,
        has_test_environment=bool(words & TEST_ENV_WORDS),
        has_edge_surface=bool(words & EDGE_WORDS),
        source=signal.source,
        auth_proven=unauth,
        status=status,
        health_only=(
            "health" in words and not (words & {"actuator", "config", "env"})
        ),
    )
    queue = queue_for(candidate_priority)
    method = http_method_for(signal.record)
    business_object = infer_business_object(words, params, candidate_type)
    business_capability = infer_business_capability(candidate_type)
    operation_type = infer_operation_type(words, method)
    trust_boundary = trust_boundary_for(candidate_type)
    root_cause_family = root_cause_for(candidate_type)
    instance_key = stable_instance_key(
        value,
        method,
        business_object,
        operation_type,
        root_cause_family,
    )
    evidence_confidence = evidence_confidence_for_auth(auth_experiment)
    reachability_stage = "route" if status else "signal"
    safe_validation_level = (
        "readonly"
        if operation_type in {"read", "download", "preview", "export"}
        else "test_object"
    )
    category = str(
        signal.record.get("category")
        or CATEGORY_BY_CANDIDATE_TYPE.get(candidate_type, "unknown")
    )
    c = Candidate(
        key=instance_key,
        name=f"{candidate_type} 候选 - {endpoint[:80]}",
        asset=asset,
        url_or_endpoint=endpoint,
        candidate_type=candidate_type,
        score=candidate_priority,
        score_reasons=reasons,
        downgrade_reasons=downgrades,
        anonymous_hint=anonymous_hint,
        observed_without_auth=observed_unauth,
        auth_experiment=auth_experiment,
        unauth_reachable=unauth,
        core_business=core,
        possible_impact=impact_for(candidate_type, core),
        next_action=next_action_for(candidate_type),
        needs_material=needs_material(candidate_type, unauth),
        material_requirements=materials_for(candidate_type),
        status="high_value" if queue == "P0" else ("triaged" if queue in {"P1", "P2"} else "discovered"),
        queue=queue,
        priority_score=candidate_priority,
        evidence_confidence=evidence_confidence,
        reachability_stage=reachability_stage,
        impact_stage="hypothesis",
        business_object=business_object,
        business_capability=business_capability,
        operation_type=operation_type,
        trust_boundary=trust_boundary,
        category=category,
        technologies=record_string_set(signal.record, "technologies"),
        observed_signals=record_string_set(
            signal.record,
            "observed_signals",
        ),
        suspected_control_gaps=record_string_set(
            signal.record,
            "suspected_control_gaps",
        ),
        available_materials=record_string_set(
            signal.record,
            "available_materials",
        ),
        available_capabilities=record_string_set(
            signal.record,
            "available_capabilities",
        ),
        safe_validation_level=safe_validation_level,
        validation_contract=build_validation_contract(candidate_type, operation_type),
        negative_controls=negative_controls_for(candidate_type),
        evidence_invariants=[
            "single_variable_control",
            "immutable_evidence_reference",
        ],
        stop_conditions=[
            "first_reproducible_business_impact",
            "unexpected_real_data_or_side_effect",
        ],
        rollback_plan={
            "required": safe_validation_level != "readonly",
            "status": "not-required" if safe_validation_level == "readonly" else "planned",
            "steps": [],
        },
        root_cause_family=root_cause_family,
        affected_instance_key=instance_key,
        reopen_conditions=(
            ["required_test_materials_available"]
            if needs_material(candidate_type, unauth)
            else ["new_differential_evidence"]
        ),
        do_not_overclaim=do_not_overclaim_for(candidate_type),
    )
    c.evidence_sources.add(signal.source)
    c.evidence_refs.add(signal.source_file)
    c.related_params.update(sorted(params | (words & IDOR_PARAMS) | (words & SSRF_PARAMS)))
    if c.needs_material and queue in {"P0", "P1"}:
        c.status = "blocked_need_material"
    return c


def impact_for(candidate_type: str, core: bool) -> str:
    mapping = {
        "SQLi": "证明数据库信息、认证绕过或业务数据读取风险",
        "SSRF": "证明服务端请求可控、内网/metadata 或回调边界风险",
        "IDOR/BOLA": "越权读取或修改核心业务对象" if core else "对象级授权边界缺陷",
        "File/Upload/Download/Import/Export": "文件上传、下载、导入、导出或处理链风险",
        "OAuth/OIDC/SAML": "账号接管、授权码/token 泄露或身份绑定缺陷",
        "API Gateway/Open Platform": "AppKey/签名/API 权限绑定或网关路由绕过",
        "OSS/STS/Object Storage": "对象存储公开、STS 临时凭据或跨用户文件访问",
        "Admin/Management": "后台/管理端未授权或低权限访问高价值功能",
        "VHost/Host-SNI": "隐藏应用、源站或测试环境暴露",
        "Open Redirect": "可组合登录、SSO、OAuth 或移动端信任链时形成凭据泄露",
        "Directory Brute": "隐藏目录、备份、Swagger、Actuator、上传/导出入口",
        "JS Attack Surface": "前端还原出的 API family、权限字段和业务对象入口",
    }
    return mapping.get(candidate_type, "授权范围内的赏金候选攻击面")


def next_action_for(candidate_type: str) -> str:
    return {
        "SQLi": "使用手工差异或 tool/sqlmap_safe.py 低风险证明 DBMS/数据库信息，不 dump 数据",
        "SSRF": "使用授权回连地址证明服务端请求可控，禁止扩大内网扫描",
        "IDOR/BOLA": "建立 A/B 账号与对象 ID 矩阵，优先只读验证对象边界",
        "File/Upload/Download/Import/Export": "分段验证 accept/store/process/serve 和跨用户文件权限",
        "OAuth/OIDC/SAML": "检查 redirect_uri、PKCE、state/nonce、code 绑定和 token endpoint",
        "API Gateway/Open Platform": "验证 AppKey/Secret、签名、nonce、API 权限绑定和测试/生产混用",
        "OSS/STS/Object Storage": "最小验证 bucket/STS/objectKey 可达性和业务关联",
        "Admin/Management": "确认认证流程、后台 API、低权限边界和高价值功能入口",
        "VHost/Host-SNI": "固定 Host/SNI 对比默认页、真实 404 和业务响应差异",
        "Open Redirect": "判断是否可组合 OAuth/SSO/callback/token/session 信任链",
        "Directory Brute": "分类命中目录，过滤 SPA fallback/默认错误页，优先验证 Swagger/Actuator/备份/管理端",
        "JS Attack Surface": "还原 API family、参数、权限和核心对象，再转入对应 P0/P1 候选",
    }.get(candidate_type, "补充证据并判断是否进入专项 playbook")


def needs_material(candidate_type: str, unauth: bool) -> bool:
    if unauth and candidate_type in {"SQLi", "SSRF", "Swagger/OpenAPI/Actuator", "VHost/Host-SNI", "Directory Brute"}:
        return False
    return candidate_type in {
        "IDOR/BOLA", "OAuth/OIDC/SAML", "File/Upload/Download/Import/Export",
        "API Gateway/Open Platform", "Mobile API/Deep Link", "Core Business API",
        "OSS/STS/Object Storage",
    }


def materials_for(candidate_type: str) -> list[str]:
    return {
        "IDOR/BOLA": ["低权限账号A", "低权限账号B", "测试对象ID", "测试组织/网点ID"],
        "OAuth/OIDC/SAML": ["低权限测试账号", "受控回调URL", "授权演练窗口"],
        "File/Upload/Download/Import/Export": ["低权限测试账号", "可回滚测试文件", "测试 fileId/objectKey"],
        "API Gateway/Open Platform": ["测试 AppKey/Secret", "测试 API 权限", "测试订单/运单/网点"],
        "OSS/STS/Object Storage": ["测试账号", "测试 objectKey", "允许验证的最小 bucket/STS 范围"],
        "Mobile API/Deep Link": ["官方安装包", "测试账号", "测试设备或抓包授权"],
        "Core Business API": ["测试账号", "测试订单/运单/支付/组织对象"],
    }.get(candidate_type, [])


def merge_candidates(candidates: list[Candidate]) -> list[Candidate]:
    merged: dict[str, Candidate] = {}
    for c in candidates:
        if c.key not in merged:
            merged[c.key] = c
            continue
        old = merged[c.key]
        old.evidence_sources.update(c.evidence_sources)
        old.evidence_refs.update(c.evidence_refs)
        old.related_params.update(c.related_params)
        old.score = max(old.score, c.score)
        old.priority_score = max(old.priority_score, c.priority_score)
        old.queue = queue_for(old.score)
        old.score_reasons = sorted(set(old.score_reasons + c.score_reasons))
        old.downgrade_reasons = sorted(set(old.downgrade_reasons + c.downgrade_reasons))
        old.anonymous_hint = old.anonymous_hint or c.anonymous_hint
        if c.observed_without_auth is True or old.observed_without_auth is None:
            old.observed_without_auth = c.observed_without_auth
        if old.auth_experiment is None and c.auth_experiment is not None:
            old.auth_experiment = c.auth_experiment
        old.unauth_reachable = old.unauth_reachable or c.unauth_reachable
        old.core_business = old.core_business or c.core_business
        old.evidence_confidence = stronger_evidence_confidence(
            old.evidence_confidence,
            c.evidence_confidence,
        )
        old.reachability_stage = later_reachability_stage(
            old.reachability_stage,
            c.reachability_stage,
        )
        old.technologies.update(c.technologies)
        old.observed_signals.update(c.observed_signals)
        old.suspected_control_gaps.update(c.suspected_control_gaps)
        old.available_materials.update(c.available_materials)
        old.available_capabilities.update(c.available_capabilities)
        if old.category == "unknown" and c.category != "unknown":
            old.category = c.category
        if old.queue == "P0":
            old.status = "blocked_need_material" if old.needs_material else "high_value"
    return sorted(merged.values(), key=lambda item: (item.queue, -item.score, item.candidate_type, item.url_or_endpoint))


def candidate_to_dict(idx: int, c: Candidate, enable_tactics: bool = False) -> dict[str, Any]:
    payload = {
        "id": f"BC-{idx:03d}",
        "name": c.name,
        "asset": c.asset,
        "url_or_endpoint": c.url_or_endpoint,
        "candidate_type": c.candidate_type,
        "queue": c.queue,
        "score": c.score,
        "evidence_sources": sorted(c.evidence_sources),
        "evidence_refs": sorted(c.evidence_refs),
        "related_params": sorted(c.related_params),
        "anonymous_hint": c.anonymous_hint,
        "observed_without_auth": c.observed_without_auth,
        "unauth_reachable": c.unauth_reachable,
        "core_business": c.core_business,
        "possible_impact": c.possible_impact,
        "status": c.status,
        "next_action": c.next_action,
        "needs_material": c.needs_material,
        "material_requirements": c.material_requirements,
        "score_reasons": c.score_reasons,
        "downgrade_reasons": c.downgrade_reasons,
    }
    if enable_tactics:
        payload["asset"] = c.asset or "unknown"
        payload.update(
            {
                "schema_version": "2.0",
                "status": "triaged" if c.status == "high_value" else c.status,
                "priority_score": c.priority_score,
                "evidence_confidence": c.evidence_confidence,
                "reachability_stage": c.reachability_stage,
                "impact_stage": c.impact_stage,
                "business_object": c.business_object,
                "business_capability": c.business_capability,
                "operation_type": c.operation_type,
                "trust_boundary": c.trust_boundary,
                "category": c.category,
                "technologies": sorted(c.technologies),
                "observed_signals": sorted(c.observed_signals),
                "suspected_control_gaps": sorted(c.suspected_control_gaps),
                "auth_experiment": c.auth_experiment,
                "safe_validation_level": c.safe_validation_level,
                "matched_tactics": c.matched_tactics,
                "route_status": c.route_status,
                "route_decision_id": c.route_decision_id,
                "route_fallback": c.route_fallback,
                "validation_contract": c.validation_contract,
                "negative_controls": c.negative_controls,
                "evidence_invariants": c.evidence_invariants,
                "stop_conditions": c.stop_conditions,
                "rollback_plan": c.rollback_plan,
                "root_cause_family": c.root_cause_family,
                "affected_instance_key": c.affected_instance_key,
                "reopen_conditions": c.reopen_conditions,
                "missing_materials": c.missing_materials,
                "blocked_reason": c.blocked_reason,
                "recovery_first_action": c.recovery_first_action,
                "resume_tactic_id": c.resume_tactic_id,
                "do_not_overclaim": c.do_not_overclaim,
            }
        )
    return payload


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# 赏金候选攻击队列",
        "",
        f"- 生成时间：`{payload['finished_at']}`",
        f"- 候选总数：{len(payload['candidates'])}",
        "",
    ]
    for queue in ("P0", "P1", "P2", "P3"):
        items = [c for c in payload["candidates"] if c["queue"] == queue]
        lines.extend([f"## {queue} 候选", ""])
        if not items:
            lines.extend(["无。", ""])
            continue
        lines.extend(["| ID | 类型 | 分数 | 状态 | 资产 | 入口 | 下一步 |", "|---|---|---:|---|---|---|---|"])
        for item in items:
            lines.append(
                f"| {item['id']} | {item['candidate_type']} | {item['score']} | {item['status']} | "
                f"`{item['asset']}` | `{item['url_or_endpoint']}` | {item['next_action']} |"
            )
        lines.append("")
    material = [c for c in payload["candidates"] if c["needs_material"]]
    lines.extend(["## 需要测试材料", ""])
    if material:
        for item in material:
            lines.append(f"- {item['id']} {item['candidate_type']} `{item['url_or_endpoint']}`：{', '.join(item['material_requirements'])}")
    else:
        lines.append("无。")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def gather_input_paths(args: argparse.Namespace) -> list[Path]:
    paths: list[Path] = []
    for raw in args.input or []:
        p = Path(raw)
        if p.is_file():
            paths.append(p)
    for root_arg, is_pipeline in (
        (args.pipeline_dir, True),
        (args.task_dir, False),
    ):
        if not root_arg:
            continue
        root = Path(root_arg)
        if not root.exists():
            continue
        discovered = iter_json_paths(root)
        for suffix in ("*.txt", "*.md", "*.js", "*.map"):
            discovered.extend(
                sorted(
                    p
                    for p in root.rglob(suffix)
                    if p.is_file() and "__pycache__" not in p.parts
                )
            )
        if is_pipeline:
            discovered = [
                path
                for path in discovered
                if not is_generated_pipeline_output(path, root)
            ]
        paths.extend(discovered)
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


class TacticRoutingUnavailable(RuntimeError):
    """Raised when candidate v2 routing was requested but is not available."""


def resolve_tactic_router() -> tuple[Any, Any]:
    try:
        module_name = (
            f"{__package__}.cybertest_core.routing"
            if __package__
            else "cybertest_core.routing"
        )
        routing = importlib.import_module(module_name)
    except (ImportError, ModuleNotFoundError) as exc:
        raise TacticRoutingUnavailable(
            "--enable-tactics requires tool/cybertest_core/routing.py with "
            "load_tactics() and rank_tactics()."
        ) from exc
    load_tactics = getattr(routing, "load_tactics", None)
    rank_tactics = getattr(routing, "rank_tactics", None)
    if not callable(load_tactics) or not callable(rank_tactics):
        raise TacticRoutingUnavailable(
            "--enable-tactics requires callable load_tactics() and "
            "rank_tactics(context, tactics, top_k=3)."
        )
    return load_tactics, rank_tactics


def route_context_for(candidate: Candidate) -> dict[str, Any]:
    target_types = ["api"]
    if candidate.candidate_type == "Admin/Management":
        target_types.append("admin")
    if candidate.candidate_type == "JS Attack Surface":
        target_types.append("spa")
    return {
        "task_kind": "security-testing",
        "phase": "triage",
        "category": candidate.category,
        "target_types": target_types,
        "technologies": sorted(candidate.technologies),
        "business_objects": [candidate.business_object],
        "operation_types": [candidate.operation_type],
        "trust_boundaries": [candidate.trust_boundary],
        "observed_signals": sorted(
            set(candidate.observed_signals)
            | set(candidate.evidence_sources)
            | set(candidate.related_params)
            | {candidate.candidate_type}
            | ({"anonymous_hint"} if candidate.anonymous_hint else set())
        ),
        "suspected_control_gaps": sorted(candidate.suspected_control_gaps),
        "auth_contexts": ["explicit_auth_experiment"] if candidate.auth_experiment else [],
        "evidence_stage": candidate.reachability_stage,
        "available_materials": sorted(candidate.available_materials),
        "available_capabilities": sorted(
            candidate.available_capabilities or {"cli.http"}
        ),
        "excluded_routes": [],
        "previous_route_decisions": [],
    }


def normalize_tactic_match(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        converted = to_dict()
        if isinstance(converted, dict):
            return converted
    return {"id": str(getattr(item, "id", item))}


def attach_tactics(candidates: list[Candidate]) -> None:
    load_tactics, rank_tactics = resolve_tactic_router()
    try:
        tactics = load_tactics()
    except Exception as exc:
        raise TacticRoutingUnavailable(f"failed to load tactic registry: {exc}") from exc
    for candidate in candidates:
        try:
            ranked = rank_tactics(route_context_for(candidate), tactics, top_k=3)
        except Exception as exc:
            raise TacticRoutingUnavailable(
                f"failed to rank tactics for {candidate.candidate_type}: {exc}"
            ) from exc
        decision = ranked if isinstance(ranked, dict) else None
        if isinstance(ranked, dict):
            ranked = ranked.get("matched_tactics", [])
        if ranked is None:
            ranked = []
        if not isinstance(ranked, (list, tuple)):
            raise TacticRoutingUnavailable("rank_tactics() must return a list of matches.")
        candidate.matched_tactics = [normalize_tactic_match(item) for item in ranked[:3]]
        if decision is not None:
            candidate.route_status = str(decision.get("route_status", "unrouted"))
            candidate.route_decision_id = str(decision.get("decision_id", ""))
            candidate.resume_tactic_id = str(
                decision.get("resume_tactic_id") or ""
            )
            fallback = decision.get("fallback")
            candidate.route_fallback = (
                dict(fallback)
                if isinstance(fallback, dict)
                else None
            )
            next_action = decision.get("next_discriminating_action")
            if isinstance(next_action, str) and next_action:
                candidate.next_action = next_action
            route_materials = decision.get("material_requirements", [])
            if isinstance(route_materials, list) and route_materials:
                normalized_materials = [
                    item
                    for item in route_materials
                    if isinstance(item, dict)
                    and isinstance(item.get("id"), str)
                ]
                candidate.material_requirements = [
                    str(item.get("description") or item["id"])
                    for item in normalized_materials
                ]
                candidate.missing_materials = [
                    str(item["id"])
                    for item in normalized_materials
                    if item.get("required", True)
                    and item.get("available") is not True
                ]
                candidate.needs_material = bool(candidate.missing_materials)
            else:
                candidate.missing_materials = []
            if candidate.route_status == "blocked_need_material":
                candidate.status = "blocked_need_material"
                candidate.needs_material = True
                candidate.blocked_reason = str(
                    (candidate.route_fallback or {}).get("reason")
                    or "required controlled material is unavailable"
                )
                candidate.recovery_first_action = candidate.next_action
                candidate.reopen_conditions = [
                    f"material_available:{item}"
                    for item in candidate.missing_materials
                ]
            else:
                if candidate.status == "blocked_need_material":
                    candidate.status = "triaged"
                candidate.blocked_reason = ""
                candidate.recovery_first_action = ""
            contract = decision.get("validation_contract")
            if isinstance(contract, dict):
                candidate.validation_contract = contract
                request_matrix = contract.get("request_matrix", [])
                if isinstance(request_matrix, list):
                    candidate.negative_controls = [
                        str(item["id"])
                        for item in request_matrix
                        if isinstance(item, dict)
                        and item.get("role") == "negative_control"
                        and item.get("id")
                    ]
                contract_negative_controls = contract.get(
                    "negative_controls"
                )
                if isinstance(contract_negative_controls, list):
                    candidate.negative_controls = [
                        str(item)
                        for item in contract_negative_controls
                        if isinstance(item, str)
                    ]
                invariants = contract.get("evidence_invariants")
                if isinstance(invariants, list):
                    candidate.evidence_invariants = [
                        str(item)
                        for item in invariants
                        if isinstance(item, str)
                    ]
                validation_level = contract.get("safe_validation_level")
                if isinstance(validation_level, str):
                    candidate.safe_validation_level = validation_level
                rollback = contract.get("rollback")
                if isinstance(rollback, dict):
                    required = bool(rollback.get("required"))
                    candidate.rollback_plan = {
                        "required": required,
                        "status": "planned" if required else "not-required",
                        "steps": [
                            str(item)
                            for item in rollback.get("steps", [])
                            if isinstance(item, str)
                        ],
                    }
            stop_conditions = decision.get("stop_conditions")
            if isinstance(stop_conditions, list):
                candidate.stop_conditions = stop_conditions
            do_not_overclaim = decision.get("do_not_overclaim")
            if isinstance(do_not_overclaim, str) and do_not_overclaim:
                candidate.do_not_overclaim = do_not_overclaim


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate P0/P1/P2/P3 bounty candidate queue from local artifacts.")
    parser.add_argument("--pipeline-dir", help="scan_pipeline output directory.")
    parser.add_argument("--task-dir", help="Cybertest task directory.")
    parser.add_argument("--input", action="append", help="Additional JSON/text/JS file. Repeatable.")
    parser.add_argument("--output-json", help="Output JSON path.")
    parser.add_argument("--output-md", help="Output Markdown path.")
    parser.add_argument("--min-score", type=int, default=0, help="Only emit candidates at or above this score.")
    parser.add_argument(
        "--enable-tactics",
        action="store_true",
        help="Emit candidate schema v2 and attach Top-3 tactics using cybertest_core.routing.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    input_paths = gather_input_paths(args)
    if not input_paths:
        print("No input artifacts found. Provide --pipeline-dir, --task-dir, or --input.", file=sys.stderr)
        return 2

    signals = collect_signals(input_paths)
    candidates: list[Candidate] = []
    for signal in signals:
        for ctype in infer_types(signal):
            candidates.append(classify_signal(signal, ctype))
    merged = [c for c in merge_candidates(candidates) if c.score >= args.min_score]
    if args.enable_tactics:
        try:
            attach_tactics(merged)
        except TacticRoutingUnavailable as exc:
            print(f"Tactic routing unavailable: {exc}", file=sys.stderr)
            return 2
    candidate_dicts = [
        candidate_to_dict(idx, c, enable_tactics=args.enable_tactics)
        for idx, c in enumerate(merged, 1)
    ]
    payload = {
        "ok": True,
        "tool": "bounty_candidate_queue",
        "started_at": started_at,
        "finished_at": utc_now(),
        "inputs": [str(p) for p in input_paths],
        "signal_count": len(signals),
        "candidate_count": len(candidate_dicts),
        "queue_summary": {q: sum(1 for c in candidate_dicts if c["queue"] == q) for q in ("P0", "P1", "P2", "P3")},
        "candidates": candidate_dicts,
    }
    if args.enable_tactics:
        payload["schema_version"] = "2.0"
    if args.output_json:
        write_json(Path(args.output_json), payload)
    if args.output_md:
        write_markdown(Path(args.output_md), payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
