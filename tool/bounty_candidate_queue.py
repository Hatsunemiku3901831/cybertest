#!/usr/bin/env python3
"""Generate a bug-bounty-oriented candidate queue from existing Cybertest outputs.

This tool is offline only: it reads scan/task artifacts and emits structured
P0/P1/P2/P3 candidates. It does not send network requests.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse


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


@dataclass
class RawSignal:
    value: str
    source: str
    source_file: str
    record: dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    key: str
    name: str
    asset: str
    url_or_endpoint: str
    candidate_type: str
    evidence_sources: set[str] = field(default_factory=set)
    evidence_refs: set[str] = field(default_factory=set)
    related_params: set[str] = field(default_factory=set)
    score: int = 0
    score_reasons: list[str] = field(default_factory=list)
    downgrade_reasons: list[str] = field(default_factory=list)
    unauth_reachable: bool = False
    core_business: bool = False
    possible_impact: str = ""
    next_action: str = ""
    needs_material: bool = False
    material_requirements: list[str] = field(default_factory=list)
    status: str = "discovered"
    queue: str = "P3"


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


def normalize_value(value: str) -> str:
    return value.strip().rstrip(".,;")


def asset_for(value: str) -> str:
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
    return {t.lower() for t in re.split(r"[^A-Za-z0-9]+", value) if t}


def query_params(value: str) -> set[str]:
    if "?" not in value:
        return set()
    query = urlparse(value).query if "://" in value else value.split("?", 1)[1]
    return {k.lower() for k, _ in parse_qsl(query, keep_blank_values=True)}


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


def base_score(candidate_type: str) -> int:
    return {
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
    }.get(candidate_type, 20)


def classify_signal(signal: RawSignal, candidate_type: str) -> Candidate:
    value = normalize_value(signal.value)
    words = tokens(value)
    params = query_params(value)
    status = str(signal.record.get("status_code") or signal.record.get("status") or signal.record.get("code") or "")
    asset = asset_for(value)
    endpoint = path_for(value)
    score = base_score(candidate_type)
    reasons = [f"{candidate_type} base"]
    downgrades: list[str] = []

    core = bool(words & CORE_WORDS or params & IDOR_PARAMS)
    if core:
        score += 15
        reasons.append("核心业务对象或权限字段")
    if words & TEST_ENV_WORDS:
        score += 12
        reasons.append("测试/预发/灰度环境关键词")
    if words & EDGE_WORDS:
        score += 8
        reasons.append("边缘/后台/API/SSO/文件关键词")
    if signal.source.startswith("gf:"):
        score += 8
        reasons.append(f"GF 命中 {signal.source.split(':', 1)[1]}")
    if signal.source == "nuclei":
        score += 8
        reasons.append("Nuclei 发现来源")
    if signal.source in {"js", "katana", "history"}:
        score += 5
        reasons.append(f"{signal.source} 攻击面来源")
    unauth = status.startswith("2") or status in {"200", "201", "204", "301", "302"}
    if unauth:
        score += 10
        reasons.append("未认证可达或 2xx/3xx 线索")
    if status in {"401", "403", "404"}:
        score -= 14
        downgrades.append(f"仅观察到 HTTP {status}")
    if candidate_type in {"Swagger/OpenAPI/Actuator", "JS Attack Surface", "Open Redirect"} and not core:
        score -= 10
        downgrades.append("当前更像信息项，需组合认证/业务影响")
    if "health" in words and not (words & {"actuator", "config", "env"}):
        score -= 15
        downgrades.append("无敏感 health/info 候选")

    score = max(0, min(100, score))
    queue = queue_for(score)
    c = Candidate(
        key=f"{candidate_type}:{asset}:{endpoint}",
        name=f"{candidate_type} 候选 - {endpoint[:80]}",
        asset=asset,
        url_or_endpoint=endpoint,
        candidate_type=candidate_type,
        score=score,
        score_reasons=reasons,
        downgrade_reasons=downgrades,
        unauth_reachable=unauth,
        core_business=core,
        possible_impact=impact_for(candidate_type, core),
        next_action=next_action_for(candidate_type),
        needs_material=needs_material(candidate_type, unauth),
        material_requirements=materials_for(candidate_type),
        status="high_value" if queue == "P0" else ("triaged" if queue in {"P1", "P2"} else "discovered"),
        queue=queue,
    )
    c.evidence_sources.add(signal.source)
    c.evidence_refs.add(signal.source_file)
    c.related_params.update(sorted(params | (words & IDOR_PARAMS) | (words & SSRF_PARAMS)))
    if c.needs_material and queue in {"P0", "P1"}:
        c.status = "blocked_need_material"
    return c


def queue_for(score: int) -> str:
    if score >= 75:
        return "P0"
    if score >= 58:
        return "P1"
    if score >= 38:
        return "P2"
    return "P3"


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
        old.queue = queue_for(old.score)
        old.score_reasons = sorted(set(old.score_reasons + c.score_reasons))
        old.downgrade_reasons = sorted(set(old.downgrade_reasons + c.downgrade_reasons))
        old.unauth_reachable = old.unauth_reachable or c.unauth_reachable
        old.core_business = old.core_business or c.core_business
        if old.queue == "P0":
            old.status = "blocked_need_material" if old.needs_material else "high_value"
    return sorted(merged.values(), key=lambda item: (item.queue, -item.score, item.candidate_type, item.url_or_endpoint))


def candidate_to_dict(idx: int, c: Candidate) -> dict[str, Any]:
    return {
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
    for root_arg in (args.pipeline_dir, args.task_dir):
        if not root_arg:
            continue
        root = Path(root_arg)
        if not root.exists():
            continue
        paths.extend(iter_json_paths(root))
        for suffix in ("*.txt", "*.md", "*.js", "*.map"):
            paths.extend(sorted(p for p in root.rglob(suffix) if p.is_file() and "__pycache__" not in p.parts))
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate P0/P1/P2/P3 bounty candidate queue from local artifacts.")
    parser.add_argument("--pipeline-dir", help="scan_pipeline output directory.")
    parser.add_argument("--task-dir", help="Cybertest task directory.")
    parser.add_argument("--input", action="append", help="Additional JSON/text/JS file. Repeatable.")
    parser.add_argument("--output-json", help="Output JSON path.")
    parser.add_argument("--output-md", help="Output Markdown path.")
    parser.add_argument("--min-score", type=int, default=0, help="Only emit candidates at or above this score.")
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
    candidate_dicts = [candidate_to_dict(idx, c) for idx, c in enumerate(merged, 1)]
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
    if args.output_json:
        write_json(Path(args.output_json), payload)
    if args.output_md:
        write_markdown(Path(args.output_md), payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
