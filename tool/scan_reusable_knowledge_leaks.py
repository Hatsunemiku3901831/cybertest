#!/usr/bin/env python3
"""Scan reusable Cybertest knowledge without echoing sensitive values."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    from cybertest_core.schema_validation import assert_valid, load_json_document
except ModuleNotFoundError:  # Imported as ``tool.scan_reusable_knowledge_leaks``.
    from tool.cybertest_core.schema_validation import (
        assert_valid,
        load_json_document,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = (
    REPO_ROOT / "agent" / "policies" / "reusable-knowledge-allowlist.json"
)
ALLOWLIST_SCHEMA = (
    REPO_ROOT
    / "agent"
    / "schemas"
    / "reusable-knowledge-allowlist.schema.json"
)
DEFAULT_ROOTS = (
    REPO_ROOT / "agent" / "cases",
    REPO_ROOT / "agent" / "memory",
    REPO_ROOT / "agent" / "tactics",
    REPO_ROOT / "agent" / "skills",
    REPO_ROOT / "agent" / "references",
    REPO_ROOT / "tests" / "fixtures",
    REPO_ROOT / "tests" / "golden",
)
TEXT_SUFFIXES = {
    ".cfg",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
IGNORED_PARTS = {
    ".git",
    ".idea",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
}

PERSONAL_PATH_PATTERNS = (
    re.compile(r"/Users/[A-Za-z0-9._-]+(?:/|\b)"),
    re.compile(r"/home/[A-Za-z0-9._-]+(?:/|\b)"),
    re.compile(r"(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+(?:\\|\b)"),
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{12,}"
    r"(?![A-Za-z0-9_-])"
)
EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}"
    r"(?![A-Za-z0-9._%+-])"
)
DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![@A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+"
    r"(?:ai|app|biz|cloud|cn|co|com|dev|edu|gov|info|io|me|mil|net|org|site|tech|top|xyz)"
    r"(?![A-Za-z0-9_.-])"
)
IPV4_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9:.])"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}"
    r"(?![A-Fa-f0-9:.])"
)
IPV6_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9:])"
    r"(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}"
    r"(?![A-Fa-f0-9:])"
)
TOKEN_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    (?<![A-Za-z0-9_])
    (?P<key_quote>["']?)
    (?:
        api[-_\s]?key
        |access[-_\s]?token
        |refresh[-_\s]?token
        |id[-_\s]?token
        |auth[-_\s]?token
        |authorization(?:[-_\s]?header)?
        |client[-_\s]?secret
        |app[-_\s]?secret
        |password
        |passwd
        |credentials?
        |secret
        |token
    )
    (?P=key_quote)
    \s*[:=]\s*
    (?:
        "(?P<double_quoted>(?:\\.|[^"\\\r\n]){24,})"
        |'(?P<single_quoted>(?:\\.|[^'\\\r\n]){24,})'
        |(?P<bare>[^\s,;\#}\]]{24,})
    )
    """
)
KNOWN_TOKEN_PATTERNS = (
    re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])"),
)

ALLOWED_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
    "json-schema.org",
}
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/15",
        "2001:db8::/32",
    )
)
PLACEHOLDER_MARKERS = {
    "controlled",
    "dummy",
    "example",
    "fixed",
    "invalid",
    "placeholder",
    "redacted",
    "sample",
    "synthetic",
    "test",
}
PLACEHOLDER_MARKER_PATTERN = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:"
    + "|".join(sorted(PLACEHOLDER_MARKERS))
    + r")(?:[^a-z0-9]|$)"
)
SEVERITY_ORDER = {
    "medium": 1,
    "high": 2,
    "critical": 3,
}
DEFAULT_FAIL_SEVERITY = "high"


class LeakScanError(ValueError):
    """Raised for an unreadable or invalid scan target."""


def canonical_json(document: Any) -> str:
    return json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _looks_placeholder(value: str) -> bool:
    if PLACEHOLDER_MARKER_PATTERN.search(value):
        return True
    if "{" in value or "}" in value or "<" in value or ">" in value:
        return True
    compact = value.strip("xX0-_")
    return not compact


def _domain_allowed(value: str) -> bool:
    lowered = value.lower().rstrip(".")
    return (
        lowered in ALLOWED_DOMAINS
        or lowered.endswith(".example.com")
        or lowered.endswith(".example.net")
        or lowered.endswith(".example.org")
        or lowered.endswith(".invalid")
        or lowered.endswith(".localhost")
        or lowered.endswith(".test")
    )


def _email_allowed(value: str) -> bool:
    domain = value.rsplit("@", 1)[-1]
    return _domain_allowed(domain)


def _ip_allowed(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return (
        address.is_loopback
        or address.is_unspecified
        or address.is_link_local
        or address.is_multicast
        or any(address in network for network in ALLOWED_NETWORKS)
    )


def _finding(
    *,
    kind: str,
    severity: str,
    path: str,
    line_number: int,
    column: int,
    value: str,
    allowlist_id: str | None = None,
) -> dict[str, Any]:
    finding = {
        "kind": kind,
        "severity": severity,
        "path": path,
        "line": line_number,
        "column": column,
        "fingerprint": hashlib.sha256(value.encode("utf-8")).hexdigest()[:16],
        "preview": f"<redacted:{kind};length={len(value)}>",
    }
    if allowlist_id:
        finding["allowlist_id"] = allowlist_id
    return finding


def _normalize_allowlist_value(match_type: str, value: str) -> str:
    if match_type == "exact_domain":
        return value.lower().rstrip(".")
    if match_type == "exact_ip":
        return str(ipaddress.ip_address(value))
    raise LeakScanError(f"unsupported allowlist match type: {match_type}")


def load_allowlist(path: Path = DEFAULT_ALLOWLIST) -> list[dict[str, Any]]:
    """Load and validate exact, path-scoped reusable-knowledge exceptions."""

    document = load_json_document(path)
    schema = load_json_document(ALLOWLIST_SCHEMA)
    assert_valid(document, schema, "reusable knowledge allowlist")

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_rules: set[tuple[str, str, tuple[str, ...]]] = set()
    for raw_entry in document["entries"]:
        entry = dict(raw_entry)
        entry_id = entry["id"]
        if entry_id in seen_ids:
            raise LeakScanError(f"duplicate allowlist id: {entry_id}")
        seen_ids.add(entry_id)

        value = entry["value"]
        if any(marker in value for marker in ("*", "?", "[", "]")):
            raise LeakScanError(
                f"allowlist entry {entry_id} must use an exact value"
            )
        entry["value"] = _normalize_allowlist_value(
            entry["match_type"],
            value,
        )
        scopes = tuple(sorted(entry["scope"]))
        rule_key = (entry["match_type"], entry["value"], scopes)
        if rule_key in seen_rules:
            raise LeakScanError(f"duplicate allowlist rule: {entry_id}")
        seen_rules.add(rule_key)

        expires_at = entry.get("expires_at")
        entry["_expired"] = bool(
            expires_at and date.fromisoformat(expires_at) < date.today()
        )
        entries.append(entry)
    return entries


def _scope_matches(path: str, scope: str) -> bool:
    normalized_path = path.replace("\\", "/").lstrip("./")
    normalized_scope = scope.replace("\\", "/").lstrip("./")
    if normalized_scope.endswith("/"):
        return normalized_path.startswith(normalized_scope)
    return normalized_path == normalized_scope


def _allowlist_match(
    *,
    kind: str,
    value: str,
    path: str,
    entries: Sequence[dict[str, Any]],
) -> str | None:
    match_type = {
        "domain": "exact_domain",
        "ip_address": "exact_ip",
    }.get(kind)
    if match_type is None:
        return None
    try:
        normalized_value = _normalize_allowlist_value(match_type, value)
    except ValueError:
        return None

    for entry in entries:
        if entry.get("_expired"):
            continue
        if entry["match_type"] != match_type:
            continue
        if entry["value"] != normalized_value:
            continue
        if any(_scope_matches(path, scope) for scope in entry["scope"]):
            return str(entry["id"])
    return None


def scan_text(
    text: str,
    *,
    path: str = "<memory>",
    allowlist: Sequence[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Return redacted findings for one text document."""

    findings: list[dict[str, Any]] = []
    seen: set[tuple[int, int, str]] = set()

    def add(
        *,
        line_number: int,
        match: re.Match[str],
        kind: str,
        severity: str,
        value: str | None = None,
    ) -> None:
        detected = value if value is not None else match.group(0)
        key = (line_number, match.start(), kind)
        if key in seen:
            return
        seen.add(key)
        allowlist_id = _allowlist_match(
            kind=kind,
            value=detected,
            path=path,
            entries=allowlist,
        )
        findings.append(
            _finding(
                kind=kind,
                severity=severity,
                path=path,
                line_number=line_number,
                column=match.start() + 1,
                value=detected,
                allowlist_id=allowlist_id,
            )
        )

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in PERSONAL_PATH_PATTERNS:
            for match in pattern.finditer(line):
                add(
                    line_number=line_number,
                    match=match,
                    kind="personal_absolute_path",
                    severity="high",
                )
        for match in PRIVATE_KEY_PATTERN.finditer(line):
            add(
                line_number=line_number,
                match=match,
                kind="private_key",
                severity="critical",
            )
        for match in JWT_PATTERN.finditer(line):
            add(
                line_number=line_number,
                match=match,
                kind="jwt",
                severity="critical",
            )
        for pattern in KNOWN_TOKEN_PATTERNS:
            for match in pattern.finditer(line):
                if not _looks_placeholder(match.group(0)):
                    add(
                        line_number=line_number,
                        match=match,
                        kind="high_confidence_token",
                        severity="critical",
                    )
        for match in TOKEN_ASSIGNMENT_PATTERN.finditer(line):
            value = next(
                group
                for group in (
                    match.group("double_quoted"),
                    match.group("single_quoted"),
                    match.group("bare"),
                )
                if group is not None
            )
            if not _looks_placeholder(value):
                add(
                    line_number=line_number,
                    match=match,
                    kind="high_confidence_token",
                    severity="critical",
                    value=value,
                )
        for match in EMAIL_PATTERN.finditer(line):
            if not _email_allowed(match.group(0)):
                add(
                    line_number=line_number,
                    match=match,
                    kind="email",
                    severity="high",
                )
        for match in DOMAIN_PATTERN.finditer(line):
            if not _domain_allowed(match.group(0)):
                add(
                    line_number=line_number,
                    match=match,
                    kind="domain",
                    severity="medium",
                )
        for match in IPV4_PATTERN.finditer(line):
            if not _ip_allowed(match.group(0)):
                add(
                    line_number=line_number,
                    match=match,
                    kind="ip_address",
                    severity="medium",
                )
        for match in IPV6_PATTERN.finditer(line):
            try:
                allowed = _ip_allowed(match.group(0))
            except ValueError:
                continue
            if not allowed:
                add(
                    line_number=line_number,
                    match=match,
                    kind="ip_address",
                    severity="medium",
                )

    return sorted(
        findings,
        key=lambda item: (
            item["path"],
            item["line"],
            item["column"],
            item["kind"],
        ),
    )


def _iter_files(paths: Iterable[Path]) -> list[Path]:
    discovered: set[Path] = set()
    for root in paths:
        if not root.exists():
            raise LeakScanError(f"scan path is missing: {root.name}")
        candidates = [root] if root.is_file() else root.rglob("*")
        for path in candidates:
            if not path.is_file():
                continue
            if any(part in IGNORED_PARTS for part in path.parts):
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            discovered.add(path.resolve())
    return sorted(discovered)


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.name


def scan_paths(
    paths: Iterable[Path],
    *,
    repo_root: Path = REPO_ROOT,
    fail_severity: str = DEFAULT_FAIL_SEVERITY,
    allowlist_path: Path = DEFAULT_ALLOWLIST,
) -> dict[str, Any]:
    """Scan configured files/directories and return a stable JSON report."""

    if fail_severity not in SEVERITY_ORDER:
        raise LeakScanError(f"unsupported fail severity: {fail_severity}")
    allowlist = load_allowlist(allowlist_path)
    files = _iter_files(paths)
    findings: list[dict[str, Any]] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(
            scan_text(
                text,
                path=_display_path(path, repo_root),
                allowlist=allowlist,
            )
        )

    threshold = SEVERITY_ORDER[fail_severity]
    suppressed_findings = [
        {**finding, "disposition": "suppressed"}
        for finding in findings
        if finding.get("allowlist_id")
    ]
    blocking_findings = [
        {**finding, "disposition": "blocking"}
        for finding in findings
        if not finding.get("allowlist_id")
        if SEVERITY_ORDER.get(finding["severity"], 0) >= threshold
    ]
    review_findings = [
        {**finding, "disposition": "review"}
        for finding in findings
        if not finding.get("allowlist_id")
        if SEVERITY_ORDER.get(finding["severity"], 0) < threshold
    ]
    status = (
        "FAIL"
        if blocking_findings
        else ("REVIEW" if review_findings else "PASS")
    )
    return {
        "schema_version": "1.0",
        "ok": not blocking_findings,
        "status": status,
        "fail_severity": fail_severity,
        "allowlist": allowlist_path.name,
        "allowlist_entry_count": len(allowlist),
        "scanned_file_count": len(files),
        "finding_count": len(findings),
        "active_finding_count": (
            len(blocking_findings) + len(review_findings)
        ),
        "blocking_finding_count": len(blocking_findings),
        "review_finding_count": len(review_findings),
        "suppressed_finding_count": len(suppressed_findings),
        "findings": sorted(
            blocking_findings + review_findings + suppressed_findings,
            key=lambda item: (
                item["path"],
                item["line"],
                item["column"],
                item["kind"],
            ),
        ),
    }


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="扫描可复用知识中的个人路径、秘密和真实目标标识，输出脱敏 JSON。",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="待扫描文件或目录；省略时扫描项目默认可复用目录。",
    )
    parser.add_argument("--output", type=Path, help="可选 JSON 报告路径。")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只输出报告，不写 --output。",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help=(
            "存在达到 --fail-severity 的未豁免发现时返回退出码 1；"
            "未设置时报告可为 FAIL 但退出码保持 0。"
        ),
    )
    parser.add_argument(
        "--fail-severity",
        choices=tuple(SEVERITY_ORDER),
        default=DEFAULT_FAIL_SEVERITY,
        help=(
            "报告阻断阈值；只改变 PASS/REVIEW/FAIL 分类，"
            "不会单独改变退出码。"
        ),
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=DEFAULT_ALLOWLIST,
        help="精确值、路径限定且经 schema 校验的允许项文件。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    paths = args.paths or list(DEFAULT_ROOTS)
    try:
        report = scan_paths(
            paths,
            fail_severity=args.fail_severity,
            allowlist_path=args.allowlist,
        )
        if args.dry_run:
            report["dry_run"] = True
            if args.output:
                report["would_write"] = args.output.name
        rendered = canonical_json(report)
        if args.output and not args.dry_run:
            _write_text(args.output, rendered)
        sys.stdout.write(rendered)
        if report["blocking_finding_count"] and args.fail_on_findings:
            return 1
        return 0
    except (LeakScanError, OSError, ValueError) as exc:
        sys.stderr.write(canonical_json({"ok": False, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
