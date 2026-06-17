#!/usr/bin/env python3
"""
ProjectDiscovery katana JSONL wrapper for authorized web crawling.

Examples:
  ./tool/katana_crawl.py --authorized --target https://example.com --output katana.json
  ./tool/katana_crawl.py --authorized --input urls.txt --js-crawl --known-files robotstxt,sitemapxml
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT = 1200
DEFAULT_TOOL_HOME = "/tmp/codex-projectdiscovery-home"

# Shared async utilities (--async-start / --async-status)
from _async_utils import add_async_args, async_start, async_status


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_json_lines(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    raw_lines: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            raw_lines.append(line)
            continue
        if isinstance(value, dict):
            records.append(value)
        else:
            raw_lines.append(line)
    return records, raw_lines


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.target or [])
    if args.input:
        for line in Path(args.input).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def build_command(args: argparse.Namespace, targets: list[str], input_path: Path | None) -> list[str]:
    command = [
        args.katana_binary,
        "-jsonl",
        "-silent",
        "-d",
        str(args.depth),
    ]

    if len(targets) == 1:
        command.extend(["-u", targets[0]])
    else:
        command.extend(["-list", str(input_path)])

    if args.exclude_output_fields:
        command.extend(["-eof", args.exclude_output_fields])
    if args.js_crawl:
        command.append("-jc")
    if args.form_extraction:
        command.append("-fx")
    if args.tech_detect:
        command.append("-td")
    if args.known_files:
        command.extend(["-kf", args.known_files])
    if args.headless:
        command.append("-headless")
    if args.system_chrome:
        command.append("-system-chrome")
    if args.no_sandbox:
        command.append("-no-sandbox")
    if args.no_scope:
        command.append("-ns")
    if args.display_out_scope:
        command.append("-do")
    if args.field_scope:
        command.extend(["-fs", args.field_scope])
    if args.crawl_scope:
        command.extend(["-cs", args.crawl_scope])
    if args.crawl_out_scope:
        command.extend(["-cos", args.crawl_out_scope])
    if args.crawl_duration:
        command.extend(["-ct", args.crawl_duration])
    if args.rate_limit:
        command.extend(["-rl", str(args.rate_limit)])
    if args.concurrency:
        command.extend(["-c", str(args.concurrency)])
    if args.proxy:
        command.extend(["-proxy", args.proxy])
    for header in args.header:
        command.extend(["-H", header])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def build_env(tool_home: str | None) -> dict[str, str] | None:
    if not tool_home:
        return None
    Path(tool_home).mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = tool_home
    return env


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def decode_process_output(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run katana and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", action="append", help="URL target. Repeat for multiple targets.")
    parser.add_argument("--input", help="File containing one URL per line.")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawl depth.")
    parser.add_argument("--js-crawl", action="store_true", help="Parse and crawl endpoints found in JavaScript files.")
    parser.add_argument("--form-extraction", action="store_true", help="Extract form/input/textarea/select data.")
    parser.add_argument("--tech-detect", action="store_true", help="Enable technology detection.")
    parser.add_argument("--known-files", help="Crawl known files, for example robotstxt,sitemapxml or all.")
    parser.add_argument("--headless", action="store_true", help="Enable Katana headless crawling.")
    parser.add_argument("--system-chrome", action="store_true", help="Use local Chrome for headless crawling.")
    parser.add_argument("--no-sandbox", action="store_true", help="Start headless Chrome with no sandbox.")
    parser.add_argument("--field-scope", choices=["rdn", "fqdn", "dn"], help="Katana predefined scope field.")
    parser.add_argument("--no-scope", action="store_true", help="Disable host-based default scope.")
    parser.add_argument("--display-out-scope", action="store_true", help="Display external endpoints found in scope.")
    parser.add_argument("--crawl-scope", help="Regex or file for in-scope URLs.")
    parser.add_argument("--crawl-out-scope", help="Regex or file for out-of-scope URLs.")
    parser.add_argument("--crawl-duration", help="Maximum crawl duration, for example 30s, 5m, 1h.")
    parser.add_argument("--rate-limit", type=int, help="Maximum requests per second.")
    parser.add_argument("--concurrency", type=int, help="Number of concurrent fetchers.")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy.")
    parser.add_argument("--header", action="append", default=[], help="Header or cookie in 'Name: value' format.")
    parser.add_argument(
        "--exclude-output-fields",
        default="raw,body",
        help="Fields to exclude from JSONL output. Default avoids large raw/body fields.",
    )
    parser.add_argument("--include-raw", action="store_true", help="Do not exclude raw/body fields.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw katana argument.")
    parser.add_argument("--tool-home", default=DEFAULT_TOOL_HOME, help="HOME directory for the wrapped katana process.")
    parser.add_argument("--katana-binary", default="katana", help="Path to katana binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    add_async_args(parser, "katana")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if args.async_status:
        return async_status(args, started_at)

    if args.include_raw:
        args.exclude_output_fields = ""

    if not args.authorized:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "authorization_required",
                    "message": "Pass --authorized only after confirming the targets are in scope.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    targets = load_targets(args)
    if not targets:
        emit(
            {
                "ok": False,
                "error": {"type": "missing_targets", "message": "Provide --target or --input."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if shutil.which(args.katana_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"katana binary not found: {args.katana_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    if args.async_start:
        return async_start(args, argv, "katana", started_at)

    with tempfile.TemporaryDirectory(prefix="katana-crawl-") as tmpdir:
        input_path = None
        if len(targets) > 1:
            input_path = Path(tmpdir) / "targets.txt"
            input_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
        command = build_command(args, targets, input_path)
        env = build_env(args.tool_home)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            emit(
                {
                    "ok": False,
                    "error": {"type": "timeout", "message": f"katana exceeded {args.timeout} seconds"},
                    "command": exc.cmd,
                    "stdout": decode_process_output(exc.stdout),
                    "stderr": decode_process_output(exc.stderr),
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 124

    records, raw_lines = parse_json_lines(completed.stdout)
    payload = {
        "ok": completed.returncode == 0,
        "tool": "katana",
        "started_at": started_at,
        "finished_at": utc_now(),
        "targets": targets,
        "depth": args.depth,
        "command": command,
        "returncode": completed.returncode,
        "results": records,
        "raw_stdout_lines": raw_lines,
        "stderr": completed.stderr,
    }
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
