#!/usr/bin/env python3
"""Arjun JSON wrapper for authorized HTTP parameter discovery."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT = 1200


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.target or [])
    if args.input:
        for line in Path(args.input).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def build_command(args: argparse.Namespace, targets: list[str], arjun_output: Path, input_path: Path | None) -> list[str]:
    command = [args.arjun_binary, "-oJ", str(arjun_output), "-t", str(args.threads)]
    if len(targets) == 1:
        command.extend(["-u", targets[0]])
    else:
        command.extend(["-i", str(input_path)])
    if args.method:
        command.extend(["-m", args.method])
    include_parts = []
    if args.data:
        include_parts.append(args.data)
    if args.include:
        include_parts.append(args.include)
    if include_parts:
        command.extend(["--include", "&".join(include_parts)])
    if args.stable:
        command.append("--stable")
    if args.passive:
        command.append("--passive")
    if args.rate:
        command.extend(["--rate-limit", str(args.rate)])
    if args.header:
        command.extend(["--headers", "\n".join(args.header)])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Arjun and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", action="append", help="Target URL. Repeat for multiple targets.")
    parser.add_argument("--input", help="File containing one target URL per line.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--method", help="HTTP method, for example GET or POST.")
    parser.add_argument("--data", help="Request body for parameter discovery.")
    parser.add_argument("--header", action="append", default=[], help="Header in 'Name: value' format.")
    parser.add_argument("--include", help="Comma-separated parameter names to include with Arjun --include.")
    parser.add_argument("--threads", type=int, default=5, help="Arjun thread count.")
    parser.add_argument("--rate", type=int, help="Optional request rate limit.")
    parser.add_argument("--stable", action="store_true", help="Enable Arjun stable mode.")
    parser.add_argument("--passive", action="store_true", help="Enable Arjun passive mode.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw Arjun argument.")
    parser.add_argument("--arjun-binary", default="arjun", help="Path to arjun binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if not args.authorized:
        emit({"ok": False, "error": {"type": "authorization_required", "message": "Pass --authorized only after confirming scope."}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 2

    targets = load_targets(args)
    if not targets:
        emit({"ok": False, "error": {"type": "missing_targets", "message": "Provide --target or --input."}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 2
    if shutil.which(args.arjun_binary) is None:
        emit({"ok": False, "error": {"type": "binary_not_found", "message": f"arjun binary not found: {args.arjun_binary}"}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 127

    with tempfile.TemporaryDirectory(prefix="arjun-json-") as tmpdir:
        arjun_output = Path(tmpdir) / "arjun.json"
        input_path = None
        if len(targets) > 1:
            input_path = Path(tmpdir) / "targets.txt"
            input_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
        command = build_command(args, targets, arjun_output, input_path)
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=args.timeout)
        except subprocess.TimeoutExpired as exc:
            emit({"ok": False, "error": {"type": "timeout", "message": f"arjun exceeded {args.timeout} seconds"}, "command": exc.cmd, "stdout": exc.stdout, "stderr": exc.stderr, "started_at": started_at, "finished_at": utc_now()}, args.output)
            return 124
        if arjun_output.exists() and arjun_output.stat().st_size > 0:
            try:
                result: Any = json.loads(arjun_output.read_text(encoding="utf-8"))
                parse_error = None
            except json.JSONDecodeError as exc:
                result = None
                parse_error = str(exc)
        else:
            result = None
            parse_error = "arjun did not produce JSON output"

    payload = {
        "ok": completed.returncode == 0 and parse_error is None,
        "tool": "arjun",
        "started_at": started_at,
        "finished_at": utc_now(),
        "targets": targets,
        "command": command,
        "returncode": completed.returncode,
        "result": result,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if parse_error:
        payload["error"] = {"type": "json_parse_error", "message": parse_error}
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
