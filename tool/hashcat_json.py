#!/usr/bin/env python3
"""
hashcat JSON wrapper for authorized offline password hash cracking.

Supports dictionary, mask (brute-force), rule-based, and combinator attacks.
Wraps hashcat's native --status-json and --outfile-json for structured output.

Hash mode shortcuts (common pentest values):
  MD5=0  SHA1=100  NTLM=1000  SHA2-256=1400  sha512crypt=1800
  bcrypt=3200  WPA2=22000  Kerberos-TGS=13100  NetNTLMv2=5600

Examples:
  # Dictionary attack on an NTLM hash
  ./tool/hashcat_json.py --authorized -m 1000 -a 0 --hash 'aad3b435b51404eeaad3b435b51404ee:...' --wordlist rockyou.txt

  # Show previously cracked hashes from potfile
  ./tool/hashcat_json.py --authorized --hash-file hashes.txt --show

  # Mask attack: 8-char lowercase + digits
  ./tool/hashcat_json.py --authorized -m 0 -a 3 --hash-file hashes.txt --mask '?l?l?l?l?l?l?d?d'

  # Dictionary + rules, CPU only, light workload
  ./tool/hashcat_json.py --authorized -m 1000 -a 0 --hash-file hashes.txt --wordlist rockyou.txt --rules best64.rule --cpu --workload 1
"""

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


DEFAULT_TIMEOUT = 7200  # 2 hours — hash cracking can take a long time
DEFAULT_WORKLOAD = 2    # 1=low, 2=default, 3=high, 4=nightmare


# Common hash modes for pentesting
HASH_MODE_SHORTCUTS: dict[str, int] = {
    "md5": 0,
    "sha1": 100,
    "ntlm": 1000,
    "sha256": 1400,
    "sha2-256": 1400,
    "sha512crypt": 1800,
    "bcrypt": 3200,
    "cisco-asa": 500,
    "kerberos-tgs": 13100,
    "kerberos-asrep": 18200,
    "netntlmv2": 5600,
    "wpa2": 22000,
    "7zip": 11600,
    "rar5": 13000,
    "pdf": 10500,
    "md5crypt": 500,
    "descrypt": 1500,
    "mysql": 300,
    "postgres": 12,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def resolve_hash_mode(raw: str) -> int:
    """Accept either a numeric hash mode or a shortcut name."""
    lower = raw.strip().lower()
    if lower in HASH_MODE_SHORTCUTS:
        return HASH_MODE_SHORTCUTS[lower]
    try:
        return int(raw)
    except ValueError:
        valid = ", ".join(sorted(HASH_MODE_SHORTCUTS.keys()))
        raise SystemExit(f"Unknown hash mode: {raw}. Use a number or shortcut: {valid}")


def hex_decode(value: str) -> str:
    """Decode a hex-encoded string from hashcat --outfile-json."""
    try:
        return bytes.fromhex(value).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return value


def parse_show_output(stdout: str) -> list[dict[str, Any]]:
    """Parse hashcat --show / --left text output.

    --show format: hash:plain
    --left format: hash  (uncracked, no password separator)
    """
    results: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            results.append({"hash": parts[0], "password": parts[1]})
        elif len(parts) == 1 and len(parts[0]) >= 32:
            # --left mode: just the hash line (uncracked)
            results.append({"hash": parts[0], "password": None, "cracked": False})
        else:
            results.append({"_parse_error": True, "_raw": line[:200]})
    return results


def parse_outfile_json(path: Path) -> list[dict[str, Any]]:
    """Parse hashcat --outfile-json lines into a list.

    hashcat --outfile-json encodes hash and password fields as hex strings.
    This function decodes them into human-readable plaintext.
    """
    if not path.exists() or path.stat().st_size == 0:
        return []
    results: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            results.append({"_parse_error": True, "_raw": line[:200]})
            continue
        # Decode hex-encoded fields
        decoded: dict[str, Any] = {}
        for key, value in obj.items():
            if isinstance(value, str) and key.endswith("_hex"):
                base_key = key[:-4]  # strip "_hex"
                decoded[base_key] = hex_decode(value)
            else:
                decoded[key] = value
        results.append(decoded)
    return results


def parse_status_lines(stdout: str) -> dict[str, Any]:
    """Extract the last valid JSON status line from hashcat stdout."""
    last_status: dict[str, Any] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            # hashcat --status-json lines contain a 'session' or 'status' key
            if isinstance(obj, dict) and any(k in obj for k in ("session", "status", "progress", "time_start")):
                last_status = obj
        except json.JSONDecodeError:
            continue
    return last_status


def build_command(args: argparse.Namespace, outfile: Path) -> list[str]:
    command = [
        args.hashcat_binary,
        "-m", str(args.hash_mode),
    ]
    # --show / --left mode: no attack params, output goes to stdout
    if args.show or args.left:
        command.extend(["--potfile-path", str(args.potfile_path)])
        if args.show:
            command.append("--show")
        if args.left:
            command.append("--left")
        if args.username:
            command.append("--username")
        if args.force:
            command.append("--force")
        for extra_arg in args.extra_arg:
            command.append(extra_arg)
        if args.hash:
            command.append(args.hash)
        elif args.hash_file:
            command.append(args.hash_file)
        return command

    # Normal cracking mode
    command.extend([
        "-a", str(args.attack_mode),
        "-w", str(args.workload),
        "--status",
        "--status-json",
        "--status-timer", str(args.status_timer),
        "--outfile", str(outfile),
        "--outfile-json",
        "--potfile-path", str(args.potfile_path),
    ])
    if args.optimized:
        command.append("-O")
    if args.device_type == "gpu":
        command.extend(["-D", "2"])
    elif args.device_type == "cpu":
        command.extend(["-D", "1"])
    if args.rules:
        command.extend(["-r", args.rules])
    if args.mask:
        command.append(args.mask)
    if args.increment:
        command.append("--increment")
        if args.increment_min:
            command.extend(["--increment-min", str(args.increment_min)])
        if args.increment_max:
            command.extend(["--increment-max", str(args.increment_max)])
    if args.loopback:
        command.append("--loopback")
    if args.username:
        command.append("--username")
    if args.force:
        command.append("--force")
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    # The target: hash string or hash file
    if args.hash:
        command.append(args.hash)
    elif args.hash_file:
        command.append(args.hash_file)
    # Wordlist
    if args.wordlist:
        command.append(args.wordlist)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run hashcat and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--hash", "-H", help="Single hash string to crack (e.g. '5f4dcc3b5aa765d61d8327deb882cf99').")
    parser.add_argument("--hash-file", help="Path to a file containing hashes (one per line).")
    parser.add_argument("--show", action="store_true", help="Show already-cracked hashes from potfile (no cracking run).")
    parser.add_argument("--left", action="store_true", help="Show uncracked hashes from hash list vs potfile.")
    parser.add_argument("--wordlist", "-w", help="Path to wordlist for dictionary attack (-a 0).")
    parser.add_argument("--mask", help="Mask for brute-force attack (-a 3), e.g. '?l?l?l?l?d?d'.")
    parser.add_argument("--rules", "-r", help="Path to rules file (e.g. best64.rule).")
    parser.add_argument("--output", "-o", help="Optional normalized JSON output file.")
    parser.add_argument("--hash-mode", "-m", default="0", help="Hash type: number or shortcut (md5, ntlm, sha256, bcrypt, ...). Default: 0 (MD5)")
    parser.add_argument("--attack-mode", "-a", type=int, default=0, choices=[0, 1, 3, 6, 7],
                        help="Attack mode: 0=dictionary, 1=combinator, 3=brute-force/mask, 6=dict+mask, 7=mask+dict. Default: 0")
    parser.add_argument("--workload", type=int, default=DEFAULT_WORKLOAD, choices=[1, 2, 3, 4],
                        help="Workload profile: 1=low, 2=default, 3=high, 4=nightmare. Default: %(default)s")
    parser.add_argument("--device-type", choices=["gpu", "cpu"], default="gpu", help="Use GPU or CPU. Default: gpu")
    parser.add_argument("--optimized", "-O", action="store_true", help="Enable optimized kernels (limits password length).")
    parser.add_argument("--increment", action="store_true", help="Enable incremental mode for mask attacks.")
    parser.add_argument("--increment-min", type=int, help="Minimum password length for incremental mode.")
    parser.add_argument("--increment-max", type=int, help="Maximum password length for incremental mode.")
    parser.add_argument("--loopback", action="store_true", help="Append new cracks to wordlist for further cracking.")
    parser.add_argument("--username", action="store_true", help="Ignore usernames in hash file.")
    parser.add_argument("--force", action="store_true", help="Ignore warnings (use with caution).")
    parser.add_argument("--status-timer", type=int, default=5, help="Seconds between status updates. Default: 5")
    parser.add_argument("--potfile-path", default=str(Path(tempfile.gettempdir()) / "hashcat-wrapper.potfile"),
                        help="Path to potfile. Default: temp dir")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw hashcat argument.")
    parser.add_argument("--hashcat-binary", default="hashcat", help="Path to hashcat binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if not args.authorized:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "authorization_required",
                    "message": "Pass --authorized only after confirming the target and hash source are in scope.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    # hashcat --show / --left only needs potfile + hash list, no attack params
    if not args.show and not args.left:
        if not args.hash and not args.hash_file:
            emit(
                {
                    "ok": False,
                    "error": {"type": "missing_input", "message": "Provide --hash or --hash-file (or use --show/--left)."},
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 2

    if shutil.which(args.hashcat_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"hashcat binary not found: {args.hashcat_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    try:
        args.hash_mode = resolve_hash_mode(args.hash_mode)
    except SystemExit as exc:
        emit(
            {
                "ok": False,
                "error": {"type": "invalid_hash_mode", "message": str(exc)},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    tmpdir = tempfile.mkdtemp(prefix="hashcat-json-")
    try:
        outfile = Path(tmpdir) / "hashcat.out"
        command = build_command(args, outfile)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            # Partial results may exist — read whatever was cracked so far
            partial = parse_outfile_json(outfile)
            status = parse_status_lines(exc.stdout or "")
            emit(
                {
                    "ok": False,
                    "error": {
                        "type": "timeout",
                        "message": f"hashcat exceeded {args.timeout} seconds — partial results captured.",
                    },
                    "command": exc.cmd,
                    "last_status": status,
                    "cracked": partial,
                    "cracked_count": len(partial),
                    "stdout": exc.stdout if exc.stdout else "",
                    "stderr": exc.stderr if exc.stderr else "",
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 124

        cracked = parse_outfile_json(outfile)
        status = parse_status_lines(completed.stdout)
        # --show / --left output goes to stdout, not outfile
        if args.show or args.left:
            cracked = parse_show_output(completed.stdout)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    payload = {
        "ok": completed.returncode in (0, 1),
        # hashcat returns 1 if some but not all hashes cracked — that's normal
        "tool": "hashcat",
        "started_at": started_at,
        "finished_at": utc_now(),
        "command": command,
        "returncode": completed.returncode,
        "hash_mode": args.hash_mode,
        "attack_mode": args.attack_mode,
        "device_type": args.device_type,
        "total_hashes_loaded": status.get("total_hashes", status.get("total_count", "unknown")),
        "cracked_count": len(cracked),
        "cracked": cracked,
        "last_status": status,
        "stderr": completed.stderr if completed.stderr else "",
    }
    if completed.returncode > 1:
        payload["ok"] = False
        payload["error"] = {
            "type": "hashcat_error",
            "message": f"hashcat exited with code {completed.returncode}",
            "stderr": completed.stderr,
        }
        # hashcat may write partial results even on error
    emit(payload, args.output)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
