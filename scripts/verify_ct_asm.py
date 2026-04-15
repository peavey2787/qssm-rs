#!/usr/bin/env python3
"""
Hard gate for constant-time assembly inspection.

1) Builds qssm-le in release and emits assembly.
2) Locates ct_reject_if_above_gamma symbol body.
3) Fails if any conditional branch (jcc) instruction appears in the symbol body.

`cmov*` is allowed.
"""

from __future__ import annotations

import glob
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable


TARGET_SYMBOL = "ct_reject_if_above_gamma"
TARGET_CRATE = "qssm-le"

# Any jcc instruction (je/jne/jg/jl/ja/jb/...) is forbidden.
# Unconditional jmp is not treated as jcc here.
JCC_RE = re.compile(r"^\s*j(?!mp\b)[a-z]{1,3}\b", re.IGNORECASE)


def run_emit_asm() -> list[Path]:
    for stale in glob.glob("target/release/deps/qssm_le-*.s"):
        try:
            Path(stale).unlink()
        except OSError:
            pass
    for stale in glob.glob("target/release/deps/**/*.s", recursive=True):
        if "qssm_le-" in Path(stale).name:
            try:
                Path(stale).unlink()
            except OSError:
                pass

    cmd = [
        "cargo",
        "rustc",
        "-p",
        TARGET_CRATE,
        "--release",
        "--lib",
        "--message-format",
        "json",
        "--",
        "-C",
        "save-temps",
        "--emit",
        "asm",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    emitted: list[Path] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("reason") != "compiler-artifact":
            continue
        target = payload.get("target", {})
        if target.get("name") != "qssm_le":
            continue
        for filename in payload.get("filenames", []):
            if str(filename).endswith(".s"):
                emitted.append(Path(filename))
    return sorted(set(emitted))


def candidate_asm_files() -> list[Path]:
    patterns = ["target/release/deps/qssm_le-*.s", "target/release/deps/**/qssm_le-*.s"]
    out: list[Path] = []
    for pattern in patterns:
        for p in glob.glob(pattern, recursive=True):
            out.append(Path(p))
    # Deterministic order for stable CI logs.
    return sorted(set(out))


def is_symbol_label(line: str, symbol: str) -> bool:
    s = line.strip()
    return s.endswith(":") and (symbol in s)


def is_nonlocal_label(line: str) -> bool:
    s = line.strip()
    if not s.endswith(":"):
        return False
    # Local labels in GNU-style asm often start with ".L".
    return not s.startswith(".L")


def extract_symbol_body(lines: list[str], start_idx: int) -> tuple[int, int]:
    """
    Return [start, end) line indices for symbol body.
    """
    i = start_idx + 1
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith(".cfi_endproc"):
            return (start_idx + 1, i)
        # Stop at next non-local label if we didn't get cfi markers.
        if is_nonlocal_label(lines[i]):
            return (start_idx + 1, i)
        i += 1
    return (start_idx + 1, len(lines))


def jcc_violations(body: Iterable[tuple[int, str]]) -> list[tuple[int, str]]:
    bad: list[tuple[int, str]] = []
    for line_no, line in body:
        if JCC_RE.search(line):
            bad.append((line_no, line.rstrip("\n")))
    return bad


def main() -> int:
    asm_files = run_emit_asm()
    if not asm_files:
        asm_files = candidate_asm_files()
    if not asm_files:
        sys.stderr.write("No .s files found after `--emit asm`.\n")
        return 2

    symbol_hits = []
    violations: list[tuple[Path, int, str]] = []

    for asm_path in asm_files:
        try:
            content = asm_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = content.splitlines(keepends=True)
        for i, line in enumerate(lines):
            if not is_symbol_label(line, TARGET_SYMBOL):
                continue
            symbol_hits.append((asm_path, i + 1))
            start, end = extract_symbol_body(lines, i)
            body = ((ln + 1, lines[ln]) for ln in range(start, end))
            for ln, text in jcc_violations(body):
                violations.append((asm_path, ln, text))

    if not symbol_hits:
        sys.stderr.write(
            f"Did not find symbol label containing `{TARGET_SYMBOL}` in emitted assembly.\n"
        )
        return 3

    if violations:
        sys.stderr.write("Conditional branch instructions found in CT symbol body:\n")
        for path, ln, text in violations:
            sys.stderr.write(f"{path}:{ln}: {text}\n")
        return 4

    print(
        f"Assembly gate passed: `{TARGET_SYMBOL}` contains no jcc instructions in emitted body."
    )
    for path, ln in symbol_hits:
        print(f"  symbol hit: {path}:{ln}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
