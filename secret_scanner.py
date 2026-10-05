"""Local-only educational scanner for common accidentally committed secrets."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Pattern

DEFAULT_IGNORES = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
MAX_FILE_SIZE = 1_000_000


@dataclass(frozen=True)
class Rule:
    name: str
    expression: Pattern[str]


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    rule: str
    preview: str


RULES = (
    Rule("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Rule("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    Rule("private key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    Rule("assignment with likely secret", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*[\"']?[^\s\"']{8,}"
    )),
)


def is_probably_text(path: Path) -> bool:
    """Return false for binary-looking files without trusting a filename suffix."""
    try:
        with path.open("rb") as handle:
            sample = handle.read(4096)
    except OSError:
        return False
    return b"\x00" not in sample


def mask(value: str) -> str:
    """Redact a match so console logs do not repeat a potential secret."""
    compact = " ".join(value.split())
    if len(compact) <= 8:
        return "*" * len(compact)
    return f"{compact[:4]}…{compact[-4:]}"


def iter_candidate_files(root: Path, ignores: set[str] = DEFAULT_IGNORES) -> Iterator[Path]:
    for path in root.rglob("*"):
        if any(part in ignores for part in path.parts):
            continue
        try:
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_FILE_SIZE and is_probably_text(path):
                yield path
        except OSError:
            continue


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings
    for number, line in enumerate(lines, start=1):
        for rule in RULES:
            match = rule.expression.search(line)
            if match:
                findings.append(Finding(path, number, rule.name, mask(match.group(0))))
    return findings


def scan(root: Path, ignores: Iterable[str] = ()) -> list[Finding]:
    ignore_set = DEFAULT_IGNORES | set(ignores)
    findings: list[Finding] = []
    for path in iter_candidate_files(root, ignore_set):
        findings.extend(scan_file(path))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="只在本机扫描授权目录中的疑似敏感信息")
    parser.add_argument("directory", type=Path, help="要扫描的本地目录")
    parser.add_argument("--ignore", action="append", default=[], metavar="NAME", help="忽略的目录名，可重复")
    parser.add_argument("--fail-on-findings", action="store_true", help="发现疑似敏感信息时返回退出码 1")
    args = parser.parse_args()
    if not args.directory.is_dir():
        print(f"错误：目录不存在：{args.directory}")
        return 2
    findings = scan(args.directory, args.ignore)
    if not findings:
        print("未发现匹配项。请注意：这不代表目录绝对不存在敏感信息。")
        return 0
    for item in findings:
        try:
            relative = item.path.relative_to(args.directory)
        except ValueError:
            relative = item.path
        print(f"{relative}:{item.line} [{item.rule}] {item.preview}")
    print(f"发现 {len(findings)} 个疑似敏感信息匹配项（输出已脱敏）。")
    return 1 if args.fail_on_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
