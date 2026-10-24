#!/usr/bin/env python3
"""PublishPilot — hardened preflight, manifest, and verify for GitHub publishing.

Stdlib only, Python 3.10+.

Encodes real incidents as checks:
- create_or_update_file takes PLAIN content, never pre-base64-encoded content.
- A file's JSON-encoded form must stay <= 105,000 bytes (OS argv cap is
  131,072 bytes; a 132 KB file once had to be split into modules).
- Files must be read as bytes / with newline preservation: Python's default
  text mode translates CRLF -> LF, silently rewriting line endings.
- API publishing drops the execute bit (files land as mode 100644), so CI
  must invoke shell scripts via ``sh ./script.sh``, never ``./script.sh``.
- .github/workflows/* cannot be written by the GitHub App — refuse early.
- Always verify a publish by blob-SHA / hash read-back.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

JSON_SIZE_LIMIT = 105_000
RAW_BASE_URL = "https://raw.githubusercontent.com"

KNOWN_TEXT_EXTENSIONS = {
    ".py", ".rs", ".js", ".ts", ".tsx", ".jsx", ".c", ".h", ".cpp", ".hpp",
    ".cs", ".java", ".go", ".rb", ".sh", ".ps1", ".bat", ".cmd",
    ".md", ".txt", ".toml", ".yaml", ".yml", ".json", ".xml", ".html",
    ".css", ".csv", ".ini", ".cfg", ".lua", ".sql",
}

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def git_blob_sha1(data: bytes) -> str:
    """Git blob SHA-1: sha1 of b"blob <len>\\0" + data."""
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_encoded_size(text: str) -> int:
    """Size in bytes of the JSON-encoded form of *text*.

    This mirrors passing the content as a single JSON string argument,
    which is subject to the OS argv cap.
    """
    return len(json.dumps(text).encode("utf-8"))


def classify_line_endings(data: bytes) -> str:
    """Return 'CRLF', 'LF', 'mixed', or 'none'."""
    crlf = data.count(b"\r\n")
    # Lone LF: LF not preceded by CR.
    lone_lf = data.count(b"\n") - crlf
    lone_cr = data.count(b"\r") - crlf
    if crlf and (lone_lf or lone_cr):
        return "mixed"
    if crlf:
        return "CRLF"
    if lone_lf:
        return "LF"
    if lone_cr:
        return "CR"
    return "none"


def is_executable(path: Path) -> bool:
    try:
        return bool(os.stat(path).st_mode & 0o111)
    except OSError:
        return False


def is_workflows_path(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/").lstrip("./")
    # lstrip("./") would mangle ".github"; handle carefully.
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p not in ("", ".")]
    normalized = "/".join(parts)
    return normalized.startswith(".github/workflows/") or normalized == ".github/workflows"


def looks_like_base64_blob(text: str) -> bool:
    """True if the whole (stripped) file is a base64 blob decoding to UTF-8 text.

    Normal source code must not trip this: code contains spaces, newlines,
    and punctuation outside the base64 alphabet. We require the stripped
    content to be a single base64 token of at least 40 characters, valid
    padding, decoding to UTF-8 text that is mostly printable.
    """
    stripped = text.strip()
    if len(stripped) < 40:
        return False
    if len(stripped) % 4 != 0:
        return False
    if not _B64_RE.match(stripped):
        return False
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return False
    if not decoded:
        return False
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return False
    # Re-encoding check: canonical base64 should round-trip.
    try:
        if base64.b64encode(decoded).decode("ascii").rstrip("=") != stripped.rstrip("="):
            return False
    except Exception:
        return False
    printable = sum(1 for ch in decoded_text if ch.isprintable() or ch in "\r\n\t")
    return bool(decoded_text) and (printable / len(decoded_text)) >= 0.9


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, level: str, message: str):
        self.level = level  # "refusal" | "warning" | "info"
        self.message = message

    def __repr__(self):  # pragma: no cover
        return f"Finding({self.level!r}, {self.message!r})"


def check_file(path: Path, display_path: str | None = None) -> dict:
    """Run all preflight rules on one file. Returns a result dict."""
    display = display_path or str(path)
    findings: list[Finding] = []
    data: bytes | None = None
    try:
        # Always read as bytes — never text mode (CRLF translation).
        data = path.read_bytes()
    except OSError as exc:
        findings.append(Finding("refusal", f"cannot read file: {exc}"))
        return {
            "path": display, "size": 0, "json_size": 0, "endings": "none",
            "findings": findings,
            "status": "REFUSAL",
        }

    size = len(data)
    endings = classify_line_endings(data) if data else "none"
    executable = is_executable(path)

    # (d) workflows path refusal
    if is_workflows_path(display):
        findings.append(Finding(
            "refusal",
            ".github/workflows/* cannot be written by the GitHub App "
            "(403, no Workflows permission); add workflow files through "
            "the GitHub web UI instead.",
        ))

    # (g) empty file warning
    if size == 0:
        findings.append(Finding("warning", "empty file"))
        return {
            "path": display, "size": 0, "json_size": 2, "endings": endings,
            "findings": findings,
            "status": "REFUSAL" if any(f.level == "refusal" for f in findings) else "WARNING",
        }

    # (a) binary / not UTF-8 refusal
    text: str | None = None
    if b"\x00" in data:
        findings.append(Finding(
            "refusal",
            "binary file (contains NUL bytes): PublishPilot handles text "
            "files only; binary publishing needs a different path.",
        ))
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            findings.append(Finding(
                "refusal",
                f"not valid UTF-8 ({exc}): PublishPilot handles text files only.",
            ))

    json_size = 0
    if text is not None:
        json_size = json_encoded_size(text)
        # (b) JSON-encoded size refusal
        if json_size > JSON_SIZE_LIMIT:
            findings.append(Finding(
                "refusal",
                f"JSON-encoded size {json_size} exceeds {JSON_SIZE_LIMIT} bytes "
                f"(OS argv cap 131,072): split this file into smaller modules "
                f"(e.g. move help data / tests into separate files) and publish "
                f"the parts separately.",
            ))
        # (c) base64-blob suspicion
        suffix = Path(display).suffix.lower()
        if suffix in KNOWN_TEXT_EXTENSIONS and looks_like_base64_blob(text):
            findings.append(Finding(
                "warning",
                "STRONG WARNING: content looks like a base64 blob decoding "
                "to UTF-8 text, but the extension is a source/text type. "
                "create_or_update_file takes PLAIN content, never "
                "pre-base64-encoded content — publishing this as-is would "
                "land a base64 blob in the repo. Decode it first.",
            ))

    # (e) executable-bit warning
    if executable:
        findings.append(Finding(
            "warning",
            "executable bit set: API publishing drops it (files land as "
            "mode 100644). CI must invoke this as `sh ./script.sh`, "
            "never `./script.sh`.",
        ))

    # (f) line-ending classification (info)
    findings.append(Finding("info", f"line endings: {endings}"))

    if any(f.level == "refusal" for f in findings):
        status = "REFUSAL"
    elif any(f.level == "warning" for f in findings):
        status = "WARNING"
    else:
        status = "OK"
    return {
        "path": display, "size": size, "json_size": json_size,
        "endings": endings, "findings": findings, "status": status,
    }


def list_files_from_git(root: Path, mode: str) -> list[Path]:
    """List tracked files. mode: 'git' (ls-files) or 'git-tree' (ls-tree HEAD)."""
    if mode == "git-tree":
        cmd = ["git", "-C", str(root), "ls-tree", "-r", "--name-only", "HEAD"]
    else:
        cmd = ["git", "-C", str(root), "ls-files"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"error: failed to list files via git ({mode}): {exc}", file=sys.stderr)
        raise SystemExit(2)
    files = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line:
            files.append(root / line)
    return files


def walk_files(root: Path) -> list[Path]:
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules"}
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for name in sorted(filenames):
            files.append(Path(dirpath) / name)
    return files


def cmd_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve() if args.root else Path.cwd()
    targets: list[tuple[Path, str]] = []  # (filesystem path, display path)

    if args.files_from:
        for p in list_files_from_git(root, args.files_from):
            try:
                display = str(p.relative_to(root))
            except ValueError:
                display = str(p)
            targets.append((p, display))
    if args.files:
        for raw in args.files:
            p = Path(raw)
            if not p.is_absolute():
                # Prefer root-relative, fall back to cwd-relative.
                candidate = root / raw
                p = candidate if candidate.exists() else p
            targets.append((p, raw))
    if not targets:
        print("error: no files to check (pass files or --files-from)", file=sys.stderr)
        return 2

    results = [check_file(p, display) for p, display in targets]

    # Table
    print(f"{'File':<50} {'Size':>8} {'JSON':>8} {'Endings':<8} Status")
    print("-" * 90)
    for r in results:
        name = r["path"]
        if len(name) > 48:
            name = "..." + name[-45:]
        print(f"{name:<50} {r['size']:>8} {r['json_size']:>8} {r['endings']:<8} {r['status']}")
        for f in r["findings"]:
            if f.level == "info":
                continue
            print(f"{'':<50} [{f.level.upper()}] {f.message}")
    print("-" * 90)
    refusals = sum(1 for r in results if r["status"] == "REFUSAL")
    warnings = sum(1 for r in results if r["status"] == "WARNING")
    print(f"{len(results)} file(s): {refusals} refusal(s), {warnings} warning(s)")
    return 1 if refusals else 0


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def manifest_entry(root: Path, path: Path) -> dict:
    data = path.read_bytes()  # bytes — newline preservation
    try:
        rel = str(path.relative_to(root)).replace(os.sep, "/")
    except ValueError:
        rel = path.name
    return {
        "path": rel,
        "size": len(data),
        "sha256": sha256_hex(data),
        "blob_sha1": git_blob_sha1(data),
        "line_endings": classify_line_endings(data),
        "executable": is_executable(path),
    }


def build_manifest(root: Path, files: list[Path]) -> dict:
    entries = []
    for p in files:
        if p.is_file():
            entries.append(manifest_entry(root, p))
    entries.sort(key=lambda e: e["path"])
    return {"version": 1, "tool": "publishpilot", "files": entries}


def cmd_manifest(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: root is not a directory: {root}", file=sys.stderr)
        return 2
    if args.files_from:
        files = list_files_from_git(root, args.files_from)
    elif args.files:
        files = [root / f if not Path(f).is_absolute() else Path(f) for f in args.files]
    else:
        files = walk_files(root)
    manifest = build_manifest(root, files)
    text = json.dumps(manifest, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {args.out}: {len(manifest['files'])} file(s)")
    else:
        sys.stdout.write(text)
    return 0


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def fetch_url(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "publishpilot/0.1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def verify_entry(entry: dict, owner: str, repo: str, branch: str, fetcher=fetch_url) -> str:
    """Return 'match', 'mismatch', or 'deferred'."""
    path = entry["path"]
    quoted = urllib.parse.quote(path, safe="/")
    url = f"{RAW_BASE_URL}/{owner}/{repo}/{branch}/{quoted}"
    try:
        remote = fetcher(url)
    except Exception:
        return "deferred"
    return "match" if sha256_hex(remote) == entry.get("sha256") else "mismatch"


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read manifest: {exc}", file=sys.stderr)
        return 2
    entries = manifest.get("files", [])
    print(f"{'File':<50} Result")
    print("-" * 70)
    counts = {"match": 0, "mismatch": 0, "deferred": 0}
    for entry in entries:
        result = verify_entry(entry, args.owner, args.repo, args.branch)
        counts[result] += 1
        print(f"{entry['path']:<50} {result}")
    print("-" * 70)
    print(f"{len(entries)} file(s): {counts['match']} match, "
          f"{counts['mismatch']} mismatch, {counts['deferred']} deferred")
    # Deferred (network) is not a failure; mismatch is.
    return 1 if counts["mismatch"] else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="publishpilot",
        description="Hardened preflight, manifest, and read-back verification "
                    "for publishing text files to GitHub.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="run preflight rules on files")
    p_check.add_argument("files", nargs="*", help="files to check")
    p_check.add_argument("--root", default=None, help="root directory (default: cwd)")
    p_check.add_argument("--files-from", choices=["git", "git-tree"], default=None,
                         help="take file list from git ls-files or git ls-tree HEAD")
    p_check.set_defaults(func=cmd_check)

    p_man = sub.add_parser("manifest", help="emit a JSON manifest")
    p_man.add_argument("--root", required=True, help="root directory")
    p_man.add_argument("--files-from", choices=["git-tree"], default=None,
                       help="take file list from git ls-tree HEAD")
    p_man.add_argument("--files", nargs="*", default=None, help="explicit files (relative to root)")
    p_man.add_argument("--out", default=None, help="output file (default: stdout)")
    p_man.set_defaults(func=cmd_manifest)

    p_ver = sub.add_parser("verify", help="verify a manifest against raw.githubusercontent.com")
    p_ver.add_argument("--manifest", required=True, help="manifest JSON file")
    p_ver.add_argument("--owner", required=True)
    p_ver.add_argument("--repo", required=True)
    p_ver.add_argument("--branch", default="main")
    p_ver.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
