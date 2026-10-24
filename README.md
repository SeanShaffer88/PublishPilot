## TL;DR

PublishPilot is a zero-dependency Python 3 CLI that catches the ways publishing
text files to GitHub has actually gone wrong — base64 blobs landing in a repo,
oversized files blowing the OS argument limit, CRLF files silently rewritten,
executable bits dropped by the API, and workflow files the GitHub App cannot
write — *before* you publish, then proves a publish landed by hash read-back.

## Features

- **`check`** — preflight rules for every file: binary / non-UTF-8 refusal,
  JSON-encoded size limit (105,000 bytes) with split advice, base64-blob
  suspicion warning for source/text files, `.github/workflows/*` refusal,
  executable-bit warning, CRLF/LF/mixed classification, empty-file warning.
  Prints a table; exit code 1 on any refusal.
- **`manifest`** — JSON manifest per file: repo path, size, SHA-256, correct
  Git blob SHA-1 (`sha1("blob <len>\0" + bytes)`), line-ending type, and
  executable flag. Files are always read as bytes, so line endings are
  reported as they really are, never translated.
- **`verify`** — fetches each manifest entry back from
  `raw.githubusercontent.com` and compares SHA-256: `match`, `mismatch`, or
  `deferred` (network failures are deferred, never a crash).

Python 3.10+, standard library only, no dependencies.

## Usage

```sh
# Preflight individual files
python3 publishpilot.py check publishpilot.py README.md

# Preflight everything tracked by git in a repo
python3 publishpilot.py check --root /path/to/repo --files-from git
python3 publishpilot.py check --root /path/to/repo --files-from git-tree

# Build a manifest (stdout, or --out to a file)
python3 publishpilot.py manifest --root /path/to/repo --out manifest.json
python3 publishpilot.py manifest --root /path/to/repo --files-from git-tree

# Verify a published repo against a manifest
python3 publishpilot.py verify --manifest manifest.json --owner OWNER --repo REPO
python3 publishpilot.py verify --manifest manifest.json --owner OWNER --repo REPO --branch main
```

Exit codes: `check` and `verify` exit 1 on refusals / mismatches, 0 otherwise,
2 on usage or I/O errors. Warnings do not fail `check` — review them.

## Why each rule exists

| Rule | Why |
|---|---|
| Plain content only — base64-blob suspicion warning | The GitHub Contents API takes plain file content. Pre-base64-encoding it once landed an entire repo as unreadable base64 blobs, repaired by re-uploading everything as plain text. |
| JSON-encoded size ≤ 105,000 bytes (refusal) | Content is passed as a single argument; the OS caps one argument at 131,072 bytes. A 132 KB source file failed with “Argument list too long” and had to be split into modules. The 105,000 limit keeps a safe margin. |
| Read bytes, preserve newlines (CRLF/LF info) | Python's default text-mode read translates CRLF → LF, so publishing a CRLF file that way silently rewrites every line ending. PublishPilot reads bytes and reports the true classification. |
| Executable-bit warning | API publishing drops the execute bit — files land as mode 100644 regardless of local permissions. CI that runs `./script.sh` then fails with “Permission denied”; CI must invoke scripts as `sh ./script.sh`. |
| `.github/workflows/*` refusal | The GitHub App has no Workflows permission and gets a 403 on workflow paths. Workflow files must be added through the GitHub web UI. |
| Blob-SHA / SHA-256 read-back (`manifest` + `verify`) | Transport hiccups have landed files silently or not at all. A publish is only proven when the remote bytes hash to the same value as the local bytes. |
| Binary / non-UTF-8 refusal | These checks, the size math, and line-ending rules only make sense for text. Refusing early is safer than mangling a binary file. |
| Empty-file warning | Empty files are usually a truncated write or a placeholder that slipped in; worth a human look before publishing. |

## Limitations

- **Text files only.** Binary files are refused by `check`, by design.
- **`verify` needs network access** to `raw.githubusercontent.com`; without
  it every entry is reported `deferred`, which is not treated as a failure.
- `verify` checks the branch tip at fetch time; a mismatch can also mean the
  file changed after the manifest was built.
- Base64 detection is a heuristic warning, not a proof: a file that genuinely
  *is* base64 data with a text extension will be flagged for a human to confirm.
- PublishPilot does not publish anything itself. It checks before, and
  verifies after, a publish done by other tooling.

## Development

```sh
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
