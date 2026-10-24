# Changelog

## 0.1.0 — 2026-10-24

- Initial release.
- `check` subcommand: preflight rules for binary / non-UTF-8 files,
  JSON-encoded size over 105,000 bytes, base64-blob suspicion,
  `.github/workflows/*` paths, executable bits, line-ending classification,
  and empty files, with `--root` and `--files-from git|git-tree`.
- `manifest` subcommand: per-file path, size, SHA-256, Git blob SHA-1,
  line-ending type, and executable flag, with `--files-from git-tree`.
- `verify` subcommand: SHA-256 read-back comparison against
  `raw.githubusercontent.com`, with network failures reported as `deferred`.
- Test suite covering the size limit, binary and workflows refusals,
  base64 detection (positive and negative), the Git blob SHA formula,
  CRLF detection, manifest generation, and verify outcomes.
