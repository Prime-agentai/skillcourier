# Changelog

## 0.1.0 (2026-11-20)

First release.

- MCP client over stdio and Streamable HTTP: protocol 2026-07-28 (`server/discover`, per-request `_meta`, metadata headers with base64 `Mcp-Name`), with the spec's legacy `initialize` fallback.
- SEP-2640 entry validation and verification: complete manifests, containment, case collisions, 512-file / 16 MiB limits, size + SHA-256 per file, frontmatter field-by-field.
- Import into `.claude/skills`, `~/.claude/skills`, `.agents/skills`, `~/.agents/skills` or any directory, with per-origin names, an origin-tagged description, provenance metadata, and `allowed-tools`/`hooks` stripped unless `--grant-tools`.
- `.skillcourier-lock.json` binds approval to (server label, uri) and the full resource set; `check` / `sync` revoke and re-prompt on any change, and restore missing or locally edited files.
- Server discovery from Claude Code (local, project, user scope) and Codex config, with `${VAR}` expansion that never writes secrets to disk.
- `dev-server`: a small spec-conformant server for a local skills folder.
- `check --hook` for a SessionStart warning when anything drifted.
