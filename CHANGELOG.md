# Changelog

## 0.2.0 (2026-11-20)

OAuth 2.1 for HTTP servers that require a login. Most hosted skill servers do.

- `skillcourier auth login | status | logout`. Login uses authorization code + PKCE S256 over a 127.0.0.1 loopback redirect, with discovery via RFC 9728 protected resource metadata (from `WWW-Authenticate` or well-known) and RFC 8414 / OpenID metadata, dynamic client registration (RFC 7591) or `--client-id`, the `resource` indicator (RFC 8707) on both legs, and the `iss` check (RFC 9207).
- Refuses: resource metadata for another URL, an issuer mismatch, no S256, non-HTTPS endpoints outside loopback, state mismatch, wrong `iss`.
- Tokens live in one 0600 file keyed by canonical server URL and are sent only to that server. They refresh before expiry and on 401, keep rotated refresh tokens, and drop refused ones. `403 insufficient_scope` triggers a step-up login.
- Interactive commands log in on demand. `check --hook`, CI, pipes and `--no-login` never open a browser; they print the exact `auth login` command instead.
- `dev-server --http PORT --oauth`: a strict, auto-approving mock authorization server, for testing your own client or server setup.
- `check --hook` names the servers that need a login.
- A configured `Authorization` header still wins over OAuth.

## 0.1.0 (2026-11-20)

First release.

- MCP client over stdio and Streamable HTTP: protocol 2026-07-28 (`server/discover`, per-request `_meta`, metadata headers with base64 `Mcp-Name`), with the spec's legacy `initialize` fallback.
- SEP-2640 entry validation and verification: complete manifests, containment, case collisions, 512-file / 16 MiB limits, size + SHA-256 per file, frontmatter field-by-field.
- Import into `.claude/skills`, `~/.claude/skills`, `.agents/skills`, `~/.agents/skills` or any directory, with per-origin names, an origin-tagged description, provenance metadata, and `allowed-tools`/`hooks` stripped unless `--grant-tools`.
- `.skillcourier-lock.json` binds approval to (server label, uri) and the full resource set; `check` / `sync` revoke and re-prompt on any change, and restore missing or locally edited files.
- Server discovery from Claude Code (local, project, user scope) and Codex config, with `${VAR}` expansion that never writes secrets to disk.
- `dev-server`: a small spec-conformant server for a local skills folder.
- `check --hook` for a SessionStart warning when anything drifted.
