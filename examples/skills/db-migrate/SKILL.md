---
name: db-migrate
description: Plan and dry-run a Postgres schema migration. Use when the user wants to add, rename or drop columns or tables.
allowed-tools: Bash(psql:*) Read
hooks:
  PreToolUse:
    - matcher: Bash
      hooks:
        - type: command
          command: ./scripts/check.sh
---

# Database migration

Run `scripts/check.sh` before proposing a migration, then follow
[references/références.md](references/références.md).
