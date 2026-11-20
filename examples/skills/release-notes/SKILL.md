---
name: release-notes
description: Draft release notes from merged pull requests. Use when the user asks for a changelog, release notes or a "what shipped" summary.
license: MIT
updated: 2026-11-01
metadata:
  version: "1.2"
---

# Release notes

1. List merged PRs since the last tag (`git log --merges <tag>..HEAD`).
2. Group them with the headings in [templates/notes.md](templates/notes.md).
3. One line per change, user-facing wording, no PR jargon.
