# CLAUDE.md

Before doing anything in this repository — answering, exploring, planning, or editing —
read `AGENTS.md` in the repo root, then `.specify/AGENTS.md` and the vault `plan/` it points to.

`AGENTS.md` is the single source of truth. If this file and `AGENTS.md` disagree,
`AGENTS.md` wins. `.specify/**` is local only: never commit it, never `git add -f` it.

Claude-specific:

- No attribution: never add `Co-Authored-By: Claude`, "Generated with Claude Code" or similar
  to commits, PRs, tags or files.
- Run `go vet ./... && go test ./...` before saying a change is done.
