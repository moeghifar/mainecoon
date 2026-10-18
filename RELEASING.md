# Releasing mainecoon

## First release (v0.1.0)

The local repo is already initialised on `main` with `origin = git@github.com:moeghifar/mainecoon.git`
and no commits yet.

1. **Create the GitHub repo** (skip if it exists): github.com/new → owner `moeghifar`, name
   `mainecoon`, **Public** (so `go get` works without GOPRIVATE), no README/licence/gitignore
   (they are in this repo).
2. **Verify locally** (Go 1.27, latest patch):
   ```sh
   cd ~/Code/github/moeghifar/mainecoon
   go mod verify && go vet ./... && go test -race ./...
   GODEBUG=fips140=only go test -run TestFIPSOnlyModule ./kat
   golangci-lint run ./...   # v2.15.0, config in .golangci.yml
   go run golang.org/x/vuln/cmd/govulncheck@latest ./...
   ```
3. **Check what will be committed** (`.specify/` and `.claude/` are ignored):
   ```sh
   git status --short
   ```
4. **Push the root commit and the release branch, open the PR** (`main` holds only
   LICENSE/NOTICE/.gitignore; the code arrives through `release/v0.1.0`):
   ```sh
   git push -u origin main
   git push -u origin release/v0.1.0
   gh pr create --base main --head release/v0.1.0 --title "release: v0.1.0" --body-file CHANGELOG.md
   ```
5. **Wait for CI** (`ci` / `test`) to go green on the PR, then merge it (merge commit or
   squash) and `git checkout main && git pull`.
6. **Repo settings** on GitHub:
   - Settings → Branches → protect `main` (require PR + status check `test`).
   - Settings → Code security → enable **Private vulnerability reporting**, Dependabot alerts.
7. **Tag** (annotated; signed with `-s` if you have a GPG/SSH signing key):
   ```sh
   git tag -a v0.1.0 -m "v0.1.0"      # or: git tag -s v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
8. **GitHub release:** Releases → Draft new release → tag `v0.1.0` → paste the `0.1.0` section of
   CHANGELOG.md → Publish.
9. **Warm the Go proxy and check it resolves:**
   ```sh
   GOPROXY=https://proxy.golang.org GO111MODULE=on go list -m github.com/moeghifar/mainecoon@v0.1.0
   ```
10. **Switch xandi to the tag:** in xandi, remove the `replace github.com/moeghifar/mainecoon => ...`
    line, then `go get github.com/moeghifar/mainecoon@v0.1.0 && go mod tidy && go test ./...`.

## Later releases

1. Update CHANGELOG.md (new section, link at the bottom).
2. PR → CI green → merge to `main`.
3. `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`, then the GitHub release.
4. Never move or delete a pushed tag; the Go checksum database has recorded it. Fix forward with a new patch version (use `retract` in go.mod for a bad one).
