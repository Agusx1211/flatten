# Issues / Bugs

Collected on Linux (arm64) with Go `go1.25.5` by:
- Building with `make build`
- Running `go test ./...` and `go vet ./...`
- Manually exercising flags via the built `./bin/flatten`

## 8) `build.sh` uses `set -e` but also checks `$?` (failure branch won’t run)

**Symptoms**
- The script intends to print a custom “Failed to build…” message, but with `set -e`, a failing `go build` exits before the `if [ $? -eq 0 ]` branch.

**Likely cause**
- `set -e` + post-command `$?` inspection.
- Several shell variables are unquoted (minor robustness issue).

**Refs**
- `build.sh:6` (`set -e`)
- `build.sh:58`–`build.sh:83` (`go build` + `$?` check)

## 9) Explicit includes can’t override lock-file filtering (e.g., `go.sum`)

**Symptoms**
- `--include go.sum` results in `Total files: 0` unless `--include-locks` is also set.
- `.flatten` profile `source-and-tests` includes `go.*` but still excludes `go.sum` unless `--include-locks` is used.

**Repro**
- `flatten . --dry-run --include go.sum`
- `flatten . --dry-run --profile source-and-tests` (in this repo)

**Likely cause**
- Lock-file exclusion happens before include-pattern matching, so explicit includes can’t “force include” lock files.

**Refs**
- `cmd/flatten/filter.go:93` (lock exclusion)
- `cmd/flatten/filter.go:113` (include enforcement)
- `.flatten` (profile `source-and-tests`)

## 10) `--markdown-delimiter` help text is mangled (triple backticks collapse)

**Symptoms**
- `flatten --help` displays something like: ``auto, `, ~~~, ...`` (missing the literal triple-backtick option: ```` ``` ````).

**Likely cause**
- pflag treats backquoted segments in usage strings specially; embedding ``` inside the usage string gets “unquoted” into a single backtick.

**Refs**
- `cmd/flatten/main.go:1346` (usage string contains ``` in the description)
