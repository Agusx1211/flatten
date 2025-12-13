# Issues / Bugs

Collected on Linux (arm64) with Go `go1.25.5` by:
- Building with `make build`
- Running `go test ./...` and `go vet ./...`
- Manually exercising flags via the built `./bin/flatten`

## 1) `--show-symlinks` doesn’t show symlink targets

**Symptoms**
- `--show-symlinks` produces no `- symlink-target:` lines.
- `--all-metadata` *does* show `- symlink-target:` for symlinks, which makes `--show-symlinks` look broken.

**Repro**
1. Create a directory containing a symlink.
2. Run:
   - `flatten <dir> --show-symlinks --no-dedup`
   - Compare with: `flatten <dir> --all-metadata --no-dedup`

**Likely cause**
- Directory walking uses `os.Stat` (follows symlinks), so `entry.Mode` typically won’t include `os.ModeSymlink`.
- The `--show-symlinks` conditional checks `entry.Mode&os.ModeSymlink != 0`, which is rarely true under `os.Stat`.

**Refs**
- `cmd/flatten/main.go:145` (uses `os.Stat`)
- `cmd/flatten/main.go:501` (checks `os.ModeSymlink`)

## 2) Symlink directories are followed (loops and out-of-tree traversal)

**Symptoms**
- A symlink loop can make `flatten` error with “too many levels of symbolic links”.
- A symlink pointing outside the input directory can cause `flatten` to traverse and dump files outside the intended root.

**Repro (loop)**
1. Make a directory with `loop -> .` inside it.
2. Run: `flatten <dir> --dry-run`
3. Observed: failure while trying to stat `.../loop/loop/loop/...` until the OS errors.

**Likely cause**
- `os.Stat`/`os.ReadDir` follow symlinks and there’s no cycle detection / visited-set.

**Refs**
- `cmd/flatten/main.go:145` / `cmd/flatten/main.go:198` (uses `os.Stat`)
- `cmd/flatten/main.go:180` / `cmd/flatten/main.go:246` (reads directories recursively)

## 3) Directory-only `--include` patterns can exclude everything (root is not includable)

**Symptoms**
- Directory-only includes (patterns ending in `/`) can produce `Total files: 0` even when matching directories exist.
- Adding `--include "."` doesn’t help; it’s effectively ignored.

**Repro**
- In this repo: `flatten . --dry-run --include "cmd/"` → `Total files: 0`
- Also: `flatten . --dry-run --include "cmd/" --include "."` → still `Total files: 0`

**Likely cause**
- `compilePatterns()` drops patterns that normalize to an empty pattern without `dirOnly` (so `"."`/`"./"` can’t be used to match root).
- When any `dirOnly` include exists, directories must match an include pattern (`hasDirOnlyIncludes` gate), and `"."` doesn’t match `"cmd"` etc.

**Refs**
- `cmd/flatten/filter.go:107` (dir pruning when `hasDirOnlyIncludes`)
- `cmd/flatten/filter.go:276` (drops empty patterns like `"."`)
- `cmd/flatten/filter.go:288` (normalizes `"."` to empty)

## 5) `--prefix` / `--suffix` wrapping doesn’t match README’s example

**Symptoms**
- Output looks like:
  - `Start`
  - `---`
  - `<content>`
  - `---`
  - `End`
- README shows prefix/suffix each wrapped by `---` lines (including a leading `---` before the prefix and a trailing `---` after the suffix).

**Repro**
- `flatten . --dry-run --prefix "Start" --suffix "End"`

**Likely cause**
- Wrapper lines are only emitted between prefix/content and content/suffix (not around prefix/suffix as separate blocks).

**Refs**
- `cmd/flatten/main.go:611` (`composeFinalOutput`)
- `README.md` (“Optional Output Wrapping” section)

## 6) Non-dry-run output starts with a blank line

**Symptoms**
- `flatten .` prints an empty first line before `Total files: ...`.

**Repro**
- `flatten . | head -n 2`

**Likely cause**
- Header write starts with `\nTotal files: ...`.

**Refs**
- `cmd/flatten/main.go:895`

## 7) Any read error aborts the whole run and prints full CLI usage

**Symptoms**
- A single unreadable file (permission denied) aborts the entire flatten.
- The error output includes the full Cobra `Usage:` help text, which is noisy for runtime errors.

**Repro**
1. Create a directory with one readable file and one `chmod 000` file.
2. Run: `flatten <dir>`
3. Observed: exit code non-zero + error + full usage printed.

**Likely cause**
- `loadDirectory()` returns an error on first `os.ReadFile` failure.
- Cobra default behavior prints usage on `RunE` error (no `SilenceUsage` set).

**Refs**
- `cmd/flatten/main.go:161` (hard error on `os.ReadFile`)
- `cmd/flatten/main.go:796` (cobra command config)

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
