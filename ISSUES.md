# Issues

Notes:
- Findings came from code review + quick local runs on 2025-12-13.
- Status: all items below have been addressed (see commits `7423be1`, `4125333`, `abd0d46`, `8c1c415`, `84bfcc6`, `cd879c8`).

## High

### `--compress` + default dedup can produce incorrect “identical” claims (and checksum/content mismatch)

**Status:** Fixed in `7423be1`.

**Impact:**
- Files can be reported as “Contents are identical to …” even when their *original* contents differ.
- When `--show-checksum` is enabled, the printed SHA256 can disagree with the displayed (compressed/deduped) content.

**Why this happens:**
- Compression mutates `contentStr` first, then dedup hashes the *mutated* string (`cmd/flatten/main.go:593`, `cmd/flatten/main.go:612`).
- Checksums are computed from the *original* bytes (`cmd/flatten/main.go:586`–`cmd/flatten/main.go:589`).

**Where:**
- `cmd/flatten/main.go:593`–`cmd/flatten/main.go:618`

**Repro (shows incorrect “identical” + different SHA256):**
```bash
tmpdir=$(mktemp -d)
blob=$(python - <<'PY'
print("A"*1200)
PY
)
id=$(python - <<'PY'
import hashlib
blob="A"*1200
print("blob-"+hashlib.sha256(blob.encode()).hexdigest()[:8])
PY
)

printf '%s' "$blob" > "$tmpdir/a.txt"
printf '%s' "$blob" > "$tmpdir/c.txt"
printf '<<<%s>>>' "$id" > "$tmpdir/b.txt"

go run ./cmd/flatten --compress --show-checksum "$tmpdir"
```

### Unreadable directories abort the whole run due to `.flatten` / `.gitignore` probing

**Status:** Fixed in `4125333`.

**Impact:** Flatten fails hard on trees that contain unreadable directories (common on `/proc`, system mounts, partially-permissioned monorepos, etc.), even though directory read errors are otherwise tracked via `ReadError`.

**What happens:**
- On every directory, `loadDirectory*` calls `WithFlattenFile()` and `WithGitIgnoreFile()` before `os.ReadDir` (`cmd/flatten/main.go:201`–`cmd/flatten/main.go:210`, `cmd/flatten/main.go:254`–`cmd/flatten/main.go:264`).
- `WithFlattenFile()` / `WithGitIgnoreFile()` treat `os.Stat()` errors other than `IsNotExist` as fatal, including `permission denied` (`cmd/flatten/filter.go:131`–`cmd/flatten/filter.go:138`, `cmd/flatten/filter.go:236`–`cmd/flatten/filter.go:243`).

**Where:**
- `cmd/flatten/main.go:201`–`cmd/flatten/main.go:210`
- `cmd/flatten/main.go:254`–`cmd/flatten/main.go:264`
- `cmd/flatten/filter.go:126`–`cmd/flatten/filter.go:160`
- `cmd/flatten/filter.go:235`–`cmd/flatten/filter.go:269`

**Repro (fails with “failed to stat …/.flatten: permission denied”):**
```bash
tmpdir=$(mktemp -d)
mkdir -p "$tmpdir/secret"
chmod 000 "$tmpdir/secret"

go run ./cmd/flatten --dry-run "$tmpdir"

# cleanup
chmod 755 "$tmpdir/secret"
rm -rf "$tmpdir"
```

## Medium

### Directory tree omits the `.` root when running `flatten .` (docs mismatch)

**Status:** Fixed in `abd0d46`.

**Impact:** The “Directory structure” output doesn’t show `.` as the root line when the user flattens `.`; it jumps straight to children. This conflicts with the README example that prints `.` (`README.md:74`–`README.md:88`).

**Where:**
- Root suppression: `cmd/flatten/main.go:308`–`cmd/flatten/main.go:312` (`if entry.Path != "." { ... }`)

**Repro:**
```bash
go run ./cmd/flatten --dry-run .
```

### `--include` does not override `.gitignore` (can be surprising)

**Status:** Clarified in docs (`8c1c415`).

**Impact:** Even if a file matches `--include` (or an include from `.flatten` profiles), it can still be excluded by `.gitignore` unless `--include-gitignore` is also used.

**Where:**
- `.gitignore` check is applied last and overrides prior include matching: `cmd/flatten/filter.go:109`–`cmd/flatten/filter.go:121`

**Example (in this repo):**
- `go.sum` is listed in `.gitignore` (`.gitignore:68`–`.gitignore:70`), so it is excluded by default.
- `--profile source-and-tests` includes `go.*` (from `.flatten`), but `go.sum` still won’t appear unless `--include-gitignore` is set:
  - `go run ./cmd/flatten --dry-run --profile source-and-tests .`
  - `go run ./cmd/flatten --dry-run --include-gitignore --profile source-and-tests .`

### CI build doesn’t run `go test` / `go vet`

**Status:** Fixed in `84bfcc6`.

**Impact:** The GitHub Actions workflow builds artifacts but doesn’t execute tests or vet, so regressions can slip through CI.

**Where:**
- `.github/workflows/build.yml:14`–`.github/workflows/build.yml:55` (build job runs `./build.sh` only)

## Low

### `.flatten` profile selection silently falls back to `profiles.default`

**Status:** Warns on missing explicit `--profile` (`cd879c8`).

**Impact:** A typo in `--profile` won’t be surfaced if the `.flatten` file has a `profiles.default`; it quietly uses default instead.

**Where:**
- `cmd/flatten/flattenfile.go:42`–`cmd/flatten/flattenfile.go:49`

### `ISSUES.md` is gitignored (easy to lose/forget)

**Status:** Fixed by tracking `ISSUES.md` in git.

**Impact:** This file won’t be committed unless `.gitignore` is changed, which may surprise contributors.

**Where:**
- `.gitignore:78`–`.gitignore:79`
