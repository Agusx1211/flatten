# .flatten quick guide
- Put a `.flatten` YAML file in any directory; its rules apply there and below until another `.flatten` appears.
- Use `include` (whitelist) and `exclude` (blacklist) arrays with glob patterns relative to the file; add a trailing `/` to target directories.
- Add optional `profiles` and pick one with `--profile`; the chosen profile falls back to `profiles.default` and the top-level lists.
- `.gitignore` is still respected by default; pass `--include-gitignore` if you want `.flatten` rules to apply to files that are normally ignored.
- Rules accumulate as you descend, so parent filters stay in effect.
- Optional: set a default output mode in `~/.flatten` with `output: print|copy|ssh-copy` (does not affect include/exclude rules).

Example:
```yaml
include:
  - "src/"
exclude:
  - "**/*.log"
profiles:
  source:
    exclude: ["**/*_test.go"]
  source-and-tests:
    include: ["src/", "tests/"]
```
