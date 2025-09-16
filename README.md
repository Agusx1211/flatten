# Flatten

[![Build and Release](https://github.com/Agusx1211/flatten/actions/workflows/build.yml/badge.svg)](https://github.com/Agusx1211/flatten/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/agusx1211/flatten)](https://goreportcard.com/report/github.com/agusx1211/flatten)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Flatten is a CLI tool that takes a directory as input and outputs a flat representation of its contents to stdout. It recurses into subdirectories and collects every file (even large ones, if you enable that) in a single readable listing. It's handy for quick overviews, backups, or curious exploration.

## Features
You can toggle metadata details like last modified time, file permissions, sizes, checksums, and more. You can also include or exclude certain special files or directories with options like `--include-git`, `--include-gitignore`, or `--include-bin` if you want your binary files included.

### Optional Output Compression (experimental)
- `--compress`: When enabled, output is post-processed to reduce redundancy, while remaining human-readable.
  - Repeated lines or small groups repeated consecutively are collapsed: they are shown once followed by a small marker, for example `(...<<<repeats N times>>>...)`.
  - Large blobs of text that repeat in multiple places (detected as large paragraphs) are extracted and replaced by placeholders like `<<<blob-XXXXXXXX>>>`. The full blob contents are appended at the end of the output under an "Extracted blobs" section.
  - A brief legend is added at the top indicating the two compression behaviors when compression was actually applied.

## Installation

### Pre-built Binaries
Download the latest release from the [GitHub Releases page](https://github.com/Agusx1211/flatten/releases). Binaries are available for:
- Linux (amd64, 386, arm64, arm)
- macOS/Darwin (amd64, arm64)  
- Windows (amd64, 386, arm64)
- FreeBSD (amd64, 386, arm64)

### From Source
Grab Go 1.21 or newer, clone this repository, then run:
```bash
go install github.com/agusx1211/flatten/cmd/flatten@latest
```

Or build locally:
```bash
git clone https://github.com/agusx1211/flatten.git
cd flatten
make build
```

### Docker
```bash
docker run --rm -v $(pwd):/workspace ghcr.io/agusx1211/flatten:latest
```

## Building

### Quick Build (Current Platform)
```bash
make build
# or
./build-local.sh
```

### Build for All Platforms
```bash
make build-all
# or
./build.sh [version]
```

### Available Make Targets
- `make build` - Build for current platform
- `make build-all` - Build for all platforms  
- `make test` - Run tests
- `make clean` - Clean build artifacts
- `make install` - Install to GOPATH/bin

## Requisites
Just a recent version of Go. There are a few external libraries for CLI and .gitignore parsing, but they're fetched automatically when you build or install.

## Limitations
Flatten doesn't do partial merges or transformations, it just gathers files and prints them out. If your directory is massive, the output can get really big. If you skip binary files, that might miss some unusual ones.

## Example
If you run `flatten .` in a small project, you might see something like:

```
- Total files: 4
- Total size: 18368 bytes
- Dir tree:
.
├── .gitignore
├── cmd
│   └── flatten
│       ├── filter.go
│       └── main.go
└── go.mod

- path: .gitignore
- content:
/dist/
/node_modules/
```

And so on, with optional metadata if you enabled it.

## Usage
Below is the help output for quick reference:

```
Usage:
  flatten [directory] [flags]

Flags:
  -a, --all-metadata        Show all available metadata
      --include-bin         Include binary files in the output
  -g, --include-git         Include .git directory and its contents
  -i, --include-gitignore   Include files that would normally be ignored by .gitignore
      --include-locks       Include lock files (package-lock.json, yarn.lock, etc.)
  -l, --last-updated        Show last updated time for each file
      --no-dedup            Disable file deduplication
      --prefix              Optional message printed before output, wrapped by --- lines
      --suffix              Optional message printed after output, wrapped by --- lines
  -c, --show-checksum       Show SHA256 checksum of files
  -M, --show-mime           Show file MIME types
  -m, --show-mode           Show file permissions
  -o, --show-owner          Show file owner and group
  -z, --show-size           Show individual file sizes
  -Z, --show-total-size     Show total size of all files
      --compress            Compress output by collapsing repeats and extracting large repeated blobs
  -t, --tokens              Show token usage for each file/directory
      --tokens-model        Model to use for token counting
  -y, --show-symlinks       Show symlink targets
  -h, --help                Help for flatten
  -I, --include             Include only files matching these patterns (e.g. '*.go,*.js')
  -E, --exclude             Exclude files matching these patterns (e.g. '*.test.js')
```

### Running Commands After Flattening
- `--command`: Command to run after flattening (can be repeated). Each command runs in the current working directory, and its start/end time, duration, exit code, stdout, and stderr are appended to the end of the flatten output.

Examples:
- `flatten . --command "go test ./..." --command "git status --porcelain"`
- `flatten repoA repoB --command "ls -la"`

### Optional Output Wrapping
Use `--prefix` and/or `--suffix` to add custom messages around the entire output. When provided, each is wrapped by delimiter lines `---` to make them easy to spot.

Example:

```
flatten . --prefix "Start of snapshot" --suffix "End of snapshot"
```

This prints:

```
---
Start of snapshot
---
...<flatten output here>...
---
End of snapshot
---
```

## License
MIT License

Copyright (c) 2023

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

The Software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the Software or the use or other dealings in the Software.
