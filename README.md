# Flatten
Flatten is a CLI tool that takes a directory as input and outputs a flat representation of its contents to stdout. It recurses into subdirectories and collects every file (even large ones, if you enable that) in a single readable listing. It's handy for quick overviews, backups, or curious exploration.

## Features
You can toggle metadata details like last modified time, file permissions, sizes, checksums, and more. You can also include or exclude certain special files or directories with options like `--include-git`, `--include-gitignore`, or `--include-bin` if you want your binary files included.

## Install
Grab Go 1.21 or newer, clone this repository, then run:
```
go build -o flatten ./cmd/flatten
```
Place the resulting `flatten` binary somewhere in your PATH.

Or simply:
```
go install github.com/agusx1211/flatten/cmd/flatten@latest
```

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
  -c, --show-checksum       Show SHA256 checksum of files
  -M, --show-mime           Show file MIME types
  -m, --show-mode           Show file permissions
  -o, --show-owner          Show file owner and group
  -z, --show-size           Show individual file sizes
  -Z, --show-total-size     Show total size of all files
  -t, --tokens              Show token usage for each file/directory
      --tokens-model        Model to use for token counting
  -y, --show-symlinks       Show symlink targets
  -h, --help                Help for flatten
  -I, --include             Include only files matching these patterns (e.g. '*.go,*.js')
  -E, --exclude             Exclude files matching these patterns (e.g. '*.test.js')
```

## License
MIT License

Copyright (c) 2023

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

The Software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the Software or the use or other dealings in the Software.