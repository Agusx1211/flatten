# Flatten
Flatten is a CLI tool that takes a directory as input and outputs a flat representation of its contents to stdout. It recurses into subdirectories and collects every file (even large ones, if you enable that) in a single readable listing that can be saved or processed. It's pretty handy for quick overviews, backups, or curious exploration.

## Features
You can toggle metadata details like last modified time, file permissions, sizes, checksums, and more. If you prefer writing everything to a file, use `-f`. If you want that output file to self-destruct after a while, combine `-f` with `-d`. You can also include or exclude certain special files or directories with options like `--include-git`, `--include-gitignore`, or `--include-bin` if you want your binary files included.

## Install
Grab Go 1.21 or newer, clone this repository, then run `go build -o flatten ./cmd/flatten` and place the resulting `flatten` binary somewhere in your PATH.

Or simply do:

`go install github.com/agusx1211/flatten/cmd/flatten@latest`

## Requisites
Just a recent version of Go. There are a few external libraries for CLI and .gitignore parsing, but they’re fetched automatically when you build or install.

## Limitations
Flatten doesn’t do partial merges or transformations, it just gathers files and prints them out. If your directory is massive, the output can get really big. If you skip binary files, that might miss some unusual ones.

## Example
Let’s say you run `flatten .` in a small project. You might see something like:

```
	•	Total files: 4
	•	Total size: 18368 bytes
	•	Dir tree:
.
├── .gitignore
├── cmd
│   └── flatten
│       ├── filter.go
│       └── main.go
└── go.mod

•	path: .gitignore
•	content:
/dist/
/node_modules/
```

And so on, with optional metadata if you enabled it.

### Auto-delete
When you run `flatten -f -d --auto-delete-time 60`, the tool writes its output to a file (default name is ./flat, or whatever you passed via -n) and spawns a background job that waits 60 seconds, checks whether the file still looks like a Flatten output, and then deletes it. If it sees you changed the file into something else, it skips deletion.

#### Disclaimer
Flatten tries to be cautious, but always double-check before letting a script delete things. Watch out for large directories or deeply nested structures that could balloon your output file. Also, if you run it on extremely large or binary-heavy folders with --include-bin, your terminal or output file might blow up in size.

## Usage
Below is the --help output for quick reference:

```
Flatten is a CLI tool that takes a directory as input and outputs
a flat representation of all its contents to stdout. It recursively processes
all subdirectories and their contents.

Usage:
  flatten [directory] [flags]

Flags:
  -a, --all-metadata           Show all available metadata
  -d, --auto-delete            Auto delete the output file after N seconds (only used with --to-file)
      --auto-delete-time int   Auto delete time in seconds (only used with --auto-delete) (default 30)
  -n, --file-name string       Output file name (only used with --to-file) (default "./flat")
  -h, --help                   help for flatten
      --include-bin            Include binary files in the output
  -g, --include-git            Include .git directory and its contents
  -i, --include-gitignore      Include files that would normally be ignored by .gitignore
  -l, --last-updated           Show last updated time for each file
      --no-dedup               Disable file deduplication
  -c, --show-checksum          Show SHA256 checksum of files
  -t, --show-mime              Show file MIME types
  -m, --show-mode              Show file permissions
  -o, --show-owner             Show file owner and group
  -z, --show-size              Show individual file sizes
  -y, --show-symlinks          Show symlink targets
  -s, --skip-gitignore         Skip adding output file to .gitignore
  -f, --to-file                Write output to file instead of stdout
      --unsafe                 Allow overwriting non-flattener output files
```

## License
MIT License

Copyright (c) 2023

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

The Software is provided “as is”, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the Software or the use or other dealings in the Software.
