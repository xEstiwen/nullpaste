# Contributing

Issues and pull requests are welcome.

## Setup

    go test ./...
    go run ./cmd/nullpaste

## Before opening a PR

- `gofmt`, `go vet ./...` and `golangci-lint run` are clean
- `go test -race ./...` passes (needs cgo)
- behaviour changes come with a test
- one concern per PR, with a message that says why, not only what

Security issues: see [SECURITY.md](SECURITY.md), please don't open a public issue.
