# Contributing

Thank you for considering a contribution. This project is a small focused library; contributions that keep it small and focused are most welcome.

## Prerequisites

- Go 1.22 or later (`go version`)
- `git`

## Setup

```bash
git clone https://github.com/codeskine/gin-gonic-xss-middleware.git
cd gin-gonic-xss-middleware
go mod download
```

## Running tests

```bash
# All tests with race detector (required before submitting a PR)
go test -race ./...

# Single test by name
go test -run TestName ./...

# Verbose output
go test -v ./...
```

## Formatting

```bash
gofmt -w .
```

The CI gate rejects unformatted code. Run `gofmt` before committing.

## Submitting a pull request

1. Open an issue first to discuss the change.
2. Fork the repository and create a branch from `main`.
3. Add or update tests as appropriate. All new behaviour must be covered.
4. Ensure `go test -race ./...` passes and `gofmt -l .` produces no output.
5. Open a pull request against `main` with a clear description of the change and the motivation behind it.

## Reporting bugs

Open a GitHub issue with:
- Go version (`go version`)
- A minimal reproduction case
- Expected vs actual behaviour
