# Contributing to seedify

Thank you for your interest in contributing. This guide covers how to set up a
local development environment, run tests, and submit changes.

## What this project is

seedify is a Go project with two surfaces:

- **Library** (`seedify.go` and related files at the repo root) — mnemonic
  generation and wallet derivation for 20+ chains.
- **CLI** (`cmd/seedify/`) — interactive tool that reads Ed25519 SSH keys and
  prints seed phrases and derived addresses.

Most changes either extend the library API, add or adjust CLI flags/output, or
add tests for deterministic derivation behavior.

## Prerequisites

- **Go 1.25.6** — required by `go.mod` and CI. Install from
  [go.dev](https://go.dev/dl/) or let the toolchain auto-download via
  `GOTOOLCHAIN=auto`.
- **Git**
- **golangci-lint v2.8.0** — optional locally; required to match CI lint checks.
- **expect(1)** — optional; needed for CLI subprocess tests in
  `cmd/seedify/main_test.go`. Tests skip automatically if `expect` is not
  installed.

## Getting started

```sh
git clone https://github.com/ZenTenApp/seedify.git
cd seedify
go mod download
```

Verify your setup:

```sh
go test ./...
go build -o seedify ./cmd/seedify
```

## Project layout

| Path | Purpose |
|------|---------|
| `seedify.go` | Core library: mnemonic generation and chain derivation |
| `*_test.go` | Library tests (`seedify_test.go`, `paynym_test.go`, etc.) |
| `example_test.go` | Runnable examples for pkg.go.dev |
| `cmd/seedify/` | CLI entrypoint, flags, and CLI-specific tests |
| `cmd/seedify/testdata/` | Sample SSH keys for manual or test use |
| `scripts/` | Helper scripts (e.g. `scripts/build.sh` for multi-platform builds) |
| `docs/` | Design notes and proposals |
| `.github/workflows/` | CI: build, lint, nightly, release |

## Development workflow

### 1. Create a branch

Work from `main` on a descriptive branch:

```sh
git checkout -b fix/bitcoin-derivation-index
```

### 2. Make your changes

- **Library changes** — add or update functions in the root package and cover
  them with tests in the matching `*_test.go` file.
- **CLI changes** — update `cmd/seedify/main.go` and add CLI tests in
  `cmd/seedify/main_test.go` when behavior changes.
- **Deterministic output** — many tests rely on fixed inputs producing fixed
  outputs. Avoid changing existing golden values unless the derivation logic
  intentionally changes.

### 3. Run tests

Run the full suite (matches CI):

```sh
go test -v -race ./...
```

Run a single package or test:

```sh
go test -v -race ./cmd/seedify/...
go test -v -race -run TestToMnemonicWithLength_Polyseed .
```

With coverage:

```sh
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 4. Build

Build the CLI binary:

```sh
go build -o seedify ./cmd/seedify
```

Build all packages:

```sh
go build -v ./...
```

Multi-platform release-style builds:

```sh
./scripts/build.sh          # version "dev"
./scripts/build.sh v1.2.3   # custom version label
```

Binaries are written to `dist/`.

### 5. Lint

CI runs two lint jobs:

```sh
# Strict lint (must pass)
golangci-lint run --config .golangci.yml

# Soft lint (additional checks)
golangci-lint run --config .golangci-soft.yml
```

Install golangci-lint v2.8.0 to match CI, or use the
[golangci-lint-action](https://github.com/golangci/golangci-lint-action) version
pinned in `.github/workflows/lint.yml`.

### 6. Try the CLI manually

The CLI requires a **password-protected Ed25519 SSH key**. Unprotected keys are
rejected by design.

Use your own key or generate a test key:

```sh
ssh-keygen -t ed25519 -f /tmp/test_ed25519 -N "testpass"
go run ./cmd/seedify /tmp/test_ed25519 --words 12
```

Useful flags for focused output:

```sh
go run ./cmd/seedify /tmp/test_ed25519 --nostr
go run ./cmd/seedify /tmp/test_ed25519 --btc --eth
go run ./cmd/seedify /tmp/test_ed25519 --full
```

Pipe a key from stdin:

```sh
cat /tmp/test_ed25519 | go run ./cmd/seedify --words 18
```

**Security tip:** prefix commands with a space so they are not saved in shell
history when `HISTCONTROL=ignorespace` is set.

## Testing conventions

- Use **table-driven tests** with `t.Run` subtests.
- Call **`t.Parallel()`** in tests and subtests where safe (enforced by the
  `tparallel` linter in `.golangci.yml`).
- Library tests often use [`github.com/matryer/is`](https://github.com/matryer/is)
  for assertions (`is := is.New(t)`).
- CLI subprocess tests build a temporary binary and drive passphrase prompts
  with `expect(1)`. If `expect` is missing, those tests are skipped — not failed.
- Prefer generating ephemeral Ed25519 keys in tests (`ed25519.GenerateKey`) over
  committing real private material. Committed test fixtures live under
  `cmd/seedify/testdata/` and must not contain production keys.

## Code style

- Run **`goimports`** before committing (enabled as a formatter in
  `.golangci.yml`).
- Follow existing naming and error-handling patterns in the file you are editing.
- Keep CLI flag help strings and README/CONTRIBUTING docs in sync when adding
  user-facing flags.
- Add `example_test.go` examples for new public library functions when the API
  surface grows.

## Continuous integration

Every push and pull request to `main` runs:

| Workflow | What it does |
|----------|--------------|
| **Build** (`.github/workflows/build.yml`) | `go test -v -race`, `go build -v ./...` on Go 1.25.6 |
| **Lint** (`.github/workflows/lint.yml`) | `golangci-lint` with `.golangci.yml` |
| **Lint (Soft)** (`.github/workflows/lint-soft.yml`) | Additional lint with `.golangci-soft.yml` |

Nightly CI (`.github/workflows/nightly.yml`) re-runs tests and builds on a
schedule.

Ensure these pass locally before opening a pull request.

## Submitting a pull request

1. Fork the repository and push your branch.
2. Open a pull request against `main`.
3. Describe **what** changed and **why**.
4. Note any intentional changes to deterministic output (mnemonics, addresses,
   fingerprints).
5. Confirm you ran `go test -v -race ./...` and lint locally.

Keep pull requests focused. Separate unrelated fixes into different PRs when
possible.

## Security and sensitive data

This project handles cryptographic key material. When contributing:

- **Never** commit real SSH private keys, mnemonics, or passphrases.
- **Never** log or print private keys in new code paths unless that is the
  explicit, documented purpose of a CLI flag.
- Treat `--seed-passphrase` and SSH passphrases as secrets in tests and examples.
- If you find a security issue, report it privately to the maintainers rather
  than opening a public issue with exploit details.

## Questions

- **Usage and API** — see [README.md](README.md) and
  [pkg.go.dev](https://pkg.go.dev/github.com/ZenTenApp/seedify).
- **Design proposals** — see [docs/](docs/) for in-repo notes.

For bugs and feature requests, open a GitHub issue with steps to reproduce or a
clear description of the desired behavior.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
