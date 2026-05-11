# Proposal: Splitting the `seedify` binary by role

Status: Draft
Date: 2026-05-07
Branch: `cld2zenly/repo-split-proposal`

## Question

Should the `seedify` binary be split into several binaries with different roles
(e.g. `seedify`, `seedify-rsa`, `seedify-nostr`)?

## Recommendation

**Not as the first step.** The current layout is one library package
([seedify.go](../seedify.go)) plus one CLI entry point
([cmd/seedify/main.go](../cmd/seedify/main.go)). Subcommands (`seedify rsa`,
`seedify nostr`) give the same user-facing separation as separate binaries
without tripling release, packaging, manpage, and completion surface, or
forcing users to install multiple tools.

Separate binaries are only worth the cost when the code paths have meaningfully
different **trust** or **dependency** footprints that we want to audit or ship
in isolation (e.g. a hardened `seedify-nostr` with a minimal dep graph for a
specific deployment). If that is not the motivation, subcommands are cheaper.

## Why this repo makes a binary split expensive today

### 1. The library is monolithic; splitting binaries alone gains nothing

`seedify.go` is ~3348 lines and owns every derivation path in one Go package:
RSA↔Ed25519, DKIM, PGP, BIP39 mnemonics, Brave Sync, nostr, etc. The CLI in
`cmd/seedify/main.go` (~2502 lines) dispatches to it.

The dependency graph pulled in by that single package already includes:

- `github.com/nbd-wtf/go-nostr`
- `github.com/btcsuite/btcd` (+ btcutil)
- `github.com/chekist32/go-monero`
- `github.com/stephenlacy/go-ethereum-hdwallet`
- `github.com/ProtonMail/go-crypto` (PGP)
- `github.com/complex-gh/polyseed_go`
- `github.com/youmark/pkcs8`
- `github.com/tyler-smith/go-bip39`

Because everything lives in one package, any binary that imports the library
links the whole graph. A `seedify-nostr` binary carved from the current code
would still pull RSA, btcd, monero, ethereum, PGP, etc. — no reduction in
attack surface, just more artifacts to ship.

**Prerequisite:** split the library into subpackages before splitting binaries.
Something like `seedify/core`, `seedify/rsa`, `seedify/nostr`, `seedify/pgp`,
etc.

### 2. RSA isn't a clean cut

RSA is chained through the Ed25519 path and can't be lifted into an isolated
binary without duplicating or depending on the core:

- `RSASeedBytes` — [seedify.go:91](../seedify.go#L91)
- `DeriveEd25519KeyFromRSA` — [seedify.go:188](../seedify.go#L188)
- `DeriveRSAKeyFromEd25519` — [seedify.go:287](../seedify.go#L287)
- `DeriveDKIMKeypair` (uses RSA) — [seedify.go:341](../seedify.go#L341)
- `DerivePGPKeypair` (uses RSA) — [seedify.go:425](../seedify.go#L425)

A `seedify-rsa` binary would either re-link `seedify/core` or reimplement the
Ed25519 derivation. In practice RSA is a feature of the core tool, not a
separable role. Nostr is more plausibly isolable because its code path is
narrower.

### 3. Release and distribution surface

The repo already ships:

- `.goreleaser.yml` (single binary build matrix)
- `manpages/` generated via the `man` subcommand
- `completions/` for bash/zsh/fish/powershell
- `Dockerfile`
- README with a single install story

Tripling this is real ongoing cost: three goreleaser configurations, three
manpage outputs, three completion sets, three Docker images, three install
paths in the README. Users installing `seedify` today would have to learn
which binary they need.

## Cheaper alternatives that capture most of the value

Ordered from lowest cost to highest:

### Option A — Subcommands (recommended default)

Keep one binary, add top-level subcommands that group capabilities:

```
seedify <key-path>              # existing default
seedify rsa ...                 # RSA-specific operations
seedify nostr ...               # nostr-specific operations
seedify brave-sync-25th         # already exists
seedify man | completion        # already exists
```

No change to the release pipeline. Clearer UX. Cobra already supports this;
the existing `man` and `completion` subcommands prove the pattern works.

### Option B — Package split + build tags

1. Extract `pkg/nostr` (and optionally `pkg/rsa`, `pkg/pgp`) as their own Go
   packages with narrow APIs.
2. Put the heaviest optional path behind a build tag, e.g. `//go:build nostr`.
3. Ship a default `seedify` built without the `nostr` tag, and a
   `seedify-full` (or tagged release) that includes it.

This gives a minimal-dep default binary for users who don't need the optional
paths, without committing to a permanent multi-binary product.

### Option C — Separate binary for a specific deployment

Only if there is a concrete consumer who needs to deploy one role without the
main tool present (e.g. a nostr-signing service that wants the smallest
possible TCB), add a `cmd/seedify-nostr` that depends only on `pkg/nostr` and
`pkg/core`. Do this **after** Option B, not before — the package split is the
hard part; wiring up an extra `cmd/` is trivial once the packages exist.

## Suggested sequencing

1. **Library refactor.** Split `seedify.go` into focused subpackages. This is
   valuable on its own regardless of whether we ever split binaries.
2. **Subcommands.** Reorganise the CLI around `seedify <role> <verb>` so the
   user-facing shape matches the new internal shape.
3. **Build tags.** Gate the heaviest optional paths behind tags if a
   minimal-dep default is desired.
4. **Extra binaries.** Only if a concrete deployment need emerges.

Steps 1 and 2 capture most of the auditability and UX value at a fraction of
the cost of a full binary split.

## Open questions

- What is driving the split — auditability, deployment size, dependency
  hygiene, or organisational clarity? The right answer depends heavily on
  this.
- Is there a specific consumer asking for a nostr-only or rsa-only artifact?
- Are we willing to take a breaking CLI change to move existing flags under
  subcommands, or does backwards compatibility rule that out?
