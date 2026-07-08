# Seedify Year-Sweep Harness

This is a standalone Docker harness for empirically checking whether
`seedify --full` produces different output on different days of the year,
given the exact same input SSH key. It is a testing/research tool, separate
from the production release image at [`../../Dockerfile`](../../Dockerfile).

It works by running `seedify --full` once for every calendar day of a target
year (2026 by default), with the container's real system clock set to that
day via `date -u -s`, and then diffing the 365 outputs against each other.

**Read the "How the clock is controlled" and "Security notes" sections below
before running this.** Changing a container's wall clock is not sandboxed by
Docker: it changes the clock for every other container and process sharing
the same Docker engine while the sweep runs.

## Why this is needed

seedify's core mnemonic derivation is deterministic, but a few parts of its
`--full` output depend on the wall clock:

- The Brave Sync 25-word phrase's 25th word rotates daily
  (`seedify.BraveSync25thWordForDate`).
- The default 16-word Polyseed birthday is pinned to `1 Jan <current year>`,
  so it is stable within a year but flips across a Jan 1 boundary.

This harness sweeps a full year to confirm exactly this: the 16-word Polyseed
and chain-derived addresses should stay constant all year, while the Brave
25-word section should change every day.

## Build

Run from the repository root (the build context needs the full source tree):

```bash
docker build -f docker/year-sweep/Dockerfile -t seedify-year-sweep .
```

## Run

```bash
docker run --rm \
  --cap-add SYS_TIME \
  -v "$HOME/.ssh/id_ed25519:/key/id_ed25519:ro" \
  -v "$(pwd)/results-2026:/results" \
  -e SEEDIFY_KEY_PASSPHRASE='your-passphrase' \
  seedify-year-sweep
```

- `--cap-add SYS_TIME` is required: the container sets its own wall clock via
  `date -u -s` for each day of the sweep (see "How the clock is controlled"
  below for why, and for the systemwide side effect this has).
- The mounted key **must be password-protected** and **Ed25519** (seedify
  requires this).
- Mount the key read-only (`:ro`) — the container never needs to write to it.
- The sweep runs 365 subprocesses (one `seedify --full` invocation per day)
  plus a two-day smoke test; expect it to take a few minutes.
- Re-running with the same `/results` mount resumes: days that already have
  a non-empty `raw/YYYY-MM-DD.txt` are skipped.

### Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `SEEDIFY_KEY_PASSPHRASE` | yes | — | Passphrase to unlock the mounted SSH key |
| `SEEDIFY_KEY_PATH` | no | `/key/id_ed25519` | Path to the key inside the container |
| `SWEEP_YEAR` | no | `2026` | Calendar year to sweep |
| `SWEEP_TIME` | no | `12:00:00` | Fixed UTC time-of-day used every day |

`SWEEP_TIME` defaults to noon UTC rather than midnight to avoid the Brave
Sync 25th-word's intra-day rounding edge case near day boundaries (see the
project's top-level analysis of `BraveSync25thWordForDate`).

## Output

Everything is written under the mounted `/results` directory:

```
results/
  raw/2026-01-01.txt          # full seedify --full stdout for that day
  raw/2026-01-02.txt
  ...
  parsed/2026-01-01.json      # that day's output split into named sections
  ...
  summary.json                # sha256 of every section, for every day
  diffs.json                  # machine-readable change log
  report.md                   # human-readable summary
```

`report.md` lists which sections ever changed relative to the `2026-01-01`
baseline, which sections never changed, and how many day-to-day transitions
produced any difference at all.

## How the clock is controlled

This harness sets the container's **real** wall clock with `date -u -s
'<date> <SWEEP_TIME>'` before each day's `seedify --full` invocation.

An earlier version of this harness tried
[`libfaketime`](https://github.com/wolfcw/libfaketime), which intercepts
`LD_PRELOAD`-loaded libc time functions and would have avoided touching the
real clock. **It does not work here**: seedify is a statically linked Go
binary, and Go reads wall-clock time via a direct vDSO/syscall path that
never goes through the libc symbols libfaketime intercepts. This is a known,
fundamental limitation of libfaketime with Go binaries, not a configuration
problem — see [libfaketime's own man page](https://github.com/wolfcw/libfaketime/blob/master/man/faketime.1)
("faketime will not work with ... statically linked programs") and
[golang/go#22190](https://github.com/golang/go/issues/22190). Actually
changing the system clock via `date -u -s` is the only mechanism that works
against seedify's clock. `--cap-add SYS_TIME` grants the container
`CAP_SYS_TIME`, the minimum capability `date -s` needs; this is a smaller
privilege escalation than `--privileged`.

`run-sweep.sh` smoke-tests this on startup by comparing the outputs for
`<year>-01-01` and `<year>-01-02`. Since the Brave 25-word section is
expected to change daily, identical output for those two days means the
clock change isn't reaching seedify, and the script aborts with a clear
error rather than silently producing a useless (all-identical) sweep.

### The systemwide side effect (read this)

Linux cannot virtualize `CLOCK_REALTIME` per container: time namespaces
(`man 7 time_namespaces`) only virtualize `CLOCK_MONOTONIC` and
`CLOCK_BOOTTIME`, explicitly *not* the wall clock. This means `date -u -s`
inside this container changes the clock for the **entire kernel it runs
on** — every other container on the same Docker engine, and (with Docker
Desktop / OrbStack on macOS) the Linux VM backing your whole Docker
installation, immediately observes the changed date for as long as the
sweep is running. It does **not** affect the macOS host's own clock, only
the Docker VM's.

Consequences and mitigations:

- **Do not run this against a Docker daemon you're using for anything else
  at the same time.** Other containers will see the wrong date while the
  sweep runs.
- `run-sweep.sh` records the real time before making any changes and
  restores it (via a `trap` that fires on normal completion, error, or
  interrupt) when it exits. This restoration is best-effort and will be
  stale by however long the sweep took to run (typically a few minutes).
- Docker Desktop and OrbStack both include automatic clock-drift correction
  for their Linux VM (originally built to fix drift after host sleep/resume)
  and will typically self-correct any residual staleness shortly after the
  container exits. If you notice clock skew in other containers afterwards,
  restarting the Docker VM (or the Docker Desktop / OrbStack app) forces an
  immediate resync.
- Prefer running this in a dedicated Docker context or VM if you have one
  available, rather than your primary development Docker instance.

## How the passphrase is fed to seedify

seedify prompts interactively for the key passphrase and does not accept it
via a flag or environment variable directly (see
[`cmd/seedify/main.go`](../../cmd/seedify/main.go): `askKeyPassphrase`). This
harness uses `expect` (the same approach as the project's own integration
tests in [`cmd/seedify/main_test.go`](../../cmd/seedify/main_test.go)) to feed
`SEEDIFY_KEY_PASSPHRASE` to that prompt non-interactively.

## Security notes

- `--cap-add SYS_TIME` lets the container change the shared kernel clock; see
  "The systemwide side effect" above before running this.
- Every file under `/results` contains derived mnemonics, private keys, and
  addresses for your real key. Treat the results directory as secret: do not
  commit it, and restrict its filesystem permissions.
- Passing the passphrase via `-e SEEDIFY_KEY_PASSPHRASE=...` makes it visible
  to anyone who can run `docker inspect` on the container or read the host
  process list while `docker run` is invoked. For anything beyond local
  testing, use Docker secrets or an equivalent mechanism instead.
- Consider running this against a disposable test key rather than a
  key protecting real funds.

## Scope

This harness only sweeps `seedify --full` with no extra flags. It
deliberately does not sweep `--zentenprofile`, which mixes in `crypto/rand`
on every invocation and would show differences unrelated to the date.
