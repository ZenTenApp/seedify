#!/bin/bash
# Loops over every day of SWEEP_YEAR, runs `seedify --full` with the
# container's real system clock set to that day, and saves the raw output.
# Once the sweep is complete, invokes parse-and-diff.py to build the
# structured diff report.
#
# IMPORTANT: this script changes the container's real wall clock via
# `date -u -s`. Docker containers do not get an isolated time namespace for
# CLOCK_REALTIME (Linux cannot virtualize it -- see `man 7 time_namespaces`),
# so this change is visible to every other container and process sharing the
# same Docker engine/VM while the sweep runs. See README.md before running
# this against a Docker daemon you use for anything else.
#
# Required environment:
#   SEEDIFY_KEY_PASSPHRASE  passphrase for the mounted SSH key
#
# Optional environment:
#   SEEDIFY_KEY_PATH  path to the Ed25519 key inside the container (default /key/id_ed25519)
#   SWEEP_YEAR        calendar year to sweep (default 2026)
#   SWEEP_TIME        fixed UTC time-of-day used every day (default 12:00:00)
#
# Output (under /results):
#   raw/YYYY-MM-DD.txt   full seedify --full stdout for that day
#   parsed/YYYY-MM-DD.json, summary.json, diffs.json, report.md (via parse-and-diff.py)

set -euo pipefail

: "${SEEDIFY_KEY_PATH:=/key/id_ed25519}"
: "${SWEEP_YEAR:=2026}"
: "${SWEEP_TIME:=12:00:00}"
RESULTS_DIR="${RESULTS_DIR:-/results}"

if [[ -z "${SEEDIFY_KEY_PASSPHRASE:-}" ]]; then
    echo "error: SEEDIFY_KEY_PASSPHRASE must be set" >&2
    exit 1
fi

if [[ ! -f "$SEEDIFY_KEY_PATH" ]]; then
    echo "error: SSH key not found at $SEEDIFY_KEY_PATH (mount it with -v)" >&2
    exit 1
fi

# Captured before any clock manipulation so we can restore it afterwards.
# This is a best-effort restore only: it will be stale by however long the
# sweep took to run. See README.md for why this matters and how to recover.
ORIGINAL_CLOCK="$(date -u +"%Y-%m-%d %H:%M:%S")"
restore_clock() {
    date -u -s "$ORIGINAL_CLOCK" >/dev/null 2>&1 || true
}
trap 'restore_clock; exit 130' INT
trap 'restore_clock; exit 143' TERM
trap restore_clock EXIT

if ! date -u -s "$ORIGINAL_CLOCK" >/dev/null 2>&1; then
    echo "error: could not set the system clock." >&2
    echo "This container needs the CAP_SYS_TIME capability: run with" >&2
    echo "  docker run --cap-add SYS_TIME ..." >&2
    echo "See README.md for the full required flags and safety notes." >&2
    exit 1
fi

RAW_DIR="$RESULTS_DIR/raw"
mkdir -p "$RAW_DIR"

# run_for_date DATE OUT_FILE
# Sets the container's clock to "DATE SWEEP_TIME" UTC, then runs seedify.
run_for_date() {
    local date_str="$1"
    local out_file="$2"

    date -u -s "${date_str} ${SWEEP_TIME}" >/dev/null

    local tmp_out
    tmp_out="$(mktemp)"
    if ! expect /scripts/run-seedify.exp /usr/local/bin/seedify "$SEEDIFY_KEY_PATH" --full \
        >"$tmp_out" 2>"${out_file}.stderr"; then
        echo "error: seedify failed for ${date_str}; see ${out_file}.stderr" >&2
        cat "${out_file}.stderr" >&2
        rm -f "$tmp_out"
        exit 1
    fi

    # The pty shared by expect echoes seedify's passphrase prompt (written to
    # stderr) interleaved with its stdout; strip that one line so the raw file
    # contains only seedify's actual --full output.
    grep -v 'Enter the passphrase to unlock' "$tmp_out" >"$out_file"
    rm -f "$tmp_out"

    # Drop the stderr file on success; it only ever contains the same
    # passphrase prompt captured separately, which is not useful once the run
    # has succeeded.
    rm -f "${out_file}.stderr"
}

echo "Smoke-testing clock control against seedify's clock..."
smoke_dir="$(mktemp -d)"
run_for_date "${SWEEP_YEAR}-01-01" "$smoke_dir/day1.txt"
run_for_date "${SWEEP_YEAR}-01-02" "$smoke_dir/day2.txt"

if diff -q "$smoke_dir/day1.txt" "$smoke_dir/day2.txt" >/dev/null; then
    echo "error: seedify produced identical output for ${SWEEP_YEAR}-01-01 and ${SWEEP_YEAR}-01-02." >&2
    echo "This is unexpected (the Brave 25-word section should change daily), which means" >&2
    echo "changing the container clock is not affecting seedify's clock in this environment." >&2
    echo "See README.md for troubleshooting." >&2
    rm -rf "$smoke_dir"
    exit 1
fi
rm -rf "$smoke_dir"
echo "Smoke test passed: the system clock is affecting seedify's output."

start_date="${SWEEP_YEAR}-01-01"
end_date="${SWEEP_YEAR}-12-31"
current_date="$start_date"

day_count=0
while [[ "$(date -u -d "$current_date" +%Y-%m-%d)" != "$(date -u -d "$end_date + 1 day" +%Y-%m-%d)" ]]; do
    out_file="$RAW_DIR/${current_date}.txt"
    if [[ -s "$out_file" ]]; then
        echo "skip ${current_date} (already present)"
    else
        echo "run  ${current_date}"
        run_for_date "$current_date" "$out_file"
    fi
    day_count=$((day_count + 1))
    current_date="$(date -u -d "$current_date + 1 day" +%Y-%m-%d)"
done

echo "Completed ${day_count} days for ${SWEEP_YEAR}. Building diff report..."
python3 /scripts/parse-and-diff.py --results-dir "$RESULTS_DIR" --year "$SWEEP_YEAR"
echo "Done. See ${RESULTS_DIR}/report.md"
echo "Restoring container clock to approximately ${ORIGINAL_CLOCK} UTC (best effort; see README.md)..."
# Actual restoration happens in the EXIT trap so it also runs on error/interrupt.
