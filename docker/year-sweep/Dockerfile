# Docker harness for sweeping seedify's `--full` output across every day of a
# calendar year under a manipulated system clock, to empirically verify which
# sections of the output are time-dependent (see README.md in this directory).
#
# This is a standalone research/testing tool, not part of the seedify release
# pipeline. The release image (../../Dockerfile) is distroless and cannot run
# shells or expect, so this harness uses a separate Debian-based image.
#
# NOTE: libfaketime (LD_PRELOAD-based clock faking) does NOT work against Go
# binaries -- Go is statically linked and reads the wall clock via a direct
# vDSO/syscall path, never through the libc symbols libfaketime intercepts.
# This harness therefore sets the container's real clock with `date -u -s`
# for each day of the sweep, which requires the CAP_SYS_TIME capability at
# runtime (see README.md for the required `docker run` flags and, critically,
# the systemwide blast radius of changing the clock this way).

FROM golang:1.25-bookworm AS build

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/seedify ./cmd/seedify

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        expect \
        python3 \
        tzdata \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=UTC

COPY --from=build /out/seedify /usr/local/bin/seedify
COPY docker/year-sweep/run-sweep.sh /scripts/run-sweep.sh
COPY docker/year-sweep/run-seedify.exp /scripts/run-seedify.exp
COPY docker/year-sweep/parse-and-diff.py /scripts/parse-and-diff.py
RUN chmod +x /scripts/run-sweep.sh /scripts/run-seedify.exp /scripts/parse-and-diff.py

# Populated by the caller: the SSH key at SEEDIFY_KEY_PATH (default below) and
# the /results output directory should be bind-mounted at runtime.
ENV SEEDIFY_KEY_PATH=/key/id_ed25519
ENV SWEEP_YEAR=2026
ENV SWEEP_TIME=12:00:00
ENV NO_COLOR=1

VOLUME ["/results"]

ENTRYPOINT ["/scripts/run-sweep.sh"]
