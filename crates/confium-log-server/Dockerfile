# Multi-stage build for confium-log-server.
#
# Builds the binary in the build stage, then copies just the binary
# into a slim runtime image. No shell, no package manager in the final
# image = minimal attack surface.

# --- build stage -----------------------------------------------------------
FROM rust:1-bookworm AS builder

WORKDIR /build
# Cache deps separately from source for faster incremental builds.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Install the binary's target deps (some crates need system libs).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build the specific binary. Uses glibc (default target), not musl —
# the base image already has glibc, no extra setup needed.
RUN cargo build --release -p confium-log-server

# --- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim

# Install just the runtime libs the binary needs (libssl, libgcc).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin confium

USER 65532:65532

COPY --from=builder \
    /build/target/release/confium-log-server \
    /usr/local/bin/confium-log-server

# Default config mounted at /etc/confium/config.toml.
VOLUME ["/etc/confium"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/confium-log-server"]
