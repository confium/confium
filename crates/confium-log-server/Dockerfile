# Multi-stage build for confium-log-server.
#
# Builds a static musl binary in the build stage, then copies just the
# binary + CA bundle into a distroless runtime image. No shell, no
# package manager, no compilers in the final image = minimal attack
# surface.

# --- build stage -----------------------------------------------------------
FROM rust:1.85-bookworm AS builder

WORKDIR /build
# Cache deps separately from source for faster incremental builds.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --target x86_64-unknown-linux-musl -p confium-log-server

# --- runtime stage ---------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# nonroot user (uid 65532) is the default; we set it explicitly for clarity.
USER 65532:65532

COPY --from=builder     /build/target/x86_64-unknown-linux-musl/release/confium-log-server     /usr/local/bin/confium-log-server

# Default config mounted at /etc/confium/config.toml.
VOLUME ["/etc/confium"]
ENTRYPOINT ["/usr/local/bin/confium-log-server"]
