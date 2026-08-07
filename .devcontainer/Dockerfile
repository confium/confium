# Devcontainer base image. Features layer Rust + Node + Python on top.
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# Pre-install OpenSSL and pkg-config for crates that need them.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        pkg-config libssl-dev ca-certificates jq \
        protobuf-compiler cmake \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
