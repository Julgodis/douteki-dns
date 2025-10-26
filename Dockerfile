# syntax=docker/dockerfile:1.6
# syntax=docker/dockerfile:1.7
FROM rust:1.83-slim AS builder
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies separately and warm registry using cache mounts.
COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --locked

COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo test --release --locked

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /src/target/release/douteki-dns /usr/local/bin/douteki-dns

ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/douteki-dns"]
CMD ["ddns"]
