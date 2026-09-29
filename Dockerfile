FROM rust:slim AS builder
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies separately and warm registry using cache mounts.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config.example.toml ./config.example.toml
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    cargo fetch --locked
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    --mount=type=cache,target=/src/target,id=douteki-target \
    cargo build --release --locked
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    --mount=type=cache,target=/src/target,id=douteki-target \
    cargo test --release --locked
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    --mount=type=cache,target=/src/target,id=douteki-target \
    cp ./target/release/douteki-dns /usr/local/bin/douteki-dns

FROM debian:bookworm-slim
ENV GITHUB_REPOSITORY=Julgodis/douteki-dns
LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/local/bin/douteki-dns /usr/local/bin/douteki-dns

ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/douteki-dns"]
CMD ["ddns"]
