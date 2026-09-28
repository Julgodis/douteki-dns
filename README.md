# douteki-dns

`douteki-dns` is a small Rust service that keeps DNS records in sync with a host's current IPv4 and IPv6 addresses. It currently supports the [GleSYS DNS API](https://glesys.com/).

> [!WARNING]
> This program can create, change, and delete DNS records using the credentials in its configuration. Review the records and API permissions before running it, and keep `config.toml` private.

## Features

- Resolve public addresses from configurable HTTP services or use static addresses.
- Manage dynamic A, AAAA, and PTR records, along with static address and text records such as TXT and MX.
- Create configured records that are missing from the provider and update records when their values change.
- Poll address sources at a configurable interval (derived from the minimum record TTL by default) and follow activity through structured logs.

## Configure and run

Copy the example configuration and add your GleSYS API credentials and DNS records:

```sh
cp config.example.toml config.toml
```

The [example configuration](config.example.toml) shows HTTP and static IP sources, dynamic IPv4/IPv6 and PTR records, static records, and a TXT record that substitutes `{ipv4}` or `{ipv6}` at runtime. The sample API key is a placeholder; replace it with your own credential.

Run with Rust and Cargo:

```sh
cargo run --release -- --config config.toml ddns
```

Or run the container image, mounting the configuration read-only:

```sh
docker run --rm \
  -v "$PWD/config.toml:/app/config.toml:ro" \
  ghcr.io/julgodis/douteki-dns:<version> \
  --config /app/config.toml ddns
```

The updater checks for address changes continuously. It applies the configured record values at startup and again when a resolved IP address changes. Set `check_interval_seconds` to control polling; by default, the interval is derived from the lowest configured record TTL.

## Commands and logging

The binary defaults to the `ddns` command. To list records from GleSYS:

```sh
cargo run -- --config config.toml glesys list-records
```

Set `RUST_LOG` to control log detail. For example:

```sh
RUST_LOG=debug cargo run -- --config config.toml ddns
```

For Docker, pass the same setting with `-e RUST_LOG=debug`.

## Container image releases

Build a local image with Docker:

```sh
docker build -t douteki-dns:local .
```

GitHub Actions runs formatting, compilation, and Rust tests on pushes to `master`, pull requests targeting `master`, and version tags. To publish a versioned image, push a version tag matching the package version in `Cargo.toml`:

```sh
git tag v0.1.2
git push origin v0.1.2
```

After the checks pass, the workflow publishes `ghcr.io/julgodis/douteki-dns:0.1.2`. GitHub Container Registry package visibility is managed separately from repository visibility; set the package to Public if you want anonymous pulls.

## Contributing

Issues and pull requests are welcome. Before submitting changes, run:

```sh
cargo fmt --all --check
cargo check --locked
cargo test --locked
```
