# douteki-dns

<p align="center">
  <img src="assets/logo.png" alt="douteki-dns logo" width="180">
</p>

`douteki-dns` is a small Rust service that keeps DNS records in sync with a host's current IPv4 and IPv6 addresses. It currently supports the [GleSYS DNS API](https://glesys.com/).

> [!WARNING]
> This program can create, change, and delete DNS records using the credentials in its configuration. Review the records and API permissions before running it, and keep `config.toml` private.

## Features

- Resolve public addresses from configurable HTTP services or use static addresses.
- Manage dynamic A, AAAA, and PTR records, along with static address and text records such as TXT and MX.
- Create configured records that are missing from the provider and update records when their values change.
- Poll address sources at a configurable interval (derived from the minimum record TTL by default) and follow activity through structured logs.
- Load multiple configuration files in order and share record settings across DNS names.

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

## Configuration files and shared record settings

Pass `--config` more than once to apply files from left to right. Later files override earlier values; tables merge by key, while arrays (including `provider.records`) replace the earlier array. If no file is specified, the default is `config.toml`.

```sh
cargo run -- --config config.toml --config local.toml ddns
```

For names in the same DNS zone, use `hostnames` to share one record's type, TTL, and value:

```toml
[[provider.records]]
domain = "example.com"
hostnames = ["a", "b"] # a.example.com and b.example.com
type = "dynamic-ipv4"
ttl = 300
```

Use `domains = ["example.com", "example.net"]` with `hostname = "home"` for the same host in several GleSYS zones. Both plural fields can be combined. Use `hostname = "*"` for a DNS wildcard such as `*.example.com`; the app sends `*` as the GleSYS host, so GleSYS must accept that record. A wildcard covers names without an explicit record; it does not replace the zone apex (`@`). Each expanded record is managed separately, so `record_id` can only be set when the entry expands to one record.

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

## Contributing

Issues and pull requests are welcome. Before submitting changes, run:

```sh
cargo fmt --all --check
cargo check --locked
cargo test --locked
```

Records with the same name and DNS type are matched by their current value. If several records could match a changed value, set `record_id` explicitly; the updater refuses ambiguous updates. Explicit IDs must belong to the configured name, zone, and type.
