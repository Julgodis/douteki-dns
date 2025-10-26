# douteki-dns

`douteki-dns` is a small utility that keeps public DNS records in sync with the network address of a host.

## Features

- Reads a TOML configuration file describing DNS records to manage
- Fetches IPv4/IPv6 addresses from configurable sources (HTTP or static)
- Creates missing DNS records automatically when they are defined in the config but absent in the provider
- Ships with structured tracing so you can follow each API call

## Supported Providers

- GleSYS DNS API

docker pull ghcr.io/<owner>/douteki-dns:<tag>
docker run --rm \
## Getting Started

1. Copy `config.example.toml` to `config.toml` and fill in your provider credentials and records.
2. Build the container image locally (requires Docker, Cargo, and `jq`):

	```bash
	scripts/build-image.sh ghcr.io/<owner>/douteki-dns --push
	```

	Omit `--push` if you only need the image locally. Provide an explicit tag as the second argument to override the version taken from `Cargo.toml`.
3. Run the updater:

	```bash
	docker run --rm \
	  -v "$PWD/config.toml:/app/config.toml:ro" \
	  ghcr.io/<owner>/douteki-dns:<tag> \
	  --config /app/config.toml \
	  ddns
	```

If you prefer to run directly on the host, `cargo run --release -- ddns` still works.

## Commands

The binary offers a small CLI:

- `cargo run -- ddns` – start the continuous updater loop (default).
- `cargo run -- glesys list-records` – fetch and print records from the GleSYS API.

## Logging

Set `RUST_LOG` to control output, e.g.:

```bash
RUST_LOG=debug docker run --rm \
	-v "$PWD/config.toml:/app/config.toml:ro" \
	ghcr.io/<owner>/douteki-dns:<tag> \
	--config /app/config.toml \
	ddns
```

## Container Publishing

Use `scripts/build-image.sh` to build tagged images locally and push them to a registry you control (for example `ghcr.io/<owner>/douteki-dns`). GitHub Container Registry supports both private and public images; choose visibility when you create the package.

## Contributing

Issues and pull requests are welcome. Please run `cargo fmt` and `cargo check` before submitting changes.
