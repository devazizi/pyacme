<p align="center">
  <br>
  <h1 align="center">PyACME CLI</h1>
  <p align="center">
    <em>Let's Encrypt certificate management with DNS-01 validation & automatic renewal</em>
    <br>
    <a href="https://pypi.org/project/pyacmecli/"><img src="https://img.shields.io/pypi/v/pyacmecli?style=flat-square" alt="PyPI"></a>
    <a href="https://pypi.org/project/pyacmecli/"><img src="https://img.shields.io/pypi/pyversions/pyacmecli?style=flat-square" alt="Python"></a>
    <a href="https://github.com/anomalyco/pyacme/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square" alt="License"></a>
  </p>
</p>

**PyACME CLI** is a lightweight Python command-line tool for issuing and renewing Let's Encrypt TLS/SSL certificates using **DNS-01 validation**. It supports wildcard certificates, multiple DNS providers, and fully automated renewal via cron.

---

- [Features](#features)
- [Supported Providers](#supported-providers)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [`init`](#init)
  - [`new`](#new)
  - [`list`](#list)
  - [`cron`](#cron)
- [Provider Examples](#provider-examples)
  - [Cloudflare](#cloudflare)
  - [ArvanCloud](#arvancloud)
  - [AcmeDNS](#acmedns)
  - [Manual DNS](#manual-dns)
- [Local Files](#local-files)
- [Logging](#logging)
- [Production Setup Example](#production-setup-example)
- [Development](#development)
- [License](#license)

---

## Features

- Issue Let's Encrypt certificates with **DNS-01 challenges**
- Wildcard domains (`*.example.com`) and **multi-domain SAN certificates**
- Automated TXT record management via **Cloudflare**, **ArvanCloud**, or **AcmeDNS**
- **Manual DNS** mode for providers without an integration
- Local certificate store under `~/.pyacme` (PEM + JSON metadata)
- **Automatic renewal** with custom post-renew hook command
- Certificate status overview in a terminal table
- Configurable DNS resolvers for propagation checks
- Colorized logging with configurable verbosity

## Supported Providers

| Provider | CLI Value | Access Token | Notes |
|----------|-----------|--------------|-------|
| Cloudflare | `cloudflare` | Yes | Cloudflare DNS API |
| ArvanCloud | `arvancloud` | Yes | ArvanCloud DNS API |
| AcmeDNS | `acmedns` | No | Registers subdomain at `auth.acme-dns.io`; first run prints a CNAME record to add to your zone |
| Manual DNS | `dns` | No | Prints the TXT record and waits for you to add it manually |

## Requirements

- Python **3.12+**
- A domain you control
- DNS access to create `_acme-challenge` records
- Network access to `acme-v02.api.letsencrypt.org` and your DNS provider API

## Installation

```bash
pip install pyacmecli
```

Run the CLI:

```bash
python -m pyacmecli --help
```

## Quick Start

Initialize the local data directory:

```bash
python -m pyacmecli init
```

Issue a wildcard certificate with Cloudflare:

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider cloudflare \
  --email admin@example.com \
  --access-token 'cloudflare-api-token' \
  --renew-command 'docker restart nginx'
```

List saved certificates:

```bash
python -m pyacmecli list
```

Renew certificates expiring within 30 days:

```bash
python -m pyacmecli cron
```

Force-renew every certificate:

```bash
python -m pyacmecli cron --force-renewal
```

## Commands

### `init`

Create the local data directory (`~/.pyacme`):

```bash
python -m pyacmecli init
```

### `new`

Request a new certificate.

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider cloudflare \
  --email admin@example.com \
  --access-token 'provider-token' \
  --renew-command 'systemctl reload nginx' \
  --dns-server 1.1.1.1 \
  --dns-server 8.8.8.8
```

| Option | Required | Description |
|--------|----------|-------------|
| `--domain` | Yes | Domain name. Repeatable for SAN certificates. |
| `--provider` | Yes | One of `cloudflare`, `arvancloud`, `acmedns`, `dns`. |
| `--email` | Yes | Email for the Let's Encrypt account registration. |
| `--access-token` | Cloudflare/ArvanCloud only | DNS provider API token. |
| `--renew-command` | Yes | Shell command to run after successful renewal. |
| `--dns-server` | No | DNS resolver IP for TXT propagation checks. Repeatable or comma-separated. Defaults to system DNS. |

### `list`

Display all certificates stored in `~/.pyacme`:

```bash
python -m pyacmecli list
```

Output columns: ID, Domain, Certificate Path, Expiry Date, Status, Renew Command, Last Renew.

### `cron`

Renew certificates expiring within 30 days:

```bash
python -m pyacmecli cron
```

Recommended cron schedule (daily at 2 AM):

```cron
0 2 * * * /path/to/venv/bin/python -m pyacmecli cron
```

Force-renew all certificates regardless of expiry:

```bash
python -m pyacmecli cron --force-renewal
```

## Provider Examples

### Cloudflare

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider cloudflare \
  --email admin@example.com \
  --access-token 'cf-api-token' \
  --renew-command 'systemctl reload nginx'
```

The token requires **Zone:Read** and **DNS:Edit** permissions for the target zone.

### ArvanCloud

```bash
python -m pyacmecli new \
  --domain example.ir \
  --domain '*.example.ir' \
  --provider arvancloud \
  --email admin@example.ir \
  --access-token 'arvancloud-api-token' \
  --renew-command 'docker restart nginx'
```

### AcmeDNS

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider acmedns \
  --email admin@example.com \
  --renew-command 'systemctl reload nginx'
```

On the first run, PyACME registers a subdomain with `auth.acme-dns.io` and prints a CNAME record. Add that CNAME (`_acme-challenge -> <fulldomain>`) to your DNS zone, then press Enter to continue.

### Manual DNS

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider dns \
  --email admin@example.com \
  --renew-command 'systemctl reload nginx'
```

PyACME prints the `_acme-challenge` TXT record value and waits for you to add it to your DNS zone before continuing.

## Local Files

All data is stored under `~/.pyacme/<domain>/`:

```
~/.pyacme/
└── example.com/
    ├── account.key.pem      # ACME account private key (RSA 2048)
    ├── account_url.result   # ACME account URL
    ├── cert.pem             # Issued certificate (full chain)
    ├── privkey.pem          # Certificate private key (RSA 2048)
    ├── certificate.json     # Metadata (expiry, provider, renew command, etc.)
    └── conf.json            # (AcmeDNS only) provider configuration
```

Do **not** delete these directories if you want automated renewal to work.

## Logging

Enable debug output:

```bash
python -m pyacmecli --verbose new ...
```

Set a specific log level:

```bash
python -m pyacmecli --log-level DEBUG list
```

Available levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.

## Production Setup Example

```bash
mkdir -p /apps/pyacmecli
cd /apps/pyacmecli

python3.12 -m venv .venv
source .venv/bin/activate
pip install pyacmecli

python -m pyacmecli init
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider cloudflare \
  --email admin@example.com \
  --access-token 'cf-api-token' \
  --renew-command 'docker restart nginx'

python -m pyacmecli list
python -m pyacmecli cron
```

Cron entry:

```cron
0 2 * * * /apps/pyacmecli/.venv/bin/python -m pyacmecli cron
```

## Development

Clone the repository and install dependencies:

```bash
git clone https://github.com/anomalyco/pyacme.git
cd pyacme
uv sync
```

Run the CLI from the working tree:

```bash
uv run python -m pyacmecli --help
```

Run linting:

```bash
uv run ruff check .
```

Format code:

```bash
uv run ruff format .
```

Run pre-commit checks:

```bash
pre-commit run --all-files --config .pre-commit-config.yaml
```

Build the package:

```bash
uv build
```

Publish to PyPI:

```bash
uv publish
```

## License

```
Apache License 2.0
```

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.
