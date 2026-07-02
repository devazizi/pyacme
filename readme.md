# PyACME CLI

PyACME CLI is a small Python command line tool for issuing and renewing
Let's Encrypt certificates with DNS-01 validation.

It can create wildcard certificates, manage DNS challenge records through
supported providers, store certificate metadata locally, list existing
certificates, and renew certificates from cron.

## Features

- Issue Let's Encrypt certificates with DNS-01 challenges.
- Support wildcard domains such as `*.example.com`.
- Support multiple names on one certificate.
- Automatically create TXT records with Cloudflare, ArvanCloud, or AcmeDNS.
- Support manual DNS TXT records when no provider integration is used.
- Store certificates, private keys, account keys, and metadata under `~/.pyacme`.
- Renew certificates automatically and run a custom command after renewal.
- Show certificate status in a terminal table.

## Supported Providers

| Provider | Value | Access token required | Notes |
| --- | --- | --- | --- |
| Cloudflare | `cloudflare` | Yes | Uses the Cloudflare DNS API. |
| ArvanCloud | `arvancloud` | Yes | Uses the ArvanCloud DNS API. |
| AcmeDNS | `acmedns` | No | First run asks you to create a CNAME record. |
| Manual DNS | `dns` | No | Prints the TXT record and waits for you to add it. |

## Requirements

- Python 3.12 or newer
- A domain you control
- DNS access for `_acme-challenge` records
- Network access to Let's Encrypt and your DNS provider API

## Installation

```bash
pip install pyacmecli
```

You can run the CLI with:

```bash
python -m pyacmecli --help
```

## Quick Start

Initialize the local PyACME directory:

```bash
python -m pyacmecli init
```

Issue a certificate with Cloudflare:

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

Renew certificates that expire within the next 30 days:

```bash
python -m pyacmecli cron
```

Force renewal for all saved certificates:

```bash
python -m pyacmecli cron --force-renewal
```

## Commands

### `init`

Creates the local data directory:

```bash
python -m pyacmecli init
```

PyACME stores data in:

```text
~/.pyacme
```

### `new`

Requests a new certificate.

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

Options:

| Option | Required | Description |
| --- | --- | --- |
| `--domain` | Yes | Domain name. Can be used multiple times. |
| `--provider` | Yes | One of `cloudflare`, `arvancloud`, `acmedns`, or `dns`. |
| `--email` | Yes | Email used for the Let's Encrypt account. |
| `--access-token` | Cloudflare/ArvanCloud only | DNS provider API token. |
| `--renew-command` | Yes | Shell command to run after successful renewal. |
| `--dns-server` | No | DNS resolver IP used while checking TXT propagation. Can be used multiple times or comma-separated. When omitted, PyACME uses the system DNS configuration. |

### `list`

Shows certificates saved under `~/.pyacme`:

```bash
python -m pyacmecli list
```

The table includes the domain, certificate path, expiry date, status, renew
command, and last renewal time.

### `cron`

Renews certificates that expire within 30 days:

```bash
python -m pyacmecli cron
```

Run it from cron once per day:

```cron
0 2 * * * /path/to/venv/bin/python -m pyacmecli cron
```

To renew every certificate regardless of expiry date:

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
  --access-token 'cloudflare-api-token' \
  --renew-command 'systemctl reload nginx'
```

The token needs permission to read zones and edit DNS records for the target
zone.

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

On the first run, PyACME registers with `auth.acme-dns.io` and prints a CNAME
record. Add that CNAME to your DNS zone, then press Enter to continue.

### Manual DNS

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider dns \
  --email admin@example.com \
  --renew-command 'systemctl reload nginx'
```

PyACME prints the required `_acme-challenge` TXT record and waits until you add
it to DNS.

## Local Files

For each certificate, PyACME creates a directory under `~/.pyacme` using the
first domain name from the request.

Example:

```text
~/.pyacme/example.com/
  account.key.pem
  account_url.result
  cert.pem
  privkey.pem
  certificate.json
```

Do not delete this directory if you want automated renewal to keep working.

## Logging

Enable debug output with:

```bash
python -m pyacmecli --verbose new ...
```

Or set a specific log level:

```bash
python -m pyacmecli --log-level DEBUG list
```

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
  --access-token 'cloudflare-api-token' \
  --renew-command 'docker restart nginx'

python -m pyacmecli list
python -m pyacmecli cron
```

Cron entry:

```cron
0 2 * * * /apps/pyacmecli/.venv/bin/python -m pyacmecli cron
```

## Development

Install dependencies with uv:

```bash
uv sync
```

Run the CLI from the repository:

```bash
uv run python -m pyacmecli --help
```

Build the package:

```bash
uv build
```

Publish the package:

```bash
uv publish
```

Run linting:

```bash
uv run ruff check .
```

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE)
for details.
