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
- Native DNS providers: Cloudflare, ArvanCloud, DigitalOcean, Hetzner, PowerDNS, AWS Route 53, OVH, and AcmeDNS.
- Support manual DNS TXT records when no provider integration is used.
- Store certificates, private keys, account keys, and metadata under `~/.pyacme`.
- Renew certificates automatically and run a custom command after renewal.
- Show certificate status in a terminal table.
- Certificate management tools: `inspect`, `export` (PEM / PFX), `revoke`, and `delete`.

## Supported Providers

| Provider | Value | Access token required | Notes |
| --- | --- | --- | --- |
| Cloudflare | `cloudflare` | Yes | Uses the Cloudflare DNS API. |
| ArvanCloud | `arvancloud` | Yes | Uses the ArvanCloud DNS API. |
| DigitalOcean | `digitalocean` | Yes | Uses the DigitalOcean Domains API v2. |
| Hetzner | `hetzner` | Yes | Supports both Hetzner Cloud DNS and Hetzner DNS API. |
| PowerDNS | `powerdns` | Yes | Uses PowerDNS HTTP API (pass `server#key` or set `PDNS_SERVER`). |
| Route 53 | `route53` | Optional | Uses `boto3` (pass `access_key#secret_key` or use AWS IAM/env). |
| OVH | `ovh` | Yes | Supports OAuth2 token or `app_key#app_secret#consumer_key`. |
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
  --renew-command 'systemctl reload nginx'
```

Options:

| Option | Required | Description |
| --- | --- | --- |
| `--domain` | Yes | Domain name. Can be used multiple times. |
| `--provider` | Yes | One of `cloudflare`, `arvancloud`, `digitalocean`, `hetzner`, `powerdns`, `route53`, `ovh`, `acmedns`, or `dns`. |
| `--email` | Yes | Email used for the Let's Encrypt account. |
| `--access-token` | When required | DNS provider API token or credential string. |
| `--renew-command` | Yes | Shell command to run after successful renewal. |
| `--staging` | No | Use Let's Encrypt Staging ACME directory to avoid rate limits. |
| `--log-file` | No | Optional file path to write log output (without ANSI color codes). |

### `list`

Shows certificates saved under `~/.pyacme`:

```bash
python -m pyacmecli list
```

The table includes the domain, certificate path, expiry date, status, renew
command, and last renewal time.

### `inspect`

Inspects detailed information of a locally saved certificate (common name, SANs, serial number, issuer, validity window, days remaining, and private key match):

```bash
python -m pyacmecli inspect example.com
```

### `export`

Exports the certificate and private key into a combined PEM bundle or PKCS#12 / PFX archive:

```bash
# Export as PEM bundle (cert.pem + privkey.pem)
python -m pyacmecli export example.com --format pem-bundle -o ./bundle.pem

# Export as encrypted PKCS#12 / PFX
python -m pyacmecli export example.com --format pfx -p 'MySecretPassword' -o ./cert.pfx
```

Options:

| Option | Required | Description |
| --- | --- | --- |
| `--output`, `-o` | No | Output file path (defaults to `./<domain>-bundle.pem` or `./<domain>-pfx`). |
| `--format`, `-f` | No | Export format: `pem-bundle` (default), `pfx`, or `pkcs12`. |
| `--password`, `-p` | No | Encryption password for PFX/PKCS#12 export. |

### `revoke`

Revokes an issued certificate on the Let's Encrypt / ACME server using the account private key and marks the local certificate status as revoked:

```bash
python -m pyacmecli revoke example.com --reason 0 --yes
```

Options:

| Option | Required | Description |
| --- | --- | --- |
| `--reason` | No | Revocation reason code `0-10` (default: `0` = unspecified, `1` = keyCompromise, `4` = superseded, `5` = cessationOfOperation). |
| `--staging` | No | Target Let's Encrypt Staging ACME directory. |
| `--yes`, `-y` | No | Skip confirmation prompt. |

### `delete`

Safely removes certificate files and metadata for a domain from `~/.pyacme`:

```bash
python -m pyacmecli delete example.com --yes
```

Options:

| Option | Required | Description |
| --- | --- | --- |
| `--yes`, `-y` | No | Skip confirmation prompt. |

### `cron`

Renews certificates that expire within 30 days:

```bash
python -m pyacmecli cron
```

Run it from cron once per day (with optional file logging):

```cron
0 2 * * * /path/to/venv/bin/python -m pyacmecli cron --log-file /var/log/pyacme-cron.log
```

To renew every certificate regardless of expiry date:

```bash
python -m pyacmecli cron --force-renewal
```

A failed renewal or a failing renew command does not stop the run: the
remaining certificates are still processed, each failure is logged, and `cron`
exits with a non-zero status listing the failed domains. Polling the CA for a
challenge or order result gives up after 5 minutes.

Options:

| Option | Required | Description |
| --- | --- | --- |
| `--force-renewal` | No | Force renewal certificates regardless of remaining days. |
| `--staging` | No | Override renewal directory to Let's Encrypt Staging. |
| `--log-file` | No | Optional file path to write log output. |

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

### DigitalOcean

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider digitalocean \
  --email admin@example.com \
  --access-token 'digitalocean-api-token' \
  --renew-command 'systemctl reload nginx'
```

### Hetzner

Supports both Hetzner Cloud DNS and Hetzner DNS API:

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider hetzner \
  --email admin@example.com \
  --access-token 'hetzner-api-token' \
  --renew-command 'systemctl reload nginx'
```

### PowerDNS

```bash
python -m pyacmecli new \
  --domain example.com \
  --provider powerdns \
  --email admin@example.com \
  --access-token 'http://pdns.internal:8081#my-secret-key' \
  --renew-command 'systemctl reload nginx'
```

### AWS Route 53

Requires `boto3` (`pip install boto3`). Credentials can be passed via `--access-token 'KEY#SECRET'` or read automatically from AWS environment / IAM roles:

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider route53 \
  --email admin@example.com \
  --access-token 'AWS_ACCESS_KEY#AWS_SECRET_KEY' \
  --renew-command 'systemctl reload nginx'
```

### OVH

Supports OAuth2 bearer token or `app_key#app_secret#consumer_key`:

```bash
python -m pyacmecli new \
  --domain example.com \
  --domain '*.example.com' \
  --provider ovh \
  --email admin@example.com \
  --access-token 'oauth-bearer-token' \
  --renew-command 'systemctl reload nginx'
```

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
