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
- Generate a fresh certificate key (RSA or ECDSA) on every issuance.
- Work with any RFC 8555 CA (`--directory-url`), not only Let's Encrypt.
- Show certificate status as a table or JSON, and export Prometheus metrics.
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
# with AWS Route 53 support
pip install 'pyacmecli[route53]'
```

You can run the CLI with:

```bash
pyacmecli --help
# or
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
| `--access-token` | When required | DNS provider API token or credential string. Prefer `PYACME_<PROVIDER>_TOKEN` (see [Credentials](#credentials)). |
| `--no-store-token` | No | Do not save the credential in `certificate.json`; renewals read it from the environment. |
| `--renew-command` | Yes | Shell command to run after successful renewal. |
| `--key-type` | No | `rsa2048` (default), `rsa4096`, `ec256`, or `ec384`. Stored and reused on renewal. |
| `--staging` | No | Use Let's Encrypt Staging ACME directory to avoid rate limits. |
| `--log-file` | No | Optional file path to write log output (without ANSI color codes). |

Use another ACME CA (step-ca, Pebble, ZeroSSL) with the global
`--directory-url` option or `PYACME_DIRECTORY_URL`. The URL is stored with
the certificate and used again for renewal and revocation:

```bash
pyacmecli --directory-url https://ca.internal/acme/acme/directory new ...
```

### `list`

Shows certificates saved under `~/.pyacme`:

```bash
python -m pyacmecli list
```

The table includes the domain, certificate path, expiry date, status, renew
command, and last renewal time. Use `--json` for machine-readable output:

```bash
pyacmecli list --json
```

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

Renews certificates that are due. A certificate is due when less than one
third of its lifetime remains: 30 days for a 90-day Let's Encrypt
certificate, proportionally less for shorter lifetimes. Revoked
certificates are skipped unless `--force-renewal` is given.

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

Only one `new`, `cron`, `revoke` or `delete` runs at a time. A second run
exits with `Another pyacme process holds ~/.pyacme/.lock` instead of racing
the first one.

The renew command gets these variables, so one command can handle every
certificate, and is stopped after 600 seconds:

| Variable | Value |
| --- | --- |
| `PYACME_DOMAIN` | Certificate name, e.g. `example.com` |
| `PYACME_CERT_DIR` | `~/.pyacme/example.com` |
| `PYACME_CERT_PATH` | `~/.pyacme/example.com/cert.pem` |
| `PYACME_KEY_PATH` | `~/.pyacme/example.com/privkey.pem` |

Options:

| Option | Required | Description |
| --- | --- | --- |
| `--force-renewal` | No | Force renewal certificates regardless of remaining days. |
| `--renew-before-days` | No | Renew certificates expiring within this many days instead of the one-third rule. |
| `--metrics-file` | No | Write Prometheus textfile-collector metrics to this path. |
| `--staging` | No | Override renewal directory to Let's Encrypt Staging. |
| `--log-file` | No | Optional file path to write log output. |

With `--metrics-file /var/lib/node_exporter/textfile/pyacme.prom`, node
exporter's textfile collector exposes:

- `pyacme_certificate_expiry_timestamp_seconds{domain}`
- `pyacme_renewal_failed{domain}` (1 if the last run failed for it)
- `pyacme_cron_last_run_timestamp_seconds`

Example alerts: `pyacme_certificate_expiry_timestamp_seconds - time() < 7 * 86400`
and `time() - pyacme_cron_last_run_timestamp_seconds > 2 * 86400`.

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

## Credentials

Pass provider credentials through `PYACME_<PROVIDER>_TOKEN`, for example
`PYACME_CLOUDFLARE_TOKEN`, instead of `--access-token`; command-line
arguments end up in shell history and are visible in `ps`. On renewal the
variable takes precedence over the stored token, so a rotated token only
needs to be updated in one place.

By default the token is also stored in `certificate.json` (mode `0600`) so
that `cron` works without extra setup. With `new --no-store-token` it is not
stored, and the variable must be set wherever `cron` runs.

## Local Files

For each certificate, PyACME creates a directory under `~/.pyacme` using the
first domain name from the request. ACME accounts are shared: one per CA
directory, under `~/.pyacme/accounts/`.

Example:

```text
~/.pyacme/
  .lock
  accounts/acme-v02.api.letsencrypt.org_directory/
    account.key.pem
    account_url.result
  example.com/
    cert.pem
    privkey.pem
    cert.pem.prev        # previous certificate, for manual rollback
    privkey.pem.prev
    certificate.json
```

Keys, `certificate.json` and account files are written with mode `0600`.
Certificates issued by versions before 0.2.0 keep their per-domain
`account.key.pem` and `account_url.result`; do not delete those. To tighten
permissions on files written by older versions:

```bash
find ~/.pyacme -type f \( -name 'privkey.pem*' -o -name 'account.key.pem' \
  -o -name '*.json' -o -name '*.result' \) -exec chmod 600 {} +
```

Rolling back a bad renewal: copy `cert.pem.prev` and `privkey.pem.prev` over
`cert.pem` and `privkey.pem`, then run the renew command.

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
