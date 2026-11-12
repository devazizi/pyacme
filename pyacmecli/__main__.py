"""CLI entrypoint for pyacme - ACME/Let's Encrypt certificate management."""

import functools
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone

import click
from tabulate import tabulate

from pyacmecli.acme.helper import (
    DEFAULT_KEY_TYPE,
    KEY_TYPES,
    PYACME_HOME_PATH,
    delete_certificate_data,
    export_certificate,
    get_certificate_for_domains_dns,
    init_dir,
    inspect_certificate,
    pyacme_lock,
    renewal_window,
    renew_certificate,
    revoke_certificate,
    validate_domain_name,
)
from pyacmecli.common.certificates import get_certificate_list
from pyacmecli.common.fsutil import (
    PUBLIC_FILE_MODE,
    LockBusyError,
    write_atomic,
)
from pyacmecli.happylog import (
    LOG,
    set_log_file,
    set_log_level,
    set_verbosity,
)

SUPPORTABLE_PROVIDER = (
    "arvancloud",
    "cloudflare",
    "acmedns",
    "dns",
    "digitalocean",
    "hetzner",
    "powerdns",
    "route53",
    "ovh",
)
TOKEN_REQUIRED_PROVIDERS = (
    "arvancloud",
    "cloudflare",
    "digitalocean",
    "hetzner",
    "powerdns",
    "ovh",
)
ARVANCLOUD = "arvancloud"
CLOUDFLARE = "cloudflare"

CERTIFICATE_TABLE_HEADERS = [
    "ID",
    "Domain",
    "Certificate Path",
    "Expiry Date",
    "Status",
    "Renew command",
    "Last Renew",
]


def locked(func):
    """Run a command while holding the pyacme lock."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            lock = pyacme_lock()
            lock.__enter__()
        except LockBusyError as exc:
            raise click.ClickException(str(exc))
        try:
            return func(*args, **kwargs)
        finally:
            lock.__exit__(None, None, None)

    return wrapper


RENEW_COMMAND_TIMEOUT = 600


def renew_command_env(cert) -> dict[str, str]:
    """Variables that tell a renew command which certificate changed."""
    cert_dir = os.path.dirname(cert.certificate_path)
    return {
        "PYACME_DOMAIN": cert.domain,
        "PYACME_CERT_DIR": cert_dir,
        "PYACME_CERT_PATH": cert.certificate_path,
        "PYACME_KEY_PATH": os.path.join(cert_dir, "privkey.pem"),
    }


def run_renew_command_as_subprocess_command(
    renew_command: str | None,
    env: dict[str, str] | None = None,
    timeout: int = RENEW_COMMAND_TIMEOUT,
) -> bool:
    """Run the post-renewal command; return False if it failed or hung.

    env is added to the inherited environment so the command can tell
    which certificate it is reloading.
    """
    if renew_command and renew_command.strip():
        try:
            LOG.info(f"Running renew command: {renew_command}")
            subprocess.run(
                renew_command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={**os.environ, **(env or {})},
                timeout=timeout,
            )
            LOG.info("Renew command executed successfully.")
        except subprocess.CalledProcessError as e:
            LOG.error(f"Renew command failed: {e.stderr.strip()}")
            return False
        except subprocess.TimeoutExpired:
            LOG.error(f"Renew command timed out after {timeout}s")
            return False
    return True


def _metric_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def write_metrics_file(
    path: str, base_dir: str, failed_domains: set[str], now: datetime
) -> None:
    """Write a Prometheus textfile-collector file describing the last run."""
    lines = [
        "# HELP pyacme_certificate_expiry_timestamp_seconds Certificate "
        "notAfter as a Unix timestamp.",
        "# TYPE pyacme_certificate_expiry_timestamp_seconds gauge",
    ]
    certificates = get_certificate_list(base_dir)
    for cert in certificates:
        try:
            expiry = datetime.fromisoformat(
                cert.expiry_date.replace("Z", "+00:00")
            ).timestamp()
        except ValueError:
            continue
        lines.append(
            "pyacme_certificate_expiry_timestamp_seconds"
            f'{{domain="{_metric_label(cert.domain)}"}} {expiry:.0f}'
        )
    lines += [
        "# HELP pyacme_renewal_failed 1 if the last cron run failed to renew "
        "the certificate or run its renew command.",
        "# TYPE pyacme_renewal_failed gauge",
    ]
    for cert in certificates:
        failed = 1 if cert.domain in failed_domains else 0
        lines.append(
            f'pyacme_renewal_failed{{domain="{_metric_label(cert.domain)}"}} '
            f"{failed}"
        )
    lines += [
        "# HELP pyacme_cron_last_run_timestamp_seconds When cron last ran.",
        "# TYPE pyacme_cron_last_run_timestamp_seconds gauge",
        f"pyacme_cron_last_run_timestamp_seconds {now.timestamp():.0f}",
    ]
    write_atomic(path, "\n".join(lines) + "\n", PUBLIC_FILE_MODE)


@click.group(
    help=(
        "PyACME CLI - Get Let's Encrypt certificates with DNS providers "
        "(Arvancloud, Cloudflare, AcmeDNS) or manual DNS records. "
        "Use --verbose or --log-level DEBUG for debug output."
    )
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable debug log level (same as --log-level DEBUG).",
    default=False,
)
@click.option(
    "--log-level",
    type=click.Choice(
        ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False
    ),
    default=None,
    help="Set log level explicitly. Overrides --verbose when set.",
)
@click.option(
    "--log-file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Optional file path to write structured log output.",
)
@click.option(
    "--staging",
    is_flag=True,
    default=False,
    help="Use Let's Encrypt Staging ACME directory.",
)
@click.option(
    "--directory-url",
    envvar="PYACME_DIRECTORY_URL",
    default=None,
    help=(
        "ACME directory URL of another CA (e.g. step-ca, Pebble). Stored "
        "with new certificates and reused on renewal. Overrides --staging."
    ),
)
@click.pass_context
def main_command(
    ctx: click.Context,
    verbose: bool = False,
    log_level: str | None = None,
    log_file: str | None = None,
    staging: bool = False,
    directory_url: str | None = None,
) -> None:
    """Root CLI group; sets verbosity, log level, log file, and staging."""
    ctx.ensure_object(dict)
    ctx.obj["VERBOSE"] = verbose
    ctx.obj["LOG_FILE"] = log_file
    ctx.obj["STAGING"] = staging
    ctx.obj["DIRECTORY_URL"] = directory_url

    if log_file:
        set_log_file(log_file)

    if log_level is not None:
        set_log_level(log_level)
    else:
        set_verbosity(verbose)


@main_command.command(name="init", help="Init pyacme directory structure")
@click.pass_context
def init_pyacme_project(ctx: click.Context) -> None:
    """Create the pyacme home directory (~/.pyacme)."""
    init_dir()


# @main_command.command(
#     name="cleanup", help="Remove ~/.pyacme directory and remove everything be careful"
# )
# def cleanup():
#     pass


@main_command.command(name="list", help="List of certificates")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Print a JSON array instead of a table.",
)
@click.pass_context
def certificate_list(ctx: click.Context, as_json: bool = False) -> None:
    """List all certificates in the pyacme home directory."""
    base_dir = os.path.expanduser(PYACME_HOME_PATH)

    if not os.path.exists(base_dir):
        if as_json:
            click.echo("[]")
            return
        click.echo(f"Directory {base_dir} does not exist.")
        return

    certificates = get_certificate_list(base_dir)
    if as_json:
        click.echo(json.dumps([c._asdict() for c in certificates], indent=2))
        return
    rows = [
        (
            c.id,
            c.domain,
            c.certificate_path,
            c.expiry_date,
            c.status,
            c.renew_command,
            c.last_renewed,
        )
        for c in certificates
    ]
    click.echo(
        tabulate(rows, headers=CERTIFICATE_TABLE_HEADERS, tablefmt="fancy_grid")
    )


@main_command.command(
    name="inspect", help="Inspect certificate details for a domain"
)
@click.argument("domain")
@click.pass_context
def certificate_inspect(ctx: click.Context, domain: str) -> None:
    """Inspect detailed information of a locally stored certificate."""
    try:
        details = inspect_certificate(domain)
        table_rows = [(k, v) for k, v in details.items()]
        click.echo(
            tabulate(
                table_rows, headers=["Property", "Value"], tablefmt="fancy_grid"
            )
        )
    except Exception as exc:
        raise click.ClickException(str(exc))


@main_command.command(
    name="delete", help="Delete certificate data for a domain"
)
@click.argument("domain")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
@click.pass_context
@locked
def certificate_delete(
    ctx: click.Context, domain: str, yes: bool = False
) -> None:
    """Safely delete certificate data for a domain from ~/.pyacme."""
    if not yes:
        click.confirm(
            f"Are you sure you want to permanently delete certificate data for '{domain}'?",
            abort=True,
        )
    try:
        deleted = delete_certificate_data(domain)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    if deleted:
        click.echo(f"Successfully deleted certificate data for '{domain}'.")
    else:
        click.echo(f"No certificate data found for '{domain}'.")


@main_command.command(
    name="export",
    help="Export certificate bundle (PEM bundle or PKCS#12/PFX)",
)
@click.argument("domain")
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, writable=True),
    required=False,
    help="Output file path.",
)
@click.option(
    "--format",
    "-f",
    "export_format",
    type=click.Choice(["pem-bundle", "pfx", "pkcs12"], case_sensitive=False),
    default="pem-bundle",
    help="Export format: pem-bundle (cert+key) or pfx/pkcs12.",
)
@click.option(
    "--password",
    "-p",
    default=None,
    help="Optional encryption password for PFX/PKCS#12 export.",
)
@click.pass_context
def certificate_export(
    ctx: click.Context,
    domain: str,
    output: str | None,
    export_format: str,
    password: str | None,
) -> None:
    """Export certificate and private key to a bundle file."""
    if output is None:
        ext = "pfx" if export_format in ("pfx", "pkcs12") else "bundle.pem"
        output = f"./{domain}-{ext}"
    try:
        exported_path = export_certificate(
            domain, output, export_format=export_format, password=password
        )
        click.echo(f"Certificate exported successfully to: {exported_path}")
    except Exception as exc:
        raise click.ClickException(str(exc))


@main_command.command(
    name="revoke",
    help="Revoke an issued certificate with Let's Encrypt",
)
@click.argument("domain")
@click.option(
    "--reason",
    type=click.IntRange(0, 10),
    default=0,
    help="Revocation reason code (0=unspecified, 1=keyCompromise, 4=superseded, 5=cessationOfOperation).",
)
@click.option(
    "--staging",
    is_flag=True,
    default=None,
    help="Use Let's Encrypt Staging ACME directory.",
)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
@click.pass_context
@locked
def certificate_revoke(
    ctx: click.Context,
    domain: str,
    reason: int = 0,
    staging: bool | None = None,
    yes: bool = False,
) -> None:
    """Revoke an issued certificate from the ACME server."""
    if not yes:
        click.confirm(
            f"Are you sure you want to revoke the certificate for '{domain}'?",
            abort=True,
        )
    effective_staging = (
        staging
        if staging is not None
        else (True if (ctx.obj or {}).get("STAGING") else None)
    )
    try:
        revoke_certificate(
            domain,
            reason=reason,
            staging=effective_staging,
            directory_url=(ctx.obj or {}).get("DIRECTORY_URL"),
        )
        click.echo(f"Certificate for '{domain}' has been revoked.")
    except Exception as exc:
        raise click.ClickException(str(exc))


@main_command.command(name="cron", help="Renew certificate")
@click.option(
    "--force-renewal", is_flag=True, help="Force renewal certificates"
)
@click.option(
    "--staging",
    is_flag=True,
    default=None,
    help="Use Let's Encrypt Staging ACME directory.",
)
@click.option(
    "--log-file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Optional file path to write log output.",
)
@click.option(
    "--metrics-file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help=(
        "Write certificate expiry and renewal status in Prometheus "
        "textfile-collector format to this path."
    ),
)
@click.option(
    "--renew-before-days",
    type=click.IntRange(1, 365),
    default=None,
    help=(
        "Renew certificates expiring within this many days. "
        "Default: one third of each certificate's lifetime."
    ),
)
@click.pass_context
@locked
def certificate_renew(
    ctx: click.Context,
    force_renewal: bool = False,
    staging: bool | None = None,
    log_file: str | None = None,
    metrics_file: str | None = None,
    renew_before_days: int | None = None,
) -> None:
    """Renew certificates that are due, or all with --force-renewal.

    Revoked certificates are skipped unless --force-renewal is given.
    """
    effective_log_file = log_file or (ctx.obj or {}).get("LOG_FILE")
    if effective_log_file:
        set_log_file(effective_log_file)

    effective_staging = (
        staging
        if staging is not None
        else (True if (ctx.obj or {}).get("STAGING") else None)
    )

    base_dir = os.path.expanduser(PYACME_HOME_PATH)

    if not os.path.exists(base_dir):
        click.echo(f"Directory {base_dir} does not exist.")
        return

    now = datetime.now(timezone.utc)

    directory_url = (ctx.obj or {}).get("DIRECTORY_URL")
    certificates = get_certificate_list(base_dir)
    failed: list[str] = []
    failed_domains: set[str] = set()
    for cert in certificates:
        cert_json_path = cert.certificate_path.replace(
            "/cert.pem", "/certificate.json"
        )
        # One broken certificate must not block renewal of the others, so
        # every failure is recorded here and reported once at the end.
        try:
            if force_renewal:
                LOG.warning(f"Force renewing certificate {cert.domain}")
            elif cert.status == "revoked":
                LOG.warning(
                    f"Skipping revoked certificate {cert.domain}; "
                    "use --force-renewal to reissue it"
                )
                continue
            else:
                expires = datetime.fromisoformat(
                    cert.expiry_date.replace("Z", "+00:00")
                )
                window = (
                    timedelta(days=renew_before_days)
                    if renew_before_days is not None
                    else renewal_window(cert.certificate_path)
                )
                remaining = expires - now
                if remaining > window:
                    LOG.info(
                        f"Certificate {cert.domain} expires in "
                        f"{remaining.days} days; renewal starts at "
                        f"{window.days} days"
                    )
                    continue
                LOG.info(f"Start renewing certificate {cert.domain}")
            renew_kwargs = {"staging": effective_staging}
            if directory_url:
                renew_kwargs["directory_url"] = directory_url
            renew_certificate(cert_json_path, **renew_kwargs)
        except Exception as exc:
            LOG.error(
                f"Renewal failed for {cert.domain}: {type(exc).__name__}: {exc}"
            )
            failed.append(cert.domain)
            failed_domains.add(cert.domain)
            continue

        if not run_renew_command_as_subprocess_command(
            cert.renew_command, env=renew_command_env(cert)
        ):
            failed.append(f"{cert.domain} (renew command)")
            failed_domains.add(cert.domain)

    if metrics_file:
        try:
            write_metrics_file(metrics_file, base_dir, failed_domains, now)
        except OSError as exc:
            LOG.error(f"Could not write metrics file {metrics_file}: {exc}")
            failed.append(f"metrics file {metrics_file}")

    if failed:
        raise click.ClickException(
            f"{len(failed)} of {len(certificates)} certificate(s) failed: "
            + ", ".join(failed)
        )


@main_command.command(name="new", help="Get new certificate")
@click.option(
    "--domain",
    help="domain name for example *.example.com",
    multiple=True,
    required=True,
)
@click.option(
    "--provider",
    help=(
        "DNS provider name: arvancloud, cloudflare, acmedns, dns, "
        "digitalocean, hetzner, powerdns, route53, ovh"
    ),
    required=True,
)
@click.option(
    "--access-token",
    help="Provider API token, key, or credentials string",
    required=False,
)
@click.option("--email", help="Email address", required=True)
@click.option(
    "--renew-command", help="Renew commands e.g myapp --reload", required=True
)
@click.option(
    "--staging",
    is_flag=True,
    default=None,
    help="Use Let's Encrypt Staging ACME directory.",
)
@click.option(
    "--log-file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Optional file path to write log output.",
)
@click.option(
    "--key-type",
    type=click.Choice(KEY_TYPES),
    default=DEFAULT_KEY_TYPE,
    show_default=True,
    help="Certificate key type; a new key is generated on every renewal.",
)
@click.pass_context
@locked
def certificate_new(
    ctx: click.Context,
    domain: tuple[str, ...],
    provider: str,
    access_token: str | None,
    email: str,
    renew_command: str,
    staging: bool | None = None,
    log_file: str | None = None,
    key_type: str = DEFAULT_KEY_TYPE,
) -> None:
    """Request a new certificate for the given domain(s) and provider."""
    effective_log_file = log_file or (ctx.obj or {}).get("LOG_FILE")
    if effective_log_file:
        set_log_file(effective_log_file)

    effective_staging = (
        staging
        if staging is not None
        else (ctx.obj or {}).get("STAGING", False)
    )

    for _domain in domain:
        try:
            validate_domain_name(_domain)
        except ValueError as exc:
            raise click.ClickException(str(exc))

    if provider not in SUPPORTABLE_PROVIDER:
        raise click.ClickException(
            f"Invalid provider, valid providers {SUPPORTABLE_PROVIDER}"
        )

    if provider in TOKEN_REQUIRED_PROVIDERS and access_token is None:
        raise click.ClickException(
            f"--access-token required when provider is {provider}"
        )

    get_certificate_for_domains_dns(
        list(domain),
        provider,
        email,
        access_token,
        renew_command,
        staging=effective_staging,
        directory_url=(ctx.obj or {}).get("DIRECTORY_URL"),
        key_type=key_type,
    )


if __name__ == "__main__":
    main_command()
