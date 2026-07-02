"""CLI entrypoint for pyacme - ACME/Let's Encrypt certificate management."""

import os
import subprocess
from datetime import datetime, timedelta, timezone

import click
from tabulate import tabulate
from validators import domain as domain_validator

from pyacmecli.acme.helper import (
    PYACME_HOME_PATH,
    get_certificate_for_domains_dns,
    init_dir,
    renew_certificate,
)
from pyacmecli.common.certificates import get_certificate_list
from pyacmecli.happylog import LOG, set_log_level, set_verbosity

SUPPORTABLE_PROVIDER = ("arvancloud", "cloudflare", "acmedns", "dns")
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


def normalize_dns_servers(dns_servers: tuple[str, ...]) -> list[str] | None:
    """Normalize repeated/comma-separated --dns-server values."""
    normalized = [
        server.strip()
        for value in dns_servers
        for server in value.split(",")
        if server.strip()
    ]
    return normalized or None


def run_renew_command_as_subprocess_command(renew_command: str | None) -> None:
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
            )
            LOG.info("Renew command executed successfully.")
        except subprocess.CalledProcessError as e:
            LOG.error(f"Renew command failed: {e.stderr.strip()}")


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
@click.pass_context
def main_command(
    ctx: click.Context, verbose: bool = False, log_level: str | None = None
) -> None:
    """Root CLI group; sets verbosity and log level."""
    ctx.ensure_object(dict)
    ctx.obj["VERBOSE"] = verbose
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
@click.pass_context
def certificate_list(ctx: click.Context) -> None:
    """List all certificates in the pyacme home directory."""
    base_dir = os.path.expanduser(PYACME_HOME_PATH)

    if not os.path.exists(base_dir):
        click.echo(f"Directory {base_dir} does not exist.")
        return

    certificates = get_certificate_list(base_dir)
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


@main_command.command(name="cron", help="Renew certificate")
@click.option(
    "--force-renewal", is_flag=True, help="Force renewal certificates"
)
@click.pass_context
def certificate_renew(ctx: click.Context, force_renewal: bool = False) -> None:
    """Renew certificates that expire within 30 days, or all if --force-renewal."""
    base_dir = os.path.expanduser(PYACME_HOME_PATH)

    if not os.path.exists(base_dir):
        click.echo(f"Directory {base_dir} does not exist.")
        return

    now = datetime.now(timezone.utc)
    one_month_later = now + timedelta(days=30)

    certificates = get_certificate_list(base_dir)
    for cert in certificates:
        cert_json_path = cert.certificate_path.replace(
            "/cert.pem", "/certificate.json"
        )
        if not force_renewal:
            target_time = datetime.fromisoformat(
                cert.expiry_date.replace("Z", "+00:00")
            )
            if target_time <= one_month_later:
                LOG.info(f"Start renewing certificate {cert.domain}")
                renew_certificate(cert_json_path)
                run_renew_command_as_subprocess_command(cert.renew_command)
            else:
                LOG.info(
                    f"Target certificate {cert.domain} is more than 30 days away"
                )
        else:
            LOG.warning("Force renewing certificates")
            renew_certificate(cert_json_path)
            run_renew_command_as_subprocess_command(cert.renew_command)


@main_command.command(name="new", help="Get new certificate")
@click.option(
    "--domain",
    help="domain name for example *.example.com",
    multiple=True,
    required=True,
)
@click.option(
    "--provider",
    help="provider name if has special provider to set it dns, acmedns, arvancloud, "
    "cloudflare",
    required=True,
)
@click.option(
    "--access-token",
    help="ArvanCloud or Cloudflare access token",
    required=False,
)
@click.option("--email", help="Email address", required=True)
@click.option(
    "--renew-command", help="Renew commands e.g myapp --reload", required=True
)
@click.option(
    "--dns-server",
    "dns_servers",
    multiple=True,
    help=(
        "DNS resolver IP to use while checking TXT propagation. "
        "Can be used multiple times or comma-separated. "
        "Defaults to the system DNS configuration."
    ),
)
@click.pass_context
def certificate_new(
    ctx: click.Context,
    domain: tuple[str, ...],
    provider: str,
    access_token: str | None,
    email: str,
    renew_command: str,
    dns_servers: tuple[str, ...],
) -> None:
    """Request a new certificate for the given domain(s) and provider."""
    for _domain in domain:
        domain_validator(_domain)

    if provider not in SUPPORTABLE_PROVIDER:
        raise click.ClickException(
            f"Invalid provider, valid providers {SUPPORTABLE_PROVIDER}"
        )

    if provider == ARVANCLOUD and access_token is None:
        raise click.ClickException(
            "--access-token required when provider is arvancloud"
        )
    if provider == CLOUDFLARE and access_token is None:
        raise click.ClickException(
            "--access-token required when provider is cloudflare"
        )

    get_certificate_for_domains_dns(
        list(domain),
        provider,
        email,
        access_token,
        renew_command,
        dns_servers=normalize_dns_servers(dns_servers),
    )


if __name__ == "__main__":
    main_command()
