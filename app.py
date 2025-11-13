import subprocess
import os
import click
from src.acme.helper import init_dir, get_certificate_for_domains_dns, PYACME_HOME_PATH, renew_certificate
from validators import domain as domain_validator
from tabulate import tabulate
from src.common.certificates import get_certificate_list
from datetime import datetime, timezone, timedelta
from src.happylog import LOG

SUPPORTABLE_PROVIDER = ('arvancloud', 'cloudflare', 'acmedns', 'dns')

ARVANCLOUD = 'arvancloud'
CLOUDFLARE = 'cloudflare'


def run_renew_command_as_subprocess_command(renew_command):
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
            LOG.info(f"Renew command executed successfully.")
        except subprocess.CalledProcessError as e:
            LOG.error(f"Renew command failed: {e.stderr.strip()}")


@click.group()
def main_command():
    pass


@main_command.command(name='init', help='init pyacme script')
def init_pyacme_project():
    init_dir()


@main_command.command(name="cleanup", help="Remove ~/.pyacme directory and remove everything be careful")
def cleanup():
    pass


@main_command.command(name='list', help='List of certificates')
def certificate_list():
    base_dir = os.path.expanduser(PYACME_HOME_PATH)

    if not os.path.exists(base_dir):
        click.echo(f"Directory {base_dir} does not exist.")
        return

    certificates = get_certificate_list(base_dir)
    certificate_table_headers = ['ID', 'Domain', 'Certificate Path',
                                 'Expiry Date', 'Status', 'Renew command', 'Last Renew']
    print(tabulate(certificates, headers=certificate_table_headers, tablefmt="fancy_grid"))


@main_command.command(name='cron', help='Renew certificate')
@click.option("--force-renewal", is_flag=True, help="Force renewal certificates")
def certificate_renew(force_renewal: bool=False):
    base_dir = os.path.expanduser(PYACME_HOME_PATH)

    if not os.path.exists(base_dir):
        click.echo(f"Directory {base_dir} does not exist.")
        return

    now = datetime.now(timezone.utc)
    one_month_later = now + timedelta(days=30)

    certificates = get_certificate_list(base_dir)
    for certificate in certificates:
        renew_command = certificate[5]
        if not force_renewal:
            certificate_domain = certificate[1]
            expiry_date = certificate[3]
            target_time = datetime.fromisoformat(f"{expiry_date}".replace("Z", "+00:00"))
            if target_time <= one_month_later:
                LOG.info(f"Start renewing certificate {certificate_domain}")
                renew_certificate(certificate[2].replace('/cert.pem', '/certificate.json'))
                run_renew_command_as_subprocess_command(renew_command)
            else:
                LOG.info(f"Target certificate {certificate_domain} is more than 30days")
        else:
            LOG.warning("Force renewing certificates")
            renew_certificate(certificate[2].replace('/cert.pem', '/certificate.json'))
            run_renew_command_as_subprocess_command(renew_command)

@main_command.command(name='new', help='Get new certificate')
@click.option('--domain', help='domain name for example *.example.com', multiple=True, required=True)
@click.option('--provider', help='provider name if has special provider to set it dns, acmedns, arvancloud, '
                                 'cloudflare, aws', required=True)
@click.option('--access-token', help='ArvanCloud or Cloudflare access token', required=True)
@click.option('--email', help='Email address', required=True)
@click.option('--renew-command', help='Renew commands e.g myapp --reload', required=True)
def certificate_new(domain, provider, access_token, email, renew_command):
    for _domain in domain:
        domain_validator(_domain)

    if provider not in SUPPORTABLE_PROVIDER:
        raise Exception(f"Invalid provider, valid providers {SUPPORTABLE_PROVIDER}")

    if provider:
        if provider == ARVANCLOUD and access_token is None:
            click.UsageError("--access_token required when provider is arvancloud")
        elif provider == CLOUDFLARE and access_token is None:
            click.UsageError("--access_token required when provider is cloudflare")
        else:
            pass

    get_certificate_for_domains_dns(domain, provider, email, access_token, renew_command)

if __name__ == '__main__':
    main_command()
