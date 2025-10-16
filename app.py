import json
import os

import click
from src.acme.helper import init_dir, get_certificate_for_domains_dns, PYACME_HOME_PATH
from validators import domain as domain_validator
from tabulate import tabulate


SUPPORTABLE_PROVIDER = ('arvancloud', 'cloudflare', 'acmedns', 'dns')

ARVANCLOUD = 'arvancloud'
CLOUDFLARE = 'cloudflare'

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
    certificates = []

    base_dir = os.path.expanduser(PYACME_HOME_PATH)

    if not os.path.exists(base_dir):
        click.echo(f"Directory {base_dir} does not exist.")
        return

    id = 0
    for root, dirs, files in os.walk(base_dir):
        if "certificate.json" in files:
            cert_path = os.path.join(root, "certificate.json")
            try:
                with open(cert_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    certificates.append([
                        id,
                        data.get('domain'),
                        data.get('certificate_path'),
                        data.get('expiry_date'),
                        data.get('status'),
                        data.get('renew_command'),
                        data.get('last_renewed'),
                    ])
                    id += 1
            except json.JSONDecodeError as err:
                raise err
            except Exception as e:
                raise e

    certificate_table_headers = ['ID', 'Domain', 'Certificate Path',
                                 'Expiry Date', 'Status', 'Renew command', 'Last Renew']
    print(tabulate(certificates, headers=certificate_table_headers, tablefmt="fancy_grid"))


@main_command.command(name='renew', help='Renew certificate')
def certificate_renew():
    click.echo("list of certificate")


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
