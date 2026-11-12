"""DNS provider integrations and the registry the CLI and ACME flow use."""

from collections.abc import Callable
from typing import NamedTuple

from pyacmecli.webhooks.acmedns import AcmeDNS
from pyacmecli.webhooks.arvancloud import ArvanCloud
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.cloudflare import Cloudflare
from pyacmecli.webhooks.digitalocean import DigitalOcean
from pyacmecli.webhooks.hetzner import Hetzner
from pyacmecli.webhooks.ovh import OVH
from pyacmecli.webhooks.powerdns import PowerDNS
from pyacmecli.webhooks.route53 import Route53


class ProviderSpec(NamedTuple):
    """How to build a provider for (domain, token, config_dir).

    factory is None for the manual 'dns' provider. token_required means
    the provider cannot work without --access-token or its env variable.
    """

    factory: Callable[[str, str | None, str], Base] | None
    token_required: bool


PROVIDERS: dict[str, ProviderSpec] = {
    "arvancloud": ProviderSpec(lambda d, t, c: ArvanCloud(d, t), True),
    "cloudflare": ProviderSpec(lambda d, t, c: Cloudflare(d, t), True),
    "acmedns": ProviderSpec(lambda d, t, c: AcmeDNS(d, c), False),
    "dns": ProviderSpec(None, False),
    "digitalocean": ProviderSpec(
        lambda d, t, c: DigitalOcean(d, t or ""), True
    ),
    "hetzner": ProviderSpec(lambda d, t, c: Hetzner(d, t or ""), True),
    "powerdns": ProviderSpec(lambda d, t, c: PowerDNS(d, t or ""), True),
    # Route 53 can use the default AWS credential chain (env, IAM role).
    "route53": ProviderSpec(lambda d, t, c: Route53(d, t), False),
    "ovh": ProviderSpec(lambda d, t, c: OVH(d, t or ""), True),
}


def provider_token_env(provider: str) -> str:
    """Environment variable that supplies the credential for provider."""
    return f"PYACME_{provider.upper()}_TOKEN"


__all__ = [
    "PROVIDERS",
    "ProviderSpec",
    "provider_token_env",
    "Base",
    "AcmeDNS",
    "ArvanCloud",
    "Cloudflare",
    "DigitalOcean",
    "Hetzner",
    "PowerDNS",
    "Route53",
    "OVH",
]
