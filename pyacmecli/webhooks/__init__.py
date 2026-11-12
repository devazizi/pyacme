"""Webhooks package containing DNS provider integrations."""

from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.acmedns import AcmeDNS
from pyacmecli.webhooks.arvancloud import ArvanCloud
from pyacmecli.webhooks.cloudflare import Cloudflare
from pyacmecli.webhooks.digitalocean import DigitalOcean
from pyacmecli.webhooks.hetzner import Hetzner
from pyacmecli.webhooks.powerdns import PowerDNS
from pyacmecli.webhooks.route53 import Route53
from pyacmecli.webhooks.ovh import OVH

__all__ = [
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
