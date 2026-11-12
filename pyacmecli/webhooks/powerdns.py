"""PowerDNS provider for ACME DNS-01 challenge."""

import os
import requests

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.func_helper import get_root_domain


class PowerDNS(Base):
    """PowerDNS HTTP API client for adding/deleting _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str) -> None:
        self.domain = domain
        self.root_domain = get_root_domain(domain)

        # Support format 'http://pdns-host:8081#my-key' or just 'my-key' with PDNS_SERVER env
        if "#" in api_token:
            self.server_url, self.api_key = api_token.split("#", 1)
        else:
            self.server_url = os.environ.get(
                "PDNS_SERVER", "http://localhost:8081"
            )
            self.api_key = api_token

        self.server_url = self.server_url.rstrip("/")
        if not self.server_url.endswith("/api/v1"):
            self.server_url += "/api/v1"

        self.base_url = (
            f"{self.server_url}/servers/localhost/zones/{self.root_domain}."
        )
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }
        self.last_record_name: str | None = None

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        self.last_record_name = name.rstrip(".") + "."
        payload = {
            "rrsets": [
                {
                    "name": self.last_record_name,
                    "type": "TXT",
                    "ttl": ttl,
                    "changetype": "REPLACE",
                    "records": [{"content": f'"{content}"', "disabled": False}],
                }
            ]
        }
        resp = requests.patch(
            self.base_url, headers=self.headers, json=payload, timeout=30
        )
        resp.raise_for_status()
        LOG.debug("Added PowerDNS TXT record: %s", self.last_record_name)

    def delete_txt_record(self) -> None:
        if not self.last_record_name:
            self.last_record_name = f"_acme-challenge.{self.domain}."
        payload = {
            "rrsets": [
                {
                    "name": self.last_record_name,
                    "type": "TXT",
                    "changetype": "DELETE",
                }
            ]
        }
        try:
            resp = requests.patch(
                self.base_url, headers=self.headers, json=payload, timeout=30
            )
            resp.raise_for_status()
            LOG.debug("Deleted PowerDNS TXT record: %s", self.last_record_name)
        except Exception as exc:
            LOG.warning("Could not delete PowerDNS TXT record: %s", exc)
