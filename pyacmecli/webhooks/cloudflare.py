"""Cloudflare DNS provider for ACME DNS-01 challenge."""

from typing import Any

import requests

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.func_helper import get_root_domain


class CloudflareZoneNotFoundError(Exception):
    """Raised when the Cloudflare zone ID cannot be resolved for a domain."""

    pass


class Cloudflare(Base):
    """Cloudflare API client for adding/deleting _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str) -> None:
        self.api_token = api_token
        self.domain = domain
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        zone_id = self._get_zone_id(domain)
        self.base_url = (
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )

    def _get_zone_id(self, domain: str) -> str:
        url = "https://api.cloudflare.com/client/v4/zones"
        params = {"name": get_root_domain(domain)}
        resp = requests.get(
            url, headers=self.headers, params=params, timeout=30
        )
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        if result.get("success") and result.get("result"):
            return result["result"][0]["id"]
        raise CloudflareZoneNotFoundError(
            f"Zone ID not found for domain: {domain}"
        )

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        payload = {"type": "TXT", "name": name, "content": content, "ttl": ttl}
        response = requests.post(
            self.base_url, headers=self.headers, json=payload, timeout=30
        )
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        if not result.get("success"):
            raise RuntimeError(
                f"Cloudflare rejected TXT record {name}: {result.get('errors')}"
            )
        LOG.debug("Added Cloudflare TXT record %s", name)

    def delete_txt_record(self) -> None:
        """Delete TXT records named exactly _acme-challenge.<domain>.

        The name filter is exact on the API side and checked again here, so
        records of sibling names (e.g. _acme-challenge.app2 when cleaning
        _acme-challenge.app) are never touched.
        """
        record_name = f"_acme-challenge.{self.domain}"
        resp = requests.get(
            self.base_url,
            headers=self.headers,
            params={"type": "TXT", "name": record_name, "per_page": 100},
            timeout=30,
        )
        resp.raise_for_status()

        for record in resp.json().get("result", []):
            if record.get("name") != record_name:
                continue
            del_resp = requests.delete(
                f"{self.base_url}/{record['id']}",
                headers=self.headers,
                timeout=30,
            )
            del_resp.raise_for_status()
            LOG.debug("Deleted Cloudflare TXT record %s", record["id"])
