"""DigitalOcean DNS provider for ACME DNS-01 challenge."""

from typing import Any
import requests

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.func_helper import get_root_domain


class DigitalOcean(Base):
    """DigitalOcean API client for adding/deleting _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str) -> None:
        self.api_token = api_token
        self.domain = domain
        self.root_domain = get_root_domain(domain)
        self.base_url = f"https://api.digitalocean.com/v2/domains/{self.root_domain}/records"
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }
        self.created_record_id: int | None = None

    def _relative_name(self, name: str) -> str:
        relative = name.removesuffix(f".{self.root_domain}").removesuffix(".")
        return relative if relative else "@"

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        relative_name = self._relative_name(name)
        payload = {
            "type": "TXT",
            "name": relative_name,
            "data": content,
            "ttl": ttl,
        }
        response = requests.post(
            self.base_url, headers=self.headers, json=payload, timeout=30
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        self.created_record_id = data.get("domain_record", {}).get("id")
        LOG.debug(
            "Added DigitalOcean TXT record %s (id: %s)",
            name,
            self.created_record_id,
        )

    def delete_txt_record(self) -> None:
        if self.created_record_id is not None:
            delete_url = f"{self.base_url}/{self.created_record_id}"
            resp = requests.delete(delete_url, headers=self.headers, timeout=30)
            if resp.status_code in (200, 204):
                LOG.debug(
                    "Deleted DigitalOcean TXT record id %s",
                    self.created_record_id,
                )
                self.created_record_id = None
                return

        # Fallback: delete records named exactly like our challenge record.
        # Matching on a substring would also remove other hosts' challenges.
        fqdn = f"_acme-challenge.{self.domain}"
        relative = self._relative_name(fqdn)
        try:
            resp = requests.get(
                self.base_url,
                headers=self.headers,
                params={"type": "TXT", "name": fqdn, "per_page": 100},
                timeout=30,
            )
            resp.raise_for_status()
            records = resp.json().get("domain_records", [])
            for rec in records:
                if rec.get("name") == relative:
                    del_url = f"{self.base_url}/{rec['id']}"
                    requests.delete(del_url, headers=self.headers, timeout=30)
                    LOG.debug("Deleted DigitalOcean TXT record %s", rec["id"])
        except Exception as exc:
            LOG.warning("Failed to clean up DigitalOcean TXT record: %s", exc)
