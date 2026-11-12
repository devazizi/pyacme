"""Hetzner DNS provider for ACME DNS-01 challenge."""

from typing import Any
import requests

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.func_helper import get_root_domain


class HetznerZoneNotFoundError(Exception):
    """Raised when the Hetzner zone cannot be found for a domain."""

    pass


class Hetzner(Base):
    """Hetzner DNS API client for adding/deleting _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str) -> None:
        self.api_token = api_token
        self.domain = domain
        self.root_domain = get_root_domain(domain)
        self.is_cloud = len(api_token.strip()) != 32

        if self.is_cloud:
            self.base_url = "https://api.hetzner.cloud/v1"
            self.headers = {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            }
        else:
            self.base_url = "https://dns.hetzner.com/api/v1"
            self.headers = {
                "Auth-API-Token": self.api_token,
                "Content-Type": "application/json",
            }

        self.zone_id = self._get_zone_id()
        self.created_record_id: str | None = None

    def _get_zone_id(self) -> str:
        if self.is_cloud:
            resp = requests.get(
                f"{self.base_url}/zones",
                headers=self.headers,
                params={"name": self.root_domain},
                timeout=30,
            )
            resp.raise_for_status()
            zones = resp.json().get("zones", [])
            for z in zones:
                if z.get("name") == self.root_domain:
                    return str(z["id"])
        else:
            resp = requests.get(
                f"{self.base_url}/zones",
                headers=self.headers,
                params={"name": self.root_domain},
                timeout=30,
            )
            resp.raise_for_status()
            zones = resp.json().get("zones", [])
            for z in zones:
                if z.get("name") == self.root_domain:
                    return str(z["id"])

        raise HetznerZoneNotFoundError(
            f"Zone not found on Hetzner for domain: {self.root_domain}"
        )

    def _relative_name(self, name: str) -> str:
        relative = name.removesuffix(f".{self.root_domain}").removesuffix(".")
        return relative if relative else "@"

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        relative_name = self._relative_name(name)

        if self.is_cloud:
            url = f"{self.base_url}/zones/{self.zone_id}/rrsets/actions/set_records"
            payload = {
                "records": [{"value": f'"{content}"'}],
                "type": "TXT",
                "name": relative_name,
                "ttl": ttl,
            }
            resp = requests.post(
                url, headers=self.headers, json=payload, timeout=30
            )
            resp.raise_for_status()
            LOG.debug("Added Hetzner Cloud TXT record for %s", name)
        else:
            url = f"{self.base_url}/records"
            payload = {
                "zone_id": self.zone_id,
                "type": "TXT",
                "name": relative_name,
                "value": content,
                "ttl": ttl,
            }
            resp = requests.post(
                url, headers=self.headers, json=payload, timeout=30
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            self.created_record_id = data.get("record", {}).get("id")
            LOG.debug(
                "Added Hetzner DNS TXT record %s (id: %s)",
                name,
                self.created_record_id,
            )

    def delete_txt_record(self) -> None:
        if self.is_cloud:
            relative_name = f"_acme-challenge.{self.domain}".removesuffix(
                f".{self.root_domain}"
            ).removesuffix(".")
            url = f"{self.base_url}/zones/{self.zone_id}/rrsets/{relative_name}/TXT"
            try:
                requests.delete(url, headers=self.headers, timeout=30)
                LOG.debug(
                    "Deleted Hetzner Cloud TXT record for %s", relative_name
                )
            except Exception as exc:
                LOG.warning(
                    "Could not delete Hetzner Cloud TXT record: %s", exc
                )
        else:
            if self.created_record_id:
                url = f"{self.base_url}/records/{self.created_record_id}"
                try:
                    requests.delete(url, headers=self.headers, timeout=30)
                    LOG.debug(
                        "Deleted Hetzner DNS TXT record id %s",
                        self.created_record_id,
                    )
                    self.created_record_id = None
                except Exception as exc:
                    LOG.warning(
                        "Could not delete Hetzner record %s: %s",
                        self.created_record_id,
                        exc,
                    )
