"""Cloudflare DNS provider for ACME DNS-01 challenge."""

from typing import Any

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import HttpProvider, ZoneNotFoundError

API = "https://api.cloudflare.com/client/v4"


class CloudflareZoneNotFoundError(ZoneNotFoundError):
    """Raised when no Cloudflare zone contains the domain."""


class Cloudflare(HttpProvider):
    """Cloudflare API v4 client for _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str | None) -> None:
        super().__init__(domain, {"Authorization": f"Bearer {api_token}"})
        try:
            _, zone_id = self.find_zone(self._zone_id)
        except ZoneNotFoundError as exc:
            raise CloudflareZoneNotFoundError(str(exc)) from exc
        self.base_url = f"{API}/zones/{zone_id}/dns_records"

    def _zone_id(self, zone: str) -> str | None:
        result = self.json("GET", f"{API}/zones", params={"name": zone})
        zones = result.get("result") or []
        return str(zones[0]["id"]) if zones else None

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        result: dict[str, Any] = self.json(
            "POST",
            self.base_url,
            json={"type": "TXT", "name": name, "content": content, "ttl": ttl},
        )
        if not result.get("success"):
            raise RuntimeError(
                f"Cloudflare rejected TXT record {name}: {result.get('errors')}"
            )
        LOG.debug("Added Cloudflare TXT record %s", name)

    def delete_txt_record(self) -> None:
        records = self.json(
            "GET",
            self.base_url,
            params={"type": "TXT", "name": self.record_name, "per_page": 100},
        ).get("result", [])
        for record in records:
            # The API filter is exact; checking again protects sibling names.
            if record.get("name") != self.record_name:
                continue
            self.request("DELETE", f"{self.base_url}/{record['id']}")
            LOG.debug("Deleted Cloudflare TXT record %s", record["id"])
