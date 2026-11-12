"""DigitalOcean DNS provider for ACME DNS-01 challenge."""

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import HttpProvider

API = "https://api.digitalocean.com/v2/domains"


class DigitalOcean(HttpProvider):
    """DigitalOcean Domains API v2 client for _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str | None) -> None:
        super().__init__(domain, {"Authorization": f"Bearer {api_token}"})
        zone, _ = self.find_zone(self._zone_exists)
        self.base_url = f"{API}/{zone}/records"
        self.created_record_id: int | None = None

    def _zone_exists(self, zone: str) -> str | None:
        found = self.request("GET", f"{API}/{zone}", missing_ok=True)
        return zone if found is not None else None

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        data = self.json(
            "POST",
            self.base_url,
            json={
                "type": "TXT",
                "name": self.relative_name(name),
                "data": content,
                "ttl": ttl,
            },
        )
        self.created_record_id = data.get("domain_record", {}).get("id")
        LOG.debug(
            "Added DigitalOcean TXT record %s (id: %s)",
            name,
            self.created_record_id,
        )

    def delete_txt_record(self) -> None:
        if self.created_record_id is not None:
            self.request(
                "DELETE",
                f"{self.base_url}/{self.created_record_id}",
                missing_ok=True,
            )
            self.created_record_id = None

        # Also remove leftovers of earlier runs, matching the exact name.
        relative = self.relative_name(self.record_name)
        records = self.json(
            "GET",
            self.base_url,
            params={"type": "TXT", "name": self.record_name, "per_page": 200},
        ).get("domain_records", [])
        for rec in records:
            if rec.get("name") == relative:
                self.request(
                    "DELETE", f"{self.base_url}/{rec['id']}", missing_ok=True
                )
                LOG.debug("Deleted DigitalOcean TXT record %s", rec["id"])
