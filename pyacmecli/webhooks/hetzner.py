"""Hetzner DNS provider for ACME DNS-01 challenge.

Two APIs are supported, chosen by the token: Hetzner Cloud DNS
(api.hetzner.cloud, project API token) and the older Hetzner DNS console
API (dns.hetzner.com, 32-character token).
"""

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import HttpProvider, ZoneNotFoundError

CLOUD_API = "https://api.hetzner.cloud/v1"
DNS_CONSOLE_API = "https://dns.hetzner.com/api/v1"


class HetznerZoneNotFoundError(ZoneNotFoundError):
    """Raised when the Hetzner zone cannot be found for a domain."""


class Hetzner(HttpProvider):
    """Hetzner DNS client for _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str | None) -> None:
        api_token = (api_token or "").strip()
        self.is_cloud = len(api_token) != 32
        if self.is_cloud:
            self.base_url = CLOUD_API
            headers = {"Authorization": f"Bearer {api_token}"}
        else:
            self.base_url = DNS_CONSOLE_API
            headers = {"Auth-API-Token": api_token}
        super().__init__(domain, headers)
        self.created_record_id: str | None = None
        try:
            _, self.zone_id = self.find_zone(self._zone_id)
        except ZoneNotFoundError as exc:
            raise HetznerZoneNotFoundError(str(exc)) from exc

    def _zone_id(self, zone: str) -> str | None:
        # Both APIs accept GET /zones?name=<zone> and return {"zones": [...]}.
        zones = self.json(
            "GET", f"{self.base_url}/zones", params={"name": zone}
        ).get("zones", [])
        for z in zones:
            if z.get("name") == zone:
                return str(z["id"])
        return None

    def _rrset_url(self) -> str:
        relative = self.relative_name(self.record_name)
        return f"{self.base_url}/zones/{self.zone_id}/rrsets/{relative}/TXT"

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        relative = self.relative_name(name)
        if self.is_cloud:
            # TXT values must be quoted in the Cloud API.
            records = [{"value": f'"{content}"'}]
            existing = self.request("GET", self._rrset_url(), missing_ok=True)
            if existing is None:
                self.request(
                    "POST",
                    f"{self.base_url}/zones/{self.zone_id}/rrsets",
                    json={
                        "name": relative,
                        "type": "TXT",
                        "ttl": ttl,
                        "records": records,
                    },
                )
            else:
                # Wildcard and apex share one record name; keep both values.
                self.request(
                    "POST",
                    f"{self._rrset_url()}/actions/add_records",
                    json={"records": records},
                )
        else:
            data = self.json(
                "POST",
                f"{self.base_url}/records",
                json={
                    "zone_id": self.zone_id,
                    "type": "TXT",
                    "name": relative,
                    "value": content,
                    "ttl": ttl,
                },
            )
            self.created_record_id = data.get("record", {}).get("id")
        LOG.debug("Added Hetzner TXT record %s", name)

    def delete_txt_record(self) -> None:
        if self.is_cloud:
            self.request("DELETE", self._rrset_url(), missing_ok=True)
            LOG.debug("Deleted Hetzner Cloud TXT rrset %s", self.record_name)
            return

        relative = self.relative_name(self.record_name)
        records = self.json(
            "GET", f"{self.base_url}/records", params={"zone_id": self.zone_id}
        ).get("records", [])
        for rec in records:
            if rec.get("type") == "TXT" and rec.get("name") == relative:
                self.request(
                    "DELETE",
                    f"{self.base_url}/records/{rec['id']}",
                    missing_ok=True,
                )
                LOG.debug("Deleted Hetzner DNS TXT record %s", rec["id"])
        self.created_record_id = None
