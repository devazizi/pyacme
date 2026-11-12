"""PowerDNS provider for ACME DNS-01 challenge."""

import os

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import HttpProvider


class PowerDNS(HttpProvider):
    """PowerDNS HTTP API client for _acme-challenge TXT records.

    The credential is 'http://pdns-host:8081#api-key', or just the key with
    the server URL in PDNS_SERVER (default http://localhost:8081).
    """

    def __init__(self, domain: str, api_token: str | None) -> None:
        api_token = api_token or ""
        if "#" in api_token:
            server_url, api_key = api_token.split("#", 1)
        else:
            server_url = os.environ.get("PDNS_SERVER", "http://localhost:8081")
            api_key = api_token
        super().__init__(domain, {"X-API-Key": api_key})
        self.api_key = api_key

        server_url = server_url.rstrip("/")
        if not server_url.endswith("/api/v1"):
            server_url += "/api/v1"
        self.server_url = server_url
        self.zones_url = f"{server_url}/servers/localhost/zones"

        zone, _ = self.find_zone(self._zone_exists)
        self.base_url = f"{self.zones_url}/{zone}."

    def _zone_exists(self, zone: str) -> str | None:
        # PowerDNS answers 404, or 422 on some versions, for unknown zones.
        found = self.request(
            "GET",
            f"{self.zones_url}/{zone}.",
            missing_ok=True,
            missing_statuses=(404, 422),
        )
        return zone if found is not None else None

    def _patch_rrset(self, rrset: dict[str, object]) -> None:
        self.request("PATCH", self.base_url, json={"rrsets": [rrset]})

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        self._patch_rrset(
            {
                "name": f"{name.rstrip('.')}.",
                "type": "TXT",
                "ttl": ttl,
                "changetype": "REPLACE",
                "records": [{"content": f'"{content}"', "disabled": False}],
            }
        )
        LOG.debug("Added PowerDNS TXT record %s", name)

    def delete_txt_record(self) -> None:
        # Deleting an rrset that does not exist succeeds in PowerDNS.
        self._patch_rrset(
            {
                "name": f"{self.record_name}.",
                "type": "TXT",
                "changetype": "DELETE",
            }
        )
        LOG.debug("Deleted PowerDNS TXT record %s", self.record_name)
