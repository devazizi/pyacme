"""ArvanCloud DNS provider for ACME DNS-01 challenge."""

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import HttpProvider

API = "https://napi.arvancloud.ir/cdn/4.0/domains"


class ArvanCloud(HttpProvider):
    """ArvanCloud CDN API v4 client for _acme-challenge TXT records."""

    def __init__(self, domain: str, api_key: str | None) -> None:
        super().__init__(domain, {"Authorization": f"{api_key}"})
        zone, _ = self.find_zone(self._zone_exists)
        self.base_url = f"{API}/{zone}/dns-records"

    def _zone_exists(self, zone: str) -> str | None:
        found = self.request("GET", f"{API}/{zone}", missing_ok=True)
        return zone if found is not None else None

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        self.request(
            "POST",
            self.base_url,
            json={
                "value": {"text": content},
                "type": "txt",
                "name": self.relative_name(name),
                "ttl": ttl,
                "cloud": False,
                "upstream_https": "default",
                "ip_filter_mode": {
                    "count": "single",
                    "order": "none",
                    "geo_filter": "none",
                },
            },
        )
        LOG.debug("Added ArvanCloud TXT record %s", name)

    def delete_txt_record(self) -> None:
        # Exact match on the relative or fully qualified name, so sibling
        # records (e.g. _acme-challenge.app2) are never touched.
        wanted = {self.record_name, self.relative_name(self.record_name)}
        for record in self.json("GET", self.base_url).get("data", []):
            if str(record.get("name", "")).rstrip(".") not in wanted:
                continue
            self.request("DELETE", f"{self.base_url}/{record['id']}")
            LOG.debug("Deleted ArvanCloud TXT record %s", record["id"])
