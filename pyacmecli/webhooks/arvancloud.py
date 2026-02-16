"""ArvanCloud DNS provider for ACME DNS-01 challenge."""

import time

import requests

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.func_helper import get_root_domain


class ArvanCloud(Base):
    """ArvanCloud API client for adding/deleting _acme-challenge TXT records."""

    def __init__(self, domain: str, api_key: str) -> None:
        self.api_token = api_key
        self.domain = domain
        self.base_url = (
            f"https://napi.arvancloud.ir/cdn/4.0/domains/"
            f"{get_root_domain(domain)}/dns-records"
        )

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"{self.api_token}",
            "Content-Type": "application/json",
        }

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        payload = {
            "value": {"text": content},
            "type": "txt",
            "name": name.replace(get_root_domain(self.domain), "", 1),
            "ttl": ttl,
            "cloud": False,
            "upstream_https": "default",
            "ip_filter_mode": {
                "count": "single",
                "order": "none",
                "geo_filter": "none",
            },
        }

        response = requests.post(
            self.base_url,
            headers=self._get_headers(),
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        LOG.debug(
            "Add TXT record status %s: %s",
            response.status_code,
            response.json(),
        )

    def delete_txt_record(self) -> None:
        """Delete the _acme-challenge TXT record for this domain."""
        resp = requests.get(
            self.base_url, headers=self._get_headers(), timeout=30
        )
        resp.raise_for_status()

        records = resp.json().get("data", [])
        for record in records:
            if (
                f"_acme-challenge.{self.domain.replace(f'.{get_root_domain(self.domain)}', '')}"
                in record.get("name")
            ):
                record_id = record.get("id")
                delete_url = f"{self.base_url}/{record_id}"
                del_resp = requests.delete(
                    delete_url,
                    headers=self._get_headers(),
                    timeout=30,
                )
                del_resp.raise_for_status()
                LOG.debug(del_resp.json())
                time.sleep(5)
