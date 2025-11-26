import time

import requests
from pyacme.src.happylog import LOG
from pyacme.src.webhooks.func_helper import get_root_domain
from pyacme.src.webhooks.base import Base


class ArvanCloud(Base):
    def __init__(self, domain: str, api_key: str):
        self.api_token = api_key

        self.domain = domain
        self.base_url = f"https://napi.arvancloud.ir/cdn/4.0/domains/{get_root_domain(domain)}/dns-records"

    def __get_headers(self):
        return {
            "Authorization": f"{self.api_token}",
            "Content-Type": "application/json"
        }

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> dict:
        payload = {
            "value": {
                "text": content
            },
            "type": "txt",
            "name": name.replace(get_root_domain(self.domain), '', 1),
            "ttl": ttl,
            "cloud": False,
            "upstream_https": "default",
            "ip_filter_mode": {
                "count": "single",
                "order": "none",
                "geo_filter": "none"
            }
        }

        response = requests.post(self.base_url, headers=self.__get_headers(), json=payload)
        response.raise_for_status()
        LOG.debug(f'Status add TXT record is {response.status_code} response is {response.json()}')

    def delete_txt_record(self) -> dict:
        """
        Delete a TXT record matching name and content.

        :param name: Full record name.
        :param content: TXT record content to match.
        :return: API response as dict.
        """
        # Fetch all TXT records for this zone
        resp = requests.get(self.base_url, headers=self.__get_headers())
        resp.raise_for_status()

        records = resp.json().get("data", [])
        for record in records:
            if f'_acme-challenge.{self.domain.replace(f'.{get_root_domain(self.domain)}', '')}' in record.get("name"):
                record_id = record.get("id")
                delete_url = f"{self.base_url}/{record_id}"
                del_resp = requests.delete(delete_url, headers=self.__get_headers())
                del_resp.raise_for_status()
                LOG.debug(del_resp.json())
                time.sleep(5)
