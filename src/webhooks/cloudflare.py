import time

import requests
from src.happylog import LOG
from src.webhooks.func_helper import get_root_domain


class Cloudflare:
    def __init__(self, domain: str, api_token: str):
        self.api_token = api_token
        self.domain = domain
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }
        zone_id = self.__get_zone_id(domain)
        self.base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"

    def __get_zone_id(self, domain: str) -> str:
        url = "https://api.cloudflare.com/client/v4/zones"
        params = {"name": get_root_domain(domain)}
        resp = requests.get(url, headers=self.headers, params=params)
        resp.raise_for_status()
        result = resp.json()

        if result.get("success") and result.get("result"):
            return result["result"][0]["id"]

        raise Exception(f"Zone ID not found for domain: {domain}")

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> dict:
        payload = {
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": ttl
        }

        response = requests.post(self.base_url, headers=self.headers, json=payload)
        # response.raise_for_status()
        LOG.debug(f'Status add TXT record is {response.status_code} response is {response.json()}')

    def delete_txt_record(self) -> dict:
        resp = requests.get(self.base_url, headers=self.headers)
        # resp.raise_for_status()

        records = resp.json().get("result", [])
        for record in records:
            if f'_acme-challenge.{self.domain.replace(f'.{get_root_domain(self.domain)}', '')}' in record.get("name"):
                record_id = record.get("id")
                delete_url = f"{self.base_url}/{record_id}"
                del_resp = requests.delete(delete_url, headers=self.headers)
                del_resp.raise_for_status()
                LOG.debug(del_resp.json())
                time.sleep(5)
