"""AcmeDNS provider for ACME DNS-01 challenge (CNAME to acme-dns.io)."""

import requests

from pyacmecli.happylog import LOG

from .base import Base


class AcmeDNS(Base):
    """AcmeDNS client: register subdomain and set TXT via API."""

    BASE_URL = "https://auth.acme-dns.io"

    def __init__(self, domain: str, cfg_dir: str) -> None:
        super().__init__(cfg_dir)
        self.domain = domain

        acmedns_conf = self.load_config()
        if acmedns_conf is None:
            response = requests.post(f"{self.BASE_URL}/register", timeout=30)
            response.raise_for_status()
            data = response.json()
            self.save_config(data)
            fulldomain = data.get("fulldomain", "")
            LOG.info(
                "Add a CNAME record: _acme-challenge -> %s",
                fulldomain,
            )
            input("Have you added the CNAME record? Press Enter to continue. ")

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        acmedns_conf = self.load_config()
        if not acmedns_conf:
            raise RuntimeError("AcmeDNS config missing; run again after CNAME.")
        subdomain = acmedns_conf["subdomain"]
        username = acmedns_conf["username"]
        password = acmedns_conf["password"]

        update_url = "https://auth.acme-dns.io/update"
        headers = {
            "X-Api-User": username,
            "X-Api-Key": password,
            "Content-Type": "application/json",
        }
        payload = {"subdomain": subdomain, "txt": content}

        update_resp = requests.post(
            update_url, json=payload, headers=headers, timeout=30
        )
        update_resp.raise_for_status()
        LOG.info("TXT record updated: %s", update_resp.json())

    def delete_txt_record(self) -> None:
        """AcmeDNS does not require deleting the TXT record."""
        pass
