"""AcmeDNS provider for ACME DNS-01 challenge (CNAME to acme-dns.io)."""

import json
import os
from typing import Any

import requests

from pyacmecli.common.fsutil import write_private_file
from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import HTTP_TIMEOUT, Base


class AcmeDNS(Base):
    """AcmeDNS client: register a subdomain once, then update its TXT value.

    The registration (username, password, subdomain) is kept in
    <cfg_dir>/conf.json with mode 0600.
    """

    BASE_URL = "https://auth.acme-dns.io"

    def __init__(self, domain: str, cfg_dir: str) -> None:
        super().__init__(domain)
        self.cfg_dir = cfg_dir

        if self.load_config() is None:
            response = requests.post(
                f"{self.BASE_URL}/register", timeout=HTTP_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            self.save_config(data)
            LOG.info(
                "Add a CNAME record: _acme-challenge -> %s",
                data.get("fulldomain", ""),
            )
            input("Have you added the CNAME record? Press Enter to continue. ")

    @property
    def config_path(self) -> str:
        return os.path.join(self.cfg_dir, "conf.json")

    def load_config(self) -> dict[str, Any] | None:
        if not os.path.exists(self.config_path):
            return None
        with open(self.config_path, encoding="utf-8") as f:
            config: dict[str, Any] = json.load(f)
        return config

    def save_config(self, config: dict[str, Any]) -> None:
        write_private_file(self.config_path, json.dumps(config, indent=4))

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        config = self.load_config()
        if not config:
            raise RuntimeError("AcmeDNS config missing; run again after CNAME.")
        response = requests.post(
            f"{self.BASE_URL}/update",
            json={"subdomain": config["subdomain"], "txt": content},
            headers={
                "X-Api-User": config["username"],
                "X-Api-Key": config["password"],
                "Content-Type": "application/json",
            },
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        LOG.info("AcmeDNS TXT record updated for %s", name)

    def delete_txt_record(self) -> None:
        """AcmeDNS keeps rolling TXT values; nothing to delete."""
