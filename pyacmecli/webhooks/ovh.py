"""OVH DNS provider for ACME DNS-01 challenge."""

import hashlib
import json
import time
from typing import Any
import requests

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.func_helper import get_root_domain


class OVH(Base):
    """OVH API client for adding/deleting _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str) -> None:
        self.domain = domain
        self.root_domain = get_root_domain(domain)
        self.endpoint_api = "https://eu.api.ovh.com/1.0"
        self.api_token = api_token

        # If api_token contains '#', split as app_key#app_secret#consumer_key
        if "#" in api_token:
            parts = api_token.split("#")
            self.app_key = parts[0]
            self.app_secret = parts[1] if len(parts) > 1 else ""
            self.consumer_key = parts[2] if len(parts) > 2 else ""
            self.is_oauth = False
        else:
            self.access_token = api_token
            self.is_oauth = True

        self.created_record_id: int | None = None
        self.session = requests.Session()
        self.time_delta = 0

        if not self.is_oauth:
            try:
                server_time = self.session.get(
                    f"{self.endpoint_api}/auth/time", timeout=10
                ).json()
                self.time_delta = int(server_time) - int(time.time())
            except Exception:
                self.time_delta = 0

    def _relative_name(self, name: str) -> str:
        relative = name.removesuffix(f".{self.root_domain}").removesuffix(".")
        return relative if relative else ""

    def _request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.endpoint_api}{path}"
        body = json.dumps(data) if data is not None else ""
        headers = {"Content-Type": "application/json"}

        if self.is_oauth:
            headers["Authorization"] = f"Bearer {self.access_token}"
        else:
            now = str(int(time.time()) + self.time_delta)
            req = requests.Request(method, url, data=body, params=params)
            prepped = self.session.prepare_request(req)

            sig = hashlib.sha1()
            sig.update(
                "+".join(
                    [
                        self.app_secret,
                        self.consumer_key,
                        method.upper(),
                        prepped.url or url,
                        body,
                        now,
                    ]
                ).encode("utf-8")
            )
            headers["X-Ovh-Application"] = self.app_key
            headers["X-Ovh-Consumer"] = self.consumer_key
            headers["X-Ovh-Timestamp"] = now
            headers["X-Ovh-Signature"] = f"$1${sig.hexdigest()}"

        resp = self.session.request(
            method=method,
            url=url,
            data=body,
            params=params,
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        if method == "DELETE" or not resp.text:
            return None
        return resp.json()

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        relative_name = self._relative_name(name)
        payload = {
            "fieldType": "TXT",
            "subDomain": relative_name,
            "target": content,
            "ttl": ttl,
        }
        res = self._request(
            "POST", f"/domain/zone/{self.root_domain}/record", data=payload
        )
        if isinstance(res, dict):
            self.created_record_id = res.get("id")
        LOG.debug(
            "Added OVH TXT record for %s (id: %s)", name, self.created_record_id
        )

        # Refresh zone so changes propagate
        try:
            self._request("POST", f"/domain/zone/{self.root_domain}/refresh")
        except Exception as exc:
            LOG.debug("Zone refresh note: %s", exc)

    def delete_txt_record(self) -> None:
        if self.created_record_id is not None:
            try:
                self._request(
                    "DELETE",
                    f"/domain/zone/{self.root_domain}/record/{self.created_record_id}",
                )
                LOG.debug(
                    "Deleted OVH TXT record id %s", self.created_record_id
                )
                self.created_record_id = None
                self._request(
                    "POST", f"/domain/zone/{self.root_domain}/refresh"
                )
            except Exception as exc:
                LOG.warning("Could not delete OVH record: %s", exc)
