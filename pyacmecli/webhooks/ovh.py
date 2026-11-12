"""OVH DNS provider for ACME DNS-01 challenge."""

import hashlib
import json
import time
from typing import Any

import requests

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import HTTP_TIMEOUT, Base

API = "https://eu.api.ovh.com/1.0"


class OVH(Base):
    """OVH API client for _acme-challenge TXT records.

    The credential is an OAuth2 bearer token, or
    'application_key#application_secret#consumer_key' for signed requests.
    """

    def __init__(self, domain: str, api_token: str | None) -> None:
        super().__init__(domain)
        api_token = api_token or ""
        self.endpoint_api = API
        self.session = requests.Session()
        self.time_delta = 0
        self.created_record_id: int | None = None

        self.is_oauth = "#" not in api_token
        if self.is_oauth:
            self.access_token = api_token
        else:
            parts = api_token.split("#")
            self.app_key = parts[0]
            self.app_secret = parts[1] if len(parts) > 1 else ""
            self.consumer_key = parts[2] if len(parts) > 2 else ""
            self._sync_time()

        _, self.root_domain = self.find_zone(self._zone_exists)

    def _sync_time(self) -> None:
        """Signed requests need the server's clock; tolerate a local skew."""
        try:
            resp = self.session.get(
                f"{self.endpoint_api}/auth/time", timeout=10
            )
            resp.raise_for_status()
            self.time_delta = int(resp.json()) - int(time.time())
        except (requests.RequestException, ValueError) as exc:
            LOG.warning(f"Could not read OVH server time, using local: {exc}")

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
            prepped = self.session.prepare_request(
                requests.Request(method, url, data=body, params=params)
            )
            sig = hashlib.sha1(
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
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        if method == "DELETE" or not resp.text:
            return None
        return resp.json()

    def _zone_exists(self, zone: str) -> str | None:
        try:
            self._request("GET", f"/domain/zone/{zone}")
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return None
            raise
        return zone

    def _refresh(self) -> None:
        """Apply pending zone changes on the OVH name servers."""
        self._request("POST", f"/domain/zone/{self.zone}/refresh")

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        res = self._request(
            "POST",
            f"/domain/zone/{self.zone}/record",
            data={
                "fieldType": "TXT",
                "subDomain": self.relative_name(name),
                "target": content,
                "ttl": ttl,
            },
        )
        if isinstance(res, dict):
            self.created_record_id = res.get("id")
        self._refresh()
        LOG.debug(
            "Added OVH TXT record for %s (id: %s)", name, self.created_record_id
        )

    def delete_txt_record(self) -> None:
        record_ids = self._request(
            "GET",
            f"/domain/zone/{self.zone}/record",
            params={
                "fieldType": "TXT",
                "subDomain": self.relative_name(self.record_name),
            },
        )
        ids = set(record_ids or [])
        if self.created_record_id is not None:
            ids.add(self.created_record_id)
        for record_id in sorted(ids):
            try:
                self._request(
                    "DELETE", f"/domain/zone/{self.zone}/record/{record_id}"
                )
            except requests.HTTPError as exc:
                if exc.response is None or exc.response.status_code != 404:
                    raise
            LOG.debug("Deleted OVH TXT record id %s", record_id)
        self.created_record_id = None
        if ids:
            self._refresh()
