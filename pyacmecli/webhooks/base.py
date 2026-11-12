"""Base classes for DNS providers that publish dns-01 TXT records."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

import requests

from pyacmecli.webhooks.func_helper import candidate_zones

HTTP_TIMEOUT = 30


class ZoneNotFoundError(RuntimeError):
    """No zone at the provider contains the challenge record."""


class Base(ABC):
    """A DNS provider able to publish _acme-challenge.<domain>.

    Contract shared by every provider:

    - add_txt_record publishes the value and raises on any API error.
    - delete_txt_record removes only records named exactly
      _acme-challenge.<domain>, also ones left by an interrupted earlier
      run, and raises on API errors. The caller decides whether a failed
      cleanup is fatal.
    """

    def __init__(self, domain: str) -> None:
        self.domain = domain.removeprefix("*.").rstrip(".")
        self.record_name = f"_acme-challenge.{self.domain}"
        self.zone = ""

    def find_zone(self, lookup: Callable[[str], str | None]) -> tuple[str, str]:
        """Return (zone name, provider zone id) for the domain.

        lookup(zone_name) returns the provider's id for that zone, or None
        if the provider does not host it. Candidates are tried from the most
        specific name up to the registrable domain, so delegated subzones
        are honoured.
        """
        tried = []
        for zone in candidate_zones(self.domain):
            tried.append(zone)
            zone_id = lookup(zone)
            if zone_id is not None:
                self.zone = zone
                return zone, zone_id
        raise ZoneNotFoundError(
            f"{type(self).__name__}: no zone found for {self.domain} "
            f"(tried {', '.join(tried)})"
        )

    def relative_name(self, fqdn: str) -> str:
        """Name relative to the zone; never empty for _acme-challenge names."""
        return fqdn.rstrip(".").removesuffix(f".{self.zone}")

    @abstractmethod
    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        """Create or update the TXT record for the DNS-01 challenge."""

    @abstractmethod
    def delete_txt_record(self) -> None:
        """Remove the TXT record used for the DNS-01 challenge."""


class HttpProvider(Base):
    """Provider backed by a JSON HTTP API."""

    def __init__(self, domain: str, headers: dict[str, str]) -> None:
        super().__init__(domain)
        self.headers = {"Content-Type": "application/json", **headers}

    def request(
        self,
        method: str,
        url: str,
        *,
        missing_ok: bool = False,
        missing_statuses: tuple[int, ...] = (404,),
        **kwargs: Any,
    ) -> requests.Response | None:
        """Send a request and raise on errors.

        With missing_ok, a status in missing_statuses returns None instead,
        for lookups where "not found" is an expected answer.
        """
        resp = requests.request(
            method, url, headers=self.headers, timeout=HTTP_TIMEOUT, **kwargs
        )
        if missing_ok and resp.status_code in missing_statuses:
            return None
        resp.raise_for_status()
        return resp

    def json(self, method: str, url: str, **kwargs: Any) -> Any:
        """Send a request that must succeed and return its JSON body."""
        resp = self.request(method, url, **kwargs)
        if resp is None:  # only possible with missing_ok
            raise RuntimeError(f"{method} {url} returned no response")
        return resp.json() if resp.content else {}
