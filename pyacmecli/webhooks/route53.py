"""AWS Route 53 DNS provider for ACME DNS-01 challenge."""

from typing import Any

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import Base


class Route53(Base):
    """AWS Route 53 client for _acme-challenge TXT records.

    The credential is 'access_key#secret_key', or None to use the default
    AWS credential chain (environment, profile, instance role).
    """

    def __init__(self, domain: str, api_token: str | None = None) -> None:
        super().__init__(domain)
        self.api_token = api_token
        self.last_record_name: str | None = None
        self.last_content: str | None = None
        self.last_ttl = 120

        try:
            import boto3
        except ImportError as err:
            raise RuntimeError(
                "boto3 is required for the Route 53 provider. "
                "Install it with: pip install 'pyacmecli[route53]'"
            ) from err

        client_kwargs: dict[str, str] = {}
        if api_token and "#" in api_token:
            access_key, secret_key = api_token.split("#", 1)
            client_kwargs["aws_access_key_id"] = access_key
            client_kwargs["aws_secret_access_key"] = secret_key

        self.r53: Any = boto3.client("route53", **client_kwargs)
        self.root_domain, self.zone_id = self.find_zone(self._zone_id)

    def _zone_id(self, zone: str) -> str | None:
        name = f"{zone}."
        resp = self.r53.list_hosted_zones_by_name(DNSName=name, MaxItems="5")
        matches = [z for z in resp.get("HostedZones", []) if z["Name"] == name]
        # Prefer the public zone: the CA validates against public DNS.
        matches.sort(
            key=lambda z: z.get("Config", {}).get("PrivateZone", False)
        )
        if not matches:
            return None
        return str(matches[0]["Id"]).replace("/hostedzone/", "")

    def _change(self, action: str, name: str, value: str, ttl: int) -> None:
        self.r53.change_resource_record_sets(
            HostedZoneId=self.zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": name,
                            "Type": "TXT",
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": value}],
                        },
                    }
                ]
            },
        )

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        self.last_record_name = name.rstrip(".") + "."
        self.last_content = f'"{content}"'
        self.last_ttl = ttl
        self._change("UPSERT", self.last_record_name, self.last_content, ttl)
        LOG.debug("Upserted Route 53 TXT record: %s", self.last_record_name)

    def delete_txt_record(self) -> None:
        # Route 53 DELETE needs the exact current value, so only the record
        # this instance created can be removed; an UPSERT on the next run
        # replaces any leftover.
        if not self.last_record_name or not self.last_content:
            return
        self._change(
            "DELETE", self.last_record_name, self.last_content, self.last_ttl
        )
        LOG.debug("Deleted Route 53 TXT record: %s", self.last_record_name)
        self.last_record_name = self.last_content = None
