"""AWS Route 53 DNS provider for ACME DNS-01 challenge."""

from pyacmecli.happylog import LOG
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.func_helper import get_root_domain


class Route53(Base):
    """AWS Route 53 client for adding/deleting _acme-challenge TXT records."""

    def __init__(self, domain: str, api_token: str | None = None) -> None:
        self.domain = domain
        self.root_domain = get_root_domain(domain)
        self.api_token = api_token
        self.last_record_name: str | None = None
        self.last_content: str | None = None

        try:
            import boto3
        except ImportError as err:
            raise RuntimeError(
                "boto3 package is required for AWS Route 53 provider. "
                "Install it using: pip install boto3"
            ) from err

        client_kwargs = {}
        if api_token and "#" in api_token:
            access_key, secret_key = api_token.split("#", 1)
            client_kwargs["aws_access_key_id"] = access_key
            client_kwargs["aws_secret_access_key"] = secret_key

        self.r53 = boto3.client("route53", **client_kwargs)
        self.zone_id = self._get_zone_id()

    def _get_zone_id(self) -> str:
        domain_name = self.root_domain.rstrip(".") + "."
        resp = self.r53.list_hosted_zones_by_name(DNSName=domain_name)
        for zone in resp.get("HostedZones", []):
            if zone["Name"] == domain_name and not zone.get("Config", {}).get(
                "PrivateZone", False
            ):
                return zone["Id"].replace("/hostedzone/", "")
        for zone in resp.get("HostedZones", []):
            if zone["Name"] == domain_name:
                return zone["Id"].replace("/hostedzone/", "")
        raise RuntimeError(
            f"Hosted zone not found on Route 53 for domain {self.root_domain}"
        )

    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        self.last_record_name = name.rstrip(".") + "."
        self.last_content = f'"{content}"'
        change_batch = {
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": self.last_record_name,
                        "Type": "TXT",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": self.last_content}],
                    },
                }
            ]
        }
        self.r53.change_resource_record_sets(
            HostedZoneId=self.zone_id, ChangeBatch=change_batch
        )
        LOG.debug("Upserted Route 53 TXT record: %s", self.last_record_name)

    def delete_txt_record(self) -> None:
        if not self.last_record_name or not self.last_content:
            return
        change_batch = {
            "Changes": [
                {
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        "Name": self.last_record_name,
                        "Type": "TXT",
                        "TTL": 120,
                        "ResourceRecords": [{"Value": self.last_content}],
                    },
                }
            ]
        }
        try:
            self.r53.change_resource_record_sets(
                HostedZoneId=self.zone_id, ChangeBatch=change_batch
            )
            LOG.debug("Deleted Route 53 TXT record: %s", self.last_record_name)
        except Exception as exc:
            LOG.warning("Could not delete Route 53 TXT record: %s", exc)
