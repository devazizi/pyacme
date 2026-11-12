"""Unit tests for newly added native DNS providers (DigitalOcean, Hetzner, PowerDNS, Route53, OVH)."""

from unittest.mock import MagicMock, patch
import pytest

from pyacmecli.acme.helper import dns_challenge_provider
from pyacmecli.webhooks.digitalocean import DigitalOcean
from pyacmecli.webhooks.hetzner import Hetzner, HetznerZoneNotFoundError
from pyacmecli.webhooks.powerdns import PowerDNS
from pyacmecli.webhooks.route53 import Route53
from pyacmecli.webhooks.ovh import OVH


class TestFactory:
    """Test that dns_challenge_provider resolves all new providers."""

    def test_factory_resolves_all_new_providers(self):
        with patch.object(DigitalOcean, "__init__", return_value=None):
            do = dns_challenge_provider("digitalocean", "example.com", "tok")
            assert isinstance(do, DigitalOcean)

        with patch.object(Hetzner, "__init__", return_value=None):
            hz = dns_challenge_provider("hetzner", "example.com", "tok")
            assert isinstance(hz, Hetzner)

        with patch.object(PowerDNS, "__init__", return_value=None):
            pdns = dns_challenge_provider("powerdns", "example.com", "tok")
            assert isinstance(pdns, PowerDNS)

        with patch.object(Route53, "__init__", return_value=None):
            r53 = dns_challenge_provider("route53", "example.com", "tok")
            assert isinstance(r53, Route53)

        with patch.object(OVH, "__init__", return_value=None):
            ovh = dns_challenge_provider("ovh", "example.com", "tok")
            assert isinstance(ovh, OVH)

    def test_factory_invalid_provider_raises(self):
        with pytest.raises(RuntimeError, match="Invalid provider"):
            dns_challenge_provider(
                "non_existent_provider", "example.com", "tok"
            )


class TestDigitalOcean:
    """Test DigitalOcean webhook client."""

    @patch("requests.post")
    def test_add_txt_record(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"domain_record": {"id": 12345}}
        mock_post.return_value = mock_resp

        do = DigitalOcean("sub.example.com", "do-token")
        do.add_txt_record("_acme-challenge.sub.example.com", "token-val")

        assert do.created_record_id == 12345
        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["json"]["type"] == "TXT"
        assert call_kwargs["json"]["name"] == "_acme-challenge.sub"
        assert call_kwargs["json"]["data"] == "token-val"

    @patch("requests.delete")
    def test_delete_txt_record_by_id(self, mock_delete):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_delete.return_value = mock_resp

        do = DigitalOcean("example.com", "do-token")
        do.created_record_id = 999
        do.delete_txt_record()

        mock_delete.assert_called_once_with(
            "https://api.digitalocean.com/v2/domains/example.com/records/999",
            headers=do.headers,
            timeout=30,
        )
        assert do.created_record_id is None


class TestHetzner:
    """Test Hetzner webhook client."""

    @patch("requests.get")
    @patch("requests.post")
    def test_hetzner_dns_api_flow(self, mock_post, mock_get):
        # 32 chars token indicates legacy Hetzner DNS API
        token_32 = "a" * 32
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = {
            "zones": [{"name": "example.com", "id": "zone-1"}]
        }
        mock_get.return_value = mock_get_resp

        mock_post_resp = MagicMock()
        mock_post_resp.json.return_value = {"record": {"id": "rec-123"}}
        mock_post.return_value = mock_post_resp

        hz = Hetzner("example.com", token_32)
        assert hz.zone_id == "zone-1"
        assert not hz.is_cloud

        hz.add_txt_record("_acme-challenge.example.com", "hetzner-token")
        assert hz.created_record_id == "rec-123"

    @patch("requests.get")
    def test_hetzner_zone_not_found(self, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = {"zones": []}
        mock_get.return_value = mock_get_resp

        with pytest.raises(HetznerZoneNotFoundError):
            Hetzner("example.com", "cloud-token-long")


class TestPowerDNS:
    """Test PowerDNS webhook client."""

    @patch("requests.patch")
    def test_powerdns_add_and_delete(self, mock_patch):
        mock_resp = MagicMock()
        mock_patch.return_value = mock_resp

        pdns = PowerDNS("example.com", "http://pdns.internal:8081#secret-key")
        assert pdns.server_url == "http://pdns.internal:8081/api/v1"
        assert pdns.api_key == "secret-key"

        # Add record
        pdns.add_txt_record("_acme-challenge.example.com", "pdns-token")
        assert mock_patch.called
        patch_kwargs = mock_patch.call_args[1]
        rrset = patch_kwargs["json"]["rrsets"][0]
        assert rrset["changetype"] == "REPLACE"
        assert rrset["records"][0]["content"] == '"pdns-token"'

        # Delete record
        mock_patch.reset_mock()
        pdns.delete_txt_record()
        assert mock_patch.called
        del_rrset = mock_patch.call_args[1]["json"]["rrsets"][0]
        assert del_rrset["changetype"] == "DELETE"


class TestRoute53:
    """Test AWS Route53 webhook client."""

    def test_route53_upsert_and_delete(self):
        mock_boto = MagicMock()
        mock_client = MagicMock()
        mock_client.list_hosted_zones_by_name.return_value = {
            "HostedZones": [
                {"Name": "example.com.", "Id": "/hostedzone/Z12345"}
            ]
        }
        mock_boto.client.return_value = mock_client

        with patch.dict("sys.modules", {"boto3": mock_boto}):
            r53 = Route53("example.com", "AKIA123#SECRET123")
            assert r53.zone_id == "Z12345"

            # Add TXT
            r53.add_txt_record("_acme-challenge.example.com", "r53-token")
            assert mock_client.change_resource_record_sets.called
            batch = mock_client.change_resource_record_sets.call_args[1][
                "ChangeBatch"
            ]
            assert batch["Changes"][0]["Action"] == "UPSERT"

            # Delete TXT
            mock_client.reset_mock()
            r53.delete_txt_record()
            assert mock_client.change_resource_record_sets.called
            del_batch = mock_client.change_resource_record_sets.call_args[1][
                "ChangeBatch"
            ]
            assert del_batch["Changes"][0]["Action"] == "DELETE"


class TestOVH:
    """Test OVH webhook client."""

    @patch("requests.Session.request")
    def test_ovh_oauth_flow(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.text = '{"id": 45678}'
        mock_resp.json.return_value = {"id": 45678}
        mock_req.return_value = mock_resp

        ovh = OVH("example.com", "my-oauth-bearer-token")
        assert ovh.is_oauth

        ovh.add_txt_record("_acme-challenge.example.com", "ovh-token")
        assert ovh.created_record_id == 45678

        ovh.delete_txt_record()
        assert ovh.created_record_id is None
