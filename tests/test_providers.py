"""DNS providers: zone discovery, exact cleanup and error propagation."""

import json as jsonlib
from unittest.mock import MagicMock, patch

import pytest
import requests

from pyacmecli.acme.operations import dns_challenge_provider
from pyacmecli.webhooks.base import ZoneNotFoundError
from pyacmecli.webhooks.cloudflare import (
    Cloudflare,
    CloudflareZoneNotFoundError,
)
from pyacmecli.webhooks.digitalocean import DigitalOcean
from pyacmecli.webhooks.func_helper import candidate_zones
from pyacmecli.webhooks.hetzner import Hetzner, HetznerZoneNotFoundError
from pyacmecli.webhooks.ovh import OVH
from pyacmecli.webhooks.powerdns import PowerDNS
from pyacmecli.webhooks.route53 import Route53


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body
        self.content = b"" if body is None else jsonlib.dumps(body).encode()
        self.text = self.content.decode()

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeHttp:
    """Route (method, url) to responses; unknown routes answer 404."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, params=None, json=None, **kwargs):
        self.calls.append((method, url, params, json))
        route = self.routes.get((method, url))
        if callable(route):
            return route(params=params, json=json)
        return route if route is not None else Resp(404)

    def sent(self, method, prefix=""):
        return [
            c for c in self.calls if c[0] == method and c[1].startswith(prefix)
        ]


def _http(routes):
    fake = FakeHttp(routes)
    return fake, patch("requests.request", side_effect=fake)


# --------------------------------------------------------------------------
# Zone discovery
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", ["example.com"]),
        ("*.example.com", ["example.com"]),
        (
            "a.b.example.co.uk",
            ["a.b.example.co.uk", "b.example.co.uk", "example.co.uk"],
        ),
    ],
)
def test_candidate_zones(domain, expected):
    assert candidate_zones(domain) == expected


CF = "https://api.cloudflare.com/client/v4"


def _cf_zones(found):
    def handler(params, json):
        name = params["name"]
        return Resp(
            200, {"result": [{"id": f"id-{name}"}] if name in found else []}
        )

    return handler


def test_cloudflare_finds_delegated_subzone():
    fake, p = _http(
        {("GET", f"{CF}/zones"): _cf_zones({"sub.example.com", "example.com"})}
    )
    with p:
        cf = Cloudflare("x.sub.example.com", "token")
    assert cf.zone == "sub.example.com"
    assert cf.base_url == f"{CF}/zones/id-sub.example.com/dns_records"
    assert [c[2]["name"] for c in fake.calls] == [
        "x.sub.example.com",
        "sub.example.com",
    ]


def test_cloudflare_zone_not_found():
    _, p = _http({("GET", f"{CF}/zones"): _cf_zones(set())})
    with p, pytest.raises(CloudflareZoneNotFoundError, match="tried"):
        Cloudflare("example.com", "token")


def test_cloudflare_add_raises_on_api_errors():
    base = f"{CF}/zones/id-example.com/dns_records"
    _, p = _http(
        {
            ("GET", f"{CF}/zones"): _cf_zones({"example.com"}),
            ("POST", base): Resp(200, {"success": False, "errors": ["bad"]}),
        }
    )
    with p:
        cf = Cloudflare("example.com", "token")
        with pytest.raises(RuntimeError, match="rejected"):
            cf.add_txt_record(cf.record_name, "v")

    _, p = _http(
        {
            ("GET", f"{CF}/zones"): _cf_zones({"example.com"}),
            ("POST", base): Resp(403, {}),
        }
    )
    with p:
        cf = Cloudflare("example.com", "token")
        with pytest.raises(requests.HTTPError):
            cf.add_txt_record(cf.record_name, "v")


def test_cloudflare_deletes_only_the_exact_record():
    base = f"{CF}/zones/id-example.com/dns_records"
    fake, p = _http(
        {
            ("GET", f"{CF}/zones"): _cf_zones({"example.com"}),
            ("GET", base): Resp(
                200,
                {
                    "result": [
                        {
                            "id": "keep",
                            "name": "_acme-challenge.app2.example.com",
                        },
                        {
                            "id": "drop",
                            "name": "_acme-challenge.app.example.com",
                        },
                    ]
                },
            ),
            ("DELETE", f"{base}/drop"): Resp(200, {}),
        }
    )
    with p:
        Cloudflare("app.example.com", "token").delete_txt_record()
    assert (
        fake.sent("GET", base)[0][2]["name"]
        == "_acme-challenge.app.example.com"
    )
    assert [c[1] for c in fake.sent("DELETE")] == [f"{base}/drop"]


# --------------------------------------------------------------------------
# DigitalOcean
# --------------------------------------------------------------------------

DO = "https://api.digitalocean.com/v2/domains"


def test_digitalocean_subzone_add_and_cleanup():
    records = f"{DO}/sub.example.com/records"
    fake, p = _http(
        {
            ("GET", f"{DO}/sub.example.com"): Resp(200, {"domain": {}}),
            ("POST", records): Resp(201, {"domain_record": {"id": 7}}),
            ("DELETE", f"{records}/7"): Resp(204),
            ("GET", records): Resp(
                200,
                {
                    "domain_records": [
                        {"id": 8, "name": "_acme-challenge.x"},
                        {"id": 9, "name": "_acme-challenge.x2"},
                    ]
                },
            ),
            ("DELETE", f"{records}/8"): Resp(204),
        }
    )
    with p:
        do = DigitalOcean("x.sub.example.com", "token")
        do.add_txt_record(do.record_name, "v")
        assert fake.sent("POST")[0][3]["name"] == "_acme-challenge.x"
        do.delete_txt_record()
    assert [c[1] for c in fake.sent("DELETE")] == [
        f"{records}/7",
        f"{records}/8",
    ]
    assert do.created_record_id is None


# --------------------------------------------------------------------------
# Hetzner
# --------------------------------------------------------------------------

HC = "https://api.hetzner.cloud/v1"
HD = "https://dns.hetzner.com/api/v1"


def _hetzner_zones(found):
    def handler(params, json):
        name = params["name"]
        zones = [{"name": name, "id": f"z-{name}"}] if name in found else []
        return Resp(200, {"zones": zones})

    return handler


def test_hetzner_cloud_creates_then_extends_rrset():
    rrset = f"{HC}/zones/z-example.com/rrsets/_acme-challenge/TXT"
    state = {"exists": False}

    def get_rrset(params, json):
        return Resp(200, {"rrset": {}}) if state["exists"] else Resp(404)

    def create(params, json):
        state["exists"] = True
        return Resp(201, {})

    fake, p = _http(
        {
            ("GET", f"{HC}/zones"): _hetzner_zones({"example.com"}),
            ("GET", rrset): get_rrset,
            ("POST", f"{HC}/zones/z-example.com/rrsets"): create,
            ("POST", f"{rrset}/actions/add_records"): Resp(201, {}),
            ("DELETE", rrset): Resp(201, {}),
        }
    )
    with p:
        hz = Hetzner("example.com", "cloud-project-token")
        assert hz.is_cloud
        hz.add_txt_record(hz.record_name, "one")
        hz.add_txt_record(hz.record_name, "two")
        hz.delete_txt_record()

    posts = fake.sent("POST")
    assert posts[0][3]["records"] == [{"value": '"one"'}]
    assert posts[1][1].endswith("/actions/add_records")
    assert posts[1][3]["records"] == [{"value": '"two"'}]
    assert fake.sent("DELETE")[0][1] == rrset


def test_hetzner_console_api_cleans_up_exact_name():
    fake, p = _http(
        {
            ("GET", f"{HD}/zones"): _hetzner_zones({"example.com"}),
            ("POST", f"{HD}/records"): Resp(200, {"record": {"id": "r1"}}),
            ("GET", f"{HD}/records"): Resp(
                200,
                {
                    "records": [
                        {
                            "id": "r1",
                            "type": "TXT",
                            "name": "_acme-challenge.www",
                        },
                        {
                            "id": "r2",
                            "type": "TXT",
                            "name": "_acme-challenge.www2",
                        },
                        {
                            "id": "r3",
                            "type": "A",
                            "name": "_acme-challenge.www",
                        },
                    ]
                },
            ),
            ("DELETE", f"{HD}/records/r1"): Resp(200, {}),
        }
    )
    with p:
        hz = Hetzner("www.example.com", "a" * 32)
        assert not hz.is_cloud
        hz.add_txt_record(hz.record_name, "v")
        assert hz.created_record_id == "r1"
        hz.delete_txt_record()
    assert [c[1] for c in fake.sent("DELETE")] == [f"{HD}/records/r1"]


def test_hetzner_zone_not_found():
    _, p = _http({("GET", f"{HC}/zones"): _hetzner_zones(set())})
    with p, pytest.raises(HetznerZoneNotFoundError):
        Hetzner("example.com", "cloud-token-long")


# --------------------------------------------------------------------------
# PowerDNS
# --------------------------------------------------------------------------

PD = "http://pdns.internal:8081/api/v1/servers/localhost/zones"


def test_powerdns_subzone_and_errors_propagate():
    fake, p = _http(
        {
            ("GET", f"{PD}/a.example.com."): Resp(422, {}),
            ("GET", f"{PD}/example.com."): Resp(200, {}),
            ("PATCH", f"{PD}/example.com."): Resp(204),
        }
    )
    with p:
        pdns = PowerDNS("a.example.com", "http://pdns.internal:8081#key")
        assert pdns.zone == "example.com"
        pdns.add_txt_record(pdns.record_name, "v")
        pdns.delete_txt_record()
    add, delete = (c[3]["rrsets"][0] for c in fake.sent("PATCH"))
    assert add["changetype"] == "REPLACE"
    assert add["records"][0]["content"] == '"v"'
    assert delete == {
        "name": "_acme-challenge.a.example.com.",
        "type": "TXT",
        "changetype": "DELETE",
    }

    _, p = _http(
        {
            ("GET", f"{PD}/example.com."): Resp(200, {}),
            ("PATCH", f"{PD}/example.com."): Resp(500, {}),
        }
    )
    with p:
        pdns = PowerDNS("example.com", "http://pdns.internal:8081#key")
        with pytest.raises(requests.HTTPError):
            pdns.delete_txt_record()


# --------------------------------------------------------------------------
# Route 53
# --------------------------------------------------------------------------


def test_route53_prefers_public_subzone():
    r53_client = MagicMock()

    def zones(DNSName, MaxItems):
        if DNSName == "sub.example.com.":
            return {
                "HostedZones": [
                    {
                        "Name": "sub.example.com.",
                        "Id": "/hostedzone/PRIV",
                        "Config": {"PrivateZone": True},
                    },
                    {
                        "Name": "sub.example.com.",
                        "Id": "/hostedzone/PUB",
                        "Config": {"PrivateZone": False},
                    },
                ]
            }
        return {"HostedZones": []}

    r53_client.list_hosted_zones_by_name.side_effect = zones
    boto = MagicMock()
    boto.client.return_value = r53_client
    with patch.dict("sys.modules", {"boto3": boto}):
        r53 = Route53("x.sub.example.com", "AKIA#SECRET")
    assert (r53.zone, r53.zone_id) == ("sub.example.com", "PUB")

    r53.add_txt_record(r53.record_name, "v", ttl=60)
    r53.delete_txt_record()
    actions = [
        c.kwargs["ChangeBatch"]["Changes"][0]
        for c in r53_client.change_resource_record_sets.call_args_list
    ]
    assert [a["Action"] for a in actions] == ["UPSERT", "DELETE"]
    assert actions[1]["ResourceRecordSet"]["TTL"] == 60

    r53_client.change_resource_record_sets.side_effect = RuntimeError("denied")
    with pytest.raises(RuntimeError, match="denied"):
        r53.add_txt_record(r53.record_name, "v")


# --------------------------------------------------------------------------
# OVH
# --------------------------------------------------------------------------

OVH_API = "https://eu.api.ovh.com/1.0"


def test_ovh_subzone_add_and_cleanup():
    def route(self, method, url, params=None, **kwargs):
        calls.append((method, url, params))
        if method == "GET" and url == f"{OVH_API}/domain/zone/x.example.com":
            return Resp(404, {})
        if method == "GET" and url == f"{OVH_API}/domain/zone/example.com":
            return Resp(200, {})
        if method == "POST" and url.endswith("/record"):
            return Resp(200, {"id": 11})
        if method == "GET" and url.endswith("/record"):
            return Resp(200, [11, 12])
        if url.endswith("/refresh") or method == "DELETE":
            return Resp(200)
        raise AssertionError((method, url))

    calls = []
    with patch("requests.Session.request", route):
        ovh = OVH("x.example.com", "oauth-token")
        assert ovh.zone == "example.com"
        ovh.add_txt_record(ovh.record_name, "v")
        assert ovh.created_record_id == 11
        ovh.delete_txt_record()

    listing = [c for c in calls if c[0] == "GET" and c[1].endswith("/record")]
    assert listing[0][2] == {
        "fieldType": "TXT",
        "subDomain": "_acme-challenge.x",
    }
    deleted = [c[1].rsplit("/", 1)[1] for c in calls if c[0] == "DELETE"]
    assert deleted == ["11", "12"]
    assert ovh.created_record_id is None


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


def test_registry_builds_every_provider():
    for name, cls in (
        ("cloudflare", Cloudflare),
        ("digitalocean", DigitalOcean),
        ("hetzner", Hetzner),
        ("powerdns", PowerDNS),
        ("route53", Route53),
        ("ovh", OVH),
    ):
        with patch.object(cls, "__init__", return_value=None):
            assert isinstance(
                dns_challenge_provider(name, "example.com", "t"), cls
            )
    assert dns_challenge_provider("dns", "example.com") is None
    with pytest.raises(RuntimeError, match="Invalid provider"):
        dns_challenge_provider("nope", "example.com", "t")


def test_zone_errors_share_a_base_class():
    assert issubclass(CloudflareZoneNotFoundError, ZoneNotFoundError)
    assert issubclass(HetznerZoneNotFoundError, ZoneNotFoundError)
