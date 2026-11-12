"""Helpers for domain and DNS names (zone candidates, root domain)."""

import tldextract

# Use the public suffix list bundled with tldextract. The default fetches it
# from the internet on first use, which adds an unannounced outbound request
# and a failure mode to every run without a warm cache.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def domains_root(domains: tuple[str, ...]) -> list[str]:
    """Sort domains by label count and wildcard for stable ordering."""
    return sorted(domains, key=lambda d: (d.count("."), "*" in d, d))


def get_root_domain(domain: str) -> str:
    """Return the registrable domain (e.g. example.com) from a hostname or wildcard."""
    domain = domain.removeprefix("*.")
    ext = _EXTRACT(domain)
    return f"{ext.domain}.{ext.suffix}"


def candidate_zones(domain: str) -> list[str]:
    """Zones that may hold _acme-challenge.<domain>, most specific first.

    a.b.example.co.uk gives a.b.example.co.uk, b.example.co.uk and
    example.co.uk. Stopping at the registrable domain means a delegated
    subzone (b.example.co.uk hosted as its own zone) is found before its
    parent, and public suffixes such as co.uk are never tried.
    """
    domain = domain.removeprefix("*.").rstrip(".").lower()
    root = get_root_domain(domain)
    labels = domain.split(".")
    zones = []
    for i in range(len(labels)):
        zone = ".".join(labels[i:])
        zones.append(zone)
        if zone == root:
            break
    return zones
