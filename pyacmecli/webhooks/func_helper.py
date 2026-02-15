"""Helpers for domain and DNS names (root domain extraction, sorting)."""

import tldextract


def domains_root(domains: tuple[str, ...]) -> list[str]:
    """Sort domains by label count and wildcard for stable ordering."""
    return sorted(domains, key=lambda d: (d.count("."), "*" in d, d))


def get_root_domain(domain: str) -> str:
    """Return the registrable domain (e.g. example.com) from a hostname or wildcard."""
    domain = domain.lstrip("*.")
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"
