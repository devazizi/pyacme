import tldextract


def domains_root(domains: tuple):
    return sorted(domains, key=lambda d: (d.count("."), "*" in d, d))


def get_root_domain(domain: str) -> str:
    domain = domain.lstrip("*.")

    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"
