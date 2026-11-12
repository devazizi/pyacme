"""DNS propagation checks for dns-01 challenges.

Named dnscheck rather than dns so it is never confused with the dnspython
package, which this module imports as "dns".
"""

import time

import dns.exception
import dns.name
import dns.resolver

from pyacmecli.happylog import LOG

PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]


def find_authoritative_servers(
    record_name: str,
) -> tuple[str, list[str] | None]:
    """Return the name to query and the IPs of its authoritative servers.

    The CA asks the authoritative servers directly, so checking them avoids
    both stale negative caches on public resolvers and split-horizon
    answers. CNAMEs are followed first (AcmeDNS delegates this way), since
    the zone that must hold the TXT record is the CNAME target's zone.
    Returns (record_name, None) when discovery fails, and the caller falls
    back to public resolvers.
    """
    try:
        resolver = dns.resolver.Resolver()
        target = dns.name.from_text(record_name)
        for _ in range(8):
            try:
                target = resolver.resolve(target, "CNAME")[0].target
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
        zone = dns.resolver.zone_for_name(target, resolver=resolver)
        addresses: set[str] = set()
        for ns in resolver.resolve(zone, "NS"):
            try:
                addresses.update(
                    r.address for r in resolver.resolve(ns.target, "A")
                )
            except dns.exception.DNSException as exc:
                LOG.debug(f"Could not resolve nameserver {ns.target}: {exc}")
        if addresses:
            name = target.to_text(omit_final_dot=True)
            LOG.info(
                f"Checking {name} on authoritative servers of {zone}: "
                f"{', '.join(sorted(addresses))}"
            )
            return name, sorted(addresses)
    except dns.exception.DNSException as exc:
        LOG.warning(
            f"Authoritative nameserver lookup for {record_name} failed ({exc}); "
            "falling back to public resolvers"
        )
    return record_name, None


def wait_for_dns(
    record_name: str,
    txt_value: str,
    interval: int = 10,
    timeout: int = 300,
    max_retries: int | None = None,
    nameservers: list[str] | None = None,
) -> None:
    """Wait until record_name serves txt_value.

    Args:
        record_name: The TXT record name (e.g. _acme-challenge.example.com).
        txt_value: The expected challenge token value.
        interval: Time in seconds between polling attempts (default: 10).
        timeout: Total timeout in seconds before failing (default: 300).
        max_retries: Maximum number of polling attempts (default: None).
        nameservers: Authoritative server IPs; every one of them must serve
            the value, since the CA may ask any of them. When None, public
            recursive resolvers are asked instead.

    Raises:
        TimeoutError: If DNS record does not match within timeout or max_retries.
    """
    LOG.info(
        f"Waiting for DNS propagation of {record_name} (timeout={timeout}s, interval={interval}s)"
    )

    groups = [[ip] for ip in nameservers] if nameservers else [PUBLIC_RESOLVERS]
    resolvers = []
    for group in groups:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = group
        resolver.timeout = min(5.0, float(interval)) if interval > 0 else 5.0
        resolver.lifetime = min(10.0, float(interval)) if interval > 0 else 10.0
        resolvers.append((group[0], resolver))
    pending = list(resolvers)

    start_time = time.time()
    attempts = 0

    while True:
        attempts += 1
        elapsed = time.time() - start_time

        for server, resolver in list(pending):
            try:
                answers = resolver.resolve(record_name, "TXT")
                found = any(
                    txt_value in [txt.decode() for txt in rdata.strings]
                    for rdata in answers
                )
                if found:
                    pending.remove((server, resolver))
                    continue
                LOG.info(
                    f"TXT record found on {server}, but value not matching. "
                    "Retrying..."
                )
            except dns.exception.DNSException as e:
                LOG.warning(
                    f"DNS query to {server} failed or no answer yet "
                    f"(attempt {attempts}): {e}"
                )

        if not pending:
            LOG.info(
                f"DNS record found for {record_name} after {attempts} attempt(s) ({elapsed:.1f}s)."
            )
            return

        elapsed = time.time() - start_time
        if elapsed >= timeout or (
            max_retries is not None and attempts >= max_retries
        ):
            msg = (
                f"DNS propagation timed out for {record_name} after {elapsed:.1f}s "
                f"({attempts} attempt(s)). Expected TXT: {txt_value}"
            )
            LOG.error(msg)
            raise TimeoutError(msg)

        sleep_time = min(float(interval), max(0.1, float(timeout - elapsed)))
        time.sleep(sleep_time)
