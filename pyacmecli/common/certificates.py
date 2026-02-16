"""Certificate listing utilities for the pyacme home directory."""

import json
import os
from typing import NamedTuple


class CertificateListItem(NamedTuple):
    """Single certificate row for list/table display and renewal logic."""

    id: int
    domain: str
    certificate_path: str
    expiry_date: str
    status: str
    renew_command: str
    last_renewed: str


def get_certificate_list(base_dir: str) -> list[CertificateListItem]:
    """Walk the pyacme base directory and collect all certificate metadata.

    Args:
        base_dir: Path to the pyacme home directory (e.g. ~/.pyacme).

    Returns:
        List of CertificateListItem for each certificate.json found.

    Raises:
        json.JSONDecodeError: If a certificate.json is invalid.
    """
    certificates: list[CertificateListItem] = []
    cert_id = 0

    for root, _dirs, files in os.walk(base_dir):
        if "certificate.json" not in files:
            continue

        cert_path = os.path.join(root, "certificate.json")
        try:
            with open(cert_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            raise
        except OSError:
            raise

        certificates.append(
            CertificateListItem(
                id=cert_id,
                domain=data.get("domain", ""),
                certificate_path=data.get("certificate_path", ""),
                expiry_date=data.get("expiry_date", ""),
                status=data.get("status", ""),
                renew_command=data.get("renew_command", ""),
                last_renewed=data.get("last_renewed", ""),
            )
        )
        cert_id += 1

    return certificates
