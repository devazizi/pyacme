import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from pyacmecli.src.happylog import LOG


class SSLCertificate:
    def __init__(
        self,
        domain: str,
        certificate_path: str,
        private_key_path: str,
        expiry_date: str,
        renew_before_days: int,
        last_renewed: str,
        renew_command: str,
        status: str,
        provider: str,
        provider_conf: str,
        email: str,
    ):
        self.domain = domain
        self.certificate_path = certificate_path
        self.private_key_path = private_key_path
        self.expiry_date = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
        self.renew_before_days = renew_before_days
        self.last_renewed = datetime.fromisoformat(last_renewed.replace("Z", "+00:00"))
        self.renew_command = renew_command
        self.status = (status,)
        self.provider = provider
        self.provider_conf = provider_conf
        self.email = email

    @classmethod
    def open(cls, file_path: str) -> "SSLCertificate":
        """Load certificate data from a JSON file."""
        with open(file_path, "r") as f:
            data = json.load(f)
        return cls(**data)

    def save(self, file_path: Optional[str] = None):
        """Save certificate data to a JSON file."""
        data = {
            "domain": self.domain,
            "certificate_path": self.certificate_path,
            "private_key_path": self.private_key_path,
            "expiry_date": self.expiry_date.isoformat().replace("+00:00", "Z"),
            "renew_before_days": self.renew_before_days,
            "last_renewed": self.last_renewed.isoformat().replace("+00:00", "Z"),
            "renew_command": self.renew_command,
            "status": "".join(self.status),
            "provider": self.provider,
            "provider_conf": self.provider_conf,
            "email": self.email,
        }
        if file_path is None:
            raise ValueError("File path must be provided to save.")
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)
        LOG.info(f"Certificate data saved to {file_path}")

    def needs_renewal(self) -> bool:
        renew_time = self.expiry_date - timedelta(days=self.renew_before_days)
        return datetime.now(timezone.utc) >= renew_time

    def days_until_expiry(self) -> int:
        """Return remaining days until expiry (UTC-safe)."""
        return (self.expiry_date - datetime.now(timezone.utc)).days

    def __repr__(self):
        return (
            f"<SSLCertificate domain={self.domain}, status={self.status}, "
            f"expires_in={self.days_until_expiry()} days>"
        )

    @classmethod
    def from_pem(
        cls,
        cert_path: str,
        key_path: str,
        provider: str,
        provider_conf: str,
        renew_before_days: int = 30,
        renew_command: str = "",
        email: str = "",
    ) -> "SSLCertificate":
        """Read SSL certificate from PEM file and create an SSLCertificate instance."""
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Extract domain from CN or SAN
        try:
            common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                0
            ].value
        except IndexError:
            common_name = ""
        try:
            san = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            domains = san.value.get_values_for_type(x509.DNSName)
            domain = domains[0] if domains else common_name
        except x509.ExtensionNotFound:
            domain = common_name

        # Use UTC-aware datetime
        expiry_date = cert.not_valid_after_utc.isoformat().replace("+00:00", "Z")
        status = (
            "valid"
            if datetime.now(timezone.utc) < cert.not_valid_after_utc
            else "expired"
        )
        last_renewed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        obj = cls(
            domain=domain,
            certificate_path=cert_path,
            private_key_path=key_path,
            expiry_date=expiry_date,
            renew_before_days=renew_before_days,
            last_renewed=last_renewed,
            renew_command=renew_command,
            status=status,
            provider=provider,
            provider_conf=provider_conf,
            email=email,
        )

        # Optional: verify private key matches
        if obj.verify_private_key_match():
            LOG.info(f"Certificate and private key match for {domain}")
        else:
            LOG.info(f"Warning: Certificate and private key do NOT match for {domain}")

        return obj

    def verify_private_key_match(self) -> bool:
        """Verify if the private key matches the certificate's public key."""
        try:
            with open(self.private_key_path, "rb") as f:
                key_data = f.read()

            private_key = serialization.load_pem_private_key(
                key_data, password=None, backend=default_backend()
            )

            with open(self.certificate_path, "rb") as f:
                cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            pub_key = cert.public_key()

            # RSA keys
            if isinstance(private_key, rsa.RSAPrivateKey) and isinstance(
                pub_key, rsa.RSAPublicKey
            ):
                return (
                    private_key.public_key().public_numbers()
                    == pub_key.public_numbers()
                )

            # EC keys
            if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(
                pub_key, ec.EllipticCurvePublicKey
            ):
                return (
                    private_key.public_key().public_numbers()
                    == pub_key.public_numbers()
                )

            return False
        except Exception as e:
            LOG.info(f"Could not verify key match: {e}")
            return False
