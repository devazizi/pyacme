"""Abstract base for DNS providers that can set/delete TXT records for ACME."""

import json
import os
from abc import ABC, abstractmethod
from typing import Any


class Base(ABC):
    """Base class for DNS challenge providers (Cloudflare, ArvanCloud, AcmeDNS)."""

    cfg_dir: str

    def __init__(self, cfg_dir: str) -> None:
        self.cfg_dir = cfg_dir

    def load_config(self) -> dict[str, Any] | None:
        """Load provider config from cfg_dir/conf.json if present."""
        config_path = os.path.join(self.cfg_dir, "conf.json")
        if not os.path.exists(config_path):
            return None
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_config(self, config: dict[str, Any]) -> None:
        """Write provider config to cfg_dir/conf.json."""
        os.makedirs(os.path.dirname(self.cfg_dir), exist_ok=True)
        with open(f"{self.cfg_dir}/conf.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)

    @abstractmethod
    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> None:
        """Create or update the TXT record for the DNS-01 challenge."""
        raise NotImplementedError("add_txt_record must be implemented")

    @abstractmethod
    def delete_txt_record(self) -> None:
        """Remove the TXT record used for the DNS-01 challenge."""
        raise NotImplementedError("delete_txt_record must be implemented")
