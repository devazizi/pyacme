import json
import os
from abc import ABC, abstractmethod

class Base(ABC):
    cfg_dir: str

    def __init__(self, cfg_dir: str):
        self.cfg_dir = cfg_dir

    def load_config(self):
        config_path = os.path.join(self.cfg_dir, "conf.json")

        if not os.path.exists(config_path):
            return None

        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_config(self, config):
        os.makedirs(os.path.dirname(self.cfg_dir), exist_ok=True)
        with open(f"{self.cfg_dir}/conf.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)

    @abstractmethod
    def add_txt_record(self, name: str, content: str, ttl: int = 120) -> dict:
        raise NotImplementedError("add_txt_record must be implemented")

    @abstractmethod
    def delete_txt_record(self) -> dict:
        raise NotImplementedError("delete_txt_record must be implemented")
