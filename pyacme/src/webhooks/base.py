import json
import os


class Base:
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
