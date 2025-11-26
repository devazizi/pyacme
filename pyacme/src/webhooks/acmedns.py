import requests
from pyacme.src.happylog import LOG
from .base import Base


class AcmeDNS(Base):
    BASE_URL = 'https://auth.acme-dns.io'

    def __init__(self, domain: str, cfg_dir: str):
        self.domain = domain
        self.cfg_dir = cfg_dir

        acmedns_conf = self.load_config()
        if acmedns_conf is None:
            response = requests.post(f'{self.BASE_URL}/register')
            response.raise_for_status()
            self.save_config(response.json())
            LOG.info(f"Please add this cname record to your zones key _acme-challenge values {response.json().get('fulldomain')}")
            input('Are you add this cname record? ')

    def add_txt_record(self, name: str, content: str, ttl: int = 120):

        acmedns_conf = self.load_config()

        subdomain = acmedns_conf['subdomain']
        username = acmedns_conf['username']
        password = acmedns_conf['password']

        update_url = f"https://auth.acme-dns.io/update"

        headers = {
            "X-Api-User": username,
            "X-Api-Key": password,
            "Content-Type": "application/json"
        }

        payload = {
            "subdomain": subdomain,
            "txt": content
        }

        update_resp = requests.post(update_url, json=payload, headers=headers)
        update_resp.raise_for_status()

        LOG.info("TXT record updated:", update_resp.json())

    def delete_txt_record(self):
        pass
