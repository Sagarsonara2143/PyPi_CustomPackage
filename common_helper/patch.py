import requests, ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

class TLSAdapter(HTTPAdapter):
    """Custom adapter to allow TLSv1.2+ with lower SECLEVEL"""
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

# Keep original Session init
_session_init = requests.Session.__init__

def _patched_init(self, *args, **kwargs):
    _session_init(self, *args, **kwargs)
    self.mount("https://", TLSAdapter())

def apply_patch():
    """Patch requests globally so all sessions use TLSAdapter"""
    requests.Session.__init__ = _patched_init