"""Demo service for SAST scanning (deliberately contains findings - not real code)."""
import hashlib
import subprocess

import requests
import yaml


def fetch_partner_feed(url):
    # MEDIUM python-requests-tls-verify-disabled + INFO python-requests-no-timeout
    return requests.get(url, verify=False)


def cache_key(payload: bytes) -> str:
    # LOW python-weak-hash (non-security use, but not declared as such)
    return hashlib.md5(payload).hexdigest()


def ping_upstream():
    # INFO python-requests-no-timeout
    return requests.head("https://upstream.internal.example/health")


# ---- Safe forms: suppressed by the allowlist patterns (N2) in config/semgrep.yml
def find_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()


def disk_usage():
    return subprocess.run("df -h", shell=True, capture_output=True, check=False)


def load_settings(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def etag(body: bytes) -> str:
    return hashlib.md5(body, usedforsecurity=False).hexdigest()


def fetch_with_timeout(url):
    return requests.get(url, timeout=10)

