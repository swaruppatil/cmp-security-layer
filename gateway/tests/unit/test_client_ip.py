from types import SimpleNamespace

from app.security import client_ip
from tests.fakes import make_settings


def req(direct: str, xff: str | None = None):
    headers = {"x-forwarded-for": xff} if xff else {}
    return SimpleNamespace(client=SimpleNamespace(host=direct), headers=headers)


def test_forwarded_for_ignored_without_trusted_proxies():
    s = make_settings(trusted_proxy_count=0)
    assert client_ip(req("10.0.0.1", "6.6.6.6"), s) == "10.0.0.1"  # spoofed header ignored


def test_one_trusted_proxy_uses_rightmost_entry():
    s = make_settings(trusted_proxy_count=1)
    assert client_ip(req("10.0.0.1", "198.51.100.7"), s) == "198.51.100.7"
    # Client tried to spoof by sending its own XFF; the proxy appended the real address.
    assert client_ip(req("10.0.0.1", "6.6.6.6, 198.51.100.7"), s) == "198.51.100.7"


def test_two_trusted_proxies():
    s = make_settings(trusted_proxy_count=2)
    assert client_ip(req("10.0.0.2", "6.6.6.6, 198.51.100.7, 10.0.0.1"), s) == "198.51.100.7"


def test_missing_header_falls_back_to_socket_address():
    assert client_ip(req("10.0.0.1"), make_settings(trusted_proxy_count=1)) == "10.0.0.1"


def test_database_url_is_assembled_from_parts():
    from app.config import Settings

    s = Settings(admin_api_key="x" * 10, database_host="db.internal", database_password="p@ss/word")
    assert s.database_url == "postgresql://sec:p%40ss%2Fword@db.internal:5432/security"
    assert Settings(admin_api_key="x" * 10).database_url.endswith("@localhost:5432/security")
