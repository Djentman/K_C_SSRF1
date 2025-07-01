# tests/test_validator.py

import pytest
from unittest import mock
from socket import error as socket_error
from ipaddress import ip_address

from ssrf_guard.validator import validate_no_ssrf, ValidationError


# Вспомогательная функция для мока gethostbyname
def mock_gethostbyname(host):
    if host in ["good.com", "k-c-twa-front.dev.cleverbots.ru"]:
        return "93.184.216.34"
    elif host == "example.com":
        return "93.184.216.34"
    elif host == "localhost":
        return "127.0.0.1"
    elif host == "private.local":
        return "192.168.1.1"
    elif host == "invalid-dns.local":
        raise socket_error
    else:
        return "8.8.8.8"


# Мокаем наши настройки
@pytest.fixture(autouse=True)
def mock_allowed_hosts():
    with mock.patch('ssrf_guard.settings.ALLOWED_SSRF_HOSTS', [
        "k-c-twa-front.dev.cleverbots.ru",
        "k-c-twa-front.test.cleverbots.ru",
        "kctwa-front.preprod.momhugs.huggies.ru",
        "kctwa-front.preprod.momhugs.huggies.uz",
        "kctwa-front.preprod.momhugs.huggies.kz",
        "kctwa-front.momhugs.huggies.ru",
        "kctwa-front.momhugs.huggies.uz",
        "kctwa-front.momhugs.huggies.kz"
    ]):
        yield


# Утилита вызова
def call_validate(url):
    return validate_no_ssrf(url)


@mock.patch("socket.gethostbyname", side_effect=mock_gethostbyname)
class TestValidateNoSSRF:

    def test_valid_url_allowed_host(self, _):
        assert call_validate("https://k-c-twa-front.dev.cleverbots.ru ") is None

    def test_valid_url_non_allowed_host(self, _):
        with pytest.raises(ValidationError):
            call_validate("https://bad-host.com ")

    def test_invalid_scheme(self, _):
        with pytest.raises(ValidationError):
            call_validate("ftp://example.com")

    def test_empty_url(self, _):
        assert call_validate("") is None

    def test_ssrf_to_localhost(self, _):
        with pytest.raises(ValidationError):
            call_validate("http://localhost")

    def test_ssrf_to_private_ip(self, _):
        with pytest.raises(ValidationError):
            call_validate("http://private.local")

    def test_public_ip_allowed(self, _):
        assert call_validate("http://good.com") is None

    def test_dns_resolution_failure(self, _):
        with pytest.raises(ValidationError):
            call_validate("http://invalid-dns.local")

    def test_reserved_ip(self, _):
        with mock.patch("ipaddress.ip_address", side_effect=lambda ip: mock.Mock(
                is_private=False,
                is_loopback=False,
                is_link_local=False,
                is_reserved=True,
        )):
            with pytest.raises(ValidationError):
                call_validate("http://reserved-ip.com")

    def test_link_local_ip(self, _):
        with mock.patch("ipaddress.ip_address", side_effect=lambda ip: mock.Mock(
                is_private=False,
                is_loopback=False,
                is_link_local=True,
                is_reserved=False,
        )):
            with pytest.raises(ValidationError):
                call_validate("http://link-local.com")