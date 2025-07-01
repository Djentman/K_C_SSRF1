from urllib.parse import urlparse
from socket import error as socket_error
import ipaddress
from .settings import ALLOWED_SSRF_HOSTS


class ValidationError(Exception):
    pass


def validate_no_ssrf(url):
    """
    Проверяет URL на SSRF-уязвимость.
    """
    if not url or url.strip() == "":
        return None

    parsed = urlparse(url)
    host = parsed.hostname

    if not host:
        raise ValidationError("No hostname provided")

    if parsed.scheme not in ("http", "https"):
        raise ValidationError("Invalid URL scheme")

    if host in ALLOWED_SSRF_HOSTS:
        return None

    try:
        ip_str = host_to_ip(host)
        ip = ipaddress.ip_address(ip_str)

        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValidationError(f"Private/reserved IP detected: {ip}")
    except socket_error:
        raise ValidationError("DNS resolution failed")

    return None


def host_to_ip(host):
    from socket import gethostbyname
    return gethostbyname(host)
