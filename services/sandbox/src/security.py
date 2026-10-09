import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Union

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "host.docker.internal",
    "gateway.docker.internal",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    # docker-compose service names of the trusted zone
    "db",
    "worker",
    "ui",
    "sandbox",
}

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class SecurityError(Exception):
    pass


class SSRFError(SecurityError):
    pass


def is_ip_forbidden(ip: IPAddress) -> bool:
    """True for every address that is not publicly routable (RFC1918, loopback, link-local,
    CGNAT 100.64/10, reserved, multicast, unspecified, IPv4-mapped/compatible IPv6 to those)."""
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            return is_ip_forbidden(mapped)
    return (not ip.is_global) or ip.is_multicast or ip.is_unspecified or ip.is_reserved


def validate_url_safety(url: str, anti_ssrf_enabled: bool = True) -> Tuple[bool, str]:
    """
    Validates that a URL is syntactically safe and does not target internal or reserved infrastructure.
    Must be called for the initial URL AND for every redirect hop / sub-request.
    Returns: (is_safe, message)
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    try:
        parsed = urlparse(url.strip())
        _ = parsed.port  # raises ValueError on garbage ports
    except ValueError as e:
        return False, f"Failed to parse URL: {e}"

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, f"Prohibited scheme: '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL is missing hostname."
    hostname_clean = hostname.lower().rstrip(".")
    if hostname_clean in BLOCKED_HOSTNAMES or hostname_clean.endswith((".internal", ".local", ".localhost")):
        return False, f"Hostname '{hostname_clean}' is prohibited (SSRF prevention)."

    if not anti_ssrf_enabled:
        return True, "URL is syntactically valid (SSRF checks disabled)."

    try:
        ip = ipaddress.ip_address(hostname_clean)
    except ValueError:
        ip = None
    if ip is not None:
        if is_ip_forbidden(ip):
            return False, f"Destination IP {ip} is a private/reserved address."
        return True, f"IP {ip} is public and valid."

    try:
        addr_info = socket.getaddrinfo(hostname_clean, None)
    except socket.gaierror as e:
        # Dead phishing domains are common; the fetch itself will fail as well.
        return True, f"DNS resolution failed ({e}), permitted as offline or dead target."
    except Exception as e:
        return False, f"Error validating hostname: {e}"

    resolved = {info[4][0] for info in addr_info}
    if not resolved:
        return False, f"DNS resolution returned no addresses for '{hostname_clean}'"
    for ip_str in resolved:
        try:
            ip_obj = ipaddress.ip_address(ip_str.split("%")[0])
        except ValueError:
            return False, f"Unparseable resolved address {ip_str}"
        if is_ip_forbidden(ip_obj):
            return False, f"Resolved IP {ip_obj} for domain '{hostname_clean}' is a private/reserved address."

    return True, "URL passed Anti-SSRF verification."
