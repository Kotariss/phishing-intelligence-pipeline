import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # Private RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # Private RFC1918
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / Cloud metadata (AWS, GCP, Azure)
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "host.docker.internal",
    "gateway.docker.internal",
    "metadata.google.internal",
    "instance-data",
}

class SecurityError(Exception):
    pass

class SSRFError(SecurityError):
    pass

def validate_url_safety(url: str, anti_ssrf_enabled: bool = True) -> Tuple[bool, str]:
    """
    Validates that a URL is syntactically safe and does not target internal or reserved infrastructure.
    Returns: (is_safe, message)
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    url_clean = url.strip()
    try:
        parsed = urlparse(url_clean)
    except Exception as e:
        return False, f"Failed to parse URL: {e}"

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, f"Prohibited scheme: '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL is missing hostname."

    hostname_clean = hostname.lower()

    if hostname_clean in BLOCKED_HOSTNAMES:
        return False, f"Hostname '{hostname_clean}' is prohibited (SSRF prevention)."

    if not anti_ssrf_enabled:
        return True, "URL is syntactically valid (SSRF checks disabled)."

    # Check if hostname is an IP literal
    try:
        ip = ipaddress.ip_address(hostname_clean)
        for net in BLOCKED_IP_NETWORKS:
            if ip in net:
                return False, f"Destination IP {ip} falls into prohibited private/reserved range {net}."
        return True, f"IP {ip} is public and valid."
    except ValueError:
        # Hostname is a domain name, resolve via DNS
        pass

    try:
        addr_info = socket.getaddrinfo(hostname_clean, None)
        resolved_ips = set()
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            resolved_ips.add(ip_str)

        if not resolved_ips:
            return False, f"DNS resolution failed for hostname '{hostname_clean}'"

        for ip_str in resolved_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in BLOCKED_IP_NETWORKS:
                if ip_obj in net:
                    return False, f"Resolved IP {ip_obj} for domain '{hostname_clean}' falls into prohibited range {net}."
    except socket.gaierror as e:
        # DNS lookup failure (e.g. non-existent domain, typical for offline phishing)
        # We allow it to proceed with caution because phishing domains frequently die
        return True, f"DNS resolution failed ({e}), permitted as offline or dead target."
    except Exception as e:
        return False, f"Error validating hostname: {e}"

    return True, "URL passed Anti-SSRF verification."
