import ipaddress
import re
from typing import Optional, Tuple

# RFC Bogon / Reserved / Private IPv4 and IPv6 networks
_BOGON_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source address)
    ipaddress.ip_network("10.0.0.0/8"),         # Private network (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space / Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 5735)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private network (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # Private network (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited broadcast (RFC 919)
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
]

_IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_REGEX = re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}')


def extract_first_ip(text: str) -> Optional[str]:
    """Extracts the first valid IPv4 or IPv6 address found in a string."""
    if not text:
        return None

    # First look for bracketed IP: [1.2.3.4] or (1.2.3.4)
    bracket_match = re.search(r'[\[\(]([0-9a-fA-F\.:]+)[\]\)]', text)
    if bracket_match:
        candidate = bracket_match.group(1).strip()
        if is_valid_ip(candidate):
            return candidate

    # Search for standard IPv4
    for match in _IPV4_REGEX.finditer(text):
        candidate = match.group(0)
        if is_valid_ip(candidate):
            return candidate

    # Search for IPv6
    for match in _IPV6_REGEX.finditer(text):
        candidate = match.group(0)
        if is_valid_ip(candidate):
            return candidate

    return None


def is_valid_ip(ip_str: str) -> bool:
    """Returns True if the string is a valid IPv4 or IPv6 address."""
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_bogon_or_private(ip_str: str) -> bool:
    """
    Returns True if the IP is an unroutable bogon, RFC 1918 private,
    loopback, link-local, or carrier NAT address.
    """
    if not ip_str:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            return True
        for net in _BOGON_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return True


def defang_ip(ip_str: str) -> str:
    """Defangs an IP address for safe presentation (e.g. 192.168.1.1 -> 192[.]168[.]1[.]1)."""
    if not ip_str:
        return ""
    return ip_str.replace(".", "[.]")


def defang_url(url: str) -> str:
    """Defangs a URL for safe presentation (e.g. https://evil.com -> hxxps[://]evil[.]com)."""
    if not url:
        return ""
    clean = url.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
    # Defang domain dots but preserve path slashes
    parts = clean.split("/", 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace(".", "[.]")
        return "/".join(parts)
    return clean.replace(".", "[.]")
