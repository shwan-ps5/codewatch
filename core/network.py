"""Which addresses the server may be asked to reach on a user's behalf: only public ones, unless an administrator
set the project up (a staging site or a git server on the local network is their call, not a user's)."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit

# git@host:path (scp-like) has no scheme for urlsplit.
SCP_LIKE_RE = re.compile(r"^[\w.-]+@([\w.-]+):")


def url_host(url):
    match = SCP_LIKE_RE.match(url)
    return match[1] if match else urlsplit(url).hostname


def public_address(address):
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped:  # an IP version, not a magic number
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_public(url):
    """ValueError unless every address the URL's host resolves to is public (not loopback, private, link-local such
    as a cloud metadata service, or reserved). Checked again when the server connects, since DNS can change."""
    host = url_host(url)
    if not host:
        raise ValueError(f"No host in {url}")
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except (socket.gaierror, UnicodeError) as exc:
        raise ValueError(f"{host} doesn't resolve") from exc
    if not all(public_address(a.split("%", 1)[0]) for a in addresses):
        raise ValueError(f"{host} is on a private or local network; only an administrator can use it")
    return url


def trusted_owner(project):
    """Set up by an administrator: owned by one, or added with `manage.py addproject` (no owner)."""
    return project.owner_id is None or project.owner.is_superuser
