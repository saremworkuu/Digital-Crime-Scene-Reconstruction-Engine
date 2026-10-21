"""IOC value format validation by type."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?@"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
USER_RE = re.compile(r"^[A-Za-z0-9._\\@-]{1,128}$")
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)

IOC_EXAMPLES = {
    "ip": "192.0.2.10 or 2001:db8::1",
    "domain": "evil.example.com",
    "hash": "MD5/SHA1/SHA256 hex",
    "user": "DOMAIN\\alice or alice@corp",
    "host": "ws-1042 or host.corp.local",
    "email": "phish@evil.example",
    "url": "https://evil.example/path",
}


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"ip must be a valid IPv4/IPv6 address (e.g. {IOC_EXAMPLES['ip']})") from exc


def _validate_domain(value: str) -> str:
    cleaned = value.rstrip(".").lower()
    if not DOMAIN_RE.match(cleaned):
        raise ValueError(f"domain must be a valid FQDN (e.g. {IOC_EXAMPLES['domain']})")
    return cleaned


def _validate_email(value: str) -> str:
    cleaned = value.strip().lower()
    if not EMAIL_RE.match(cleaned):
        raise ValueError(f"email must be a valid address (e.g. {IOC_EXAMPLES['email']})")
    return cleaned


def _validate_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"url must be http(s) with a host (e.g. {IOC_EXAMPLES['url']})")
    return value.strip()


def _validate_hash(value: str) -> str:
    cleaned = value.strip().lower()
    if not HASH_RE.match(cleaned):
        raise ValueError(f"hash must be MD5 (32), SHA1 (40), or SHA256 (64) hex")
    return cleaned


def _validate_user(value: str) -> str:
    cleaned = value.strip()
    if not USER_RE.match(cleaned):
        raise ValueError(f"user must be an account name (e.g. {IOC_EXAMPLES['user']})")
    return cleaned


def _validate_host(value: str) -> str:
    cleaned = value.strip().lower()
    # Allow bare IP used as host identifier
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        pass
    if not HOST_RE.match(cleaned):
        raise ValueError(f"host must be a hostname (e.g. {IOC_EXAMPLES['host']})")
    return cleaned


_VALIDATORS = {
    "ip": _validate_ip,
    "domain": _validate_domain,
    "email": _validate_email,
    "url": _validate_url,
    "hash": _validate_hash,
    "user": _validate_user,
    "host": _validate_host,
}


def normalize_ioc_value(ioc_type: str, value: str) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        raise ValueError("value is required")
    validator = _VALIDATORS.get(ioc_type)
    if not validator:
        return cleaned
    return validator(cleaned)
