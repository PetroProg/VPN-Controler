"""Pydantic schemas and strict input validation for VPN Controler API."""

import ipaddress
import re
from typing import List, Literal
from pydantic import BaseModel, Field, field_validator

_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_SERVICE_ID_RE = re.compile(r"^[a-z0-9_-]{1,40}$")
_TAILSCALE_IPV4_NET = ipaddress.ip_network("100.64.0.0/10")
_TAILSCALE_IPV6_NET = ipaddress.ip_network("fd7a:115c:a1e0::/48")


def normalize_domain(raw: str) -> str:
    """Normalize and validate an RFC hostname to prevent injection and XSS."""
    if not isinstance(raw, str):
        raise ValueError("Domain must be a string")
    value = raw.strip().lower()
    if any(ch in value for ch in (" ", "\t", "\r", "\n", "<", ">", "'", '"', "^", "|", "$", "*", "@", ";", "\\")):
        raise ValueError("Domain contains disallowed characters")
    if value.startswith("http://"):
        value = value[7:]
    elif value.startswith("https://"):
        value = value[8:]
    value = value.split("/", 1)[0].rstrip(".")
    if not value or len(value) > 253 or not _DOMAIN_RE.match(value):
        raise ValueError("Invalid domain name")
    return value


class ToggleFeaturePayload(BaseModel):
    feature: Literal["protection", "adblock", "malware", "doh", "safesearch", "parental"]
    enabled: bool


class PausePayload(BaseModel):
    minutes: int = Field(default=15, ge=1, le=1440)


class UpstreamPayload(BaseModel):
    provider: Literal["quad9", "cloudflare", "adguard", "google"]


class DomainPayload(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        return normalize_domain(v)


class UserRuleAddPayload(BaseModel):
    domain: str
    mode: Literal["block", "allow"] = "block"

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        return normalize_domain(v)


class UserRuleDeletePayload(BaseModel):
    rule: str = Field(..., min_length=3, max_length=300)

    @field_validator("rule")
    @classmethod
    def _validate_rule(cls, v: str) -> str:
        cleaned = v.strip()
        if any(ch in cleaned for ch in ("\r", "\n", "\x00")):
            raise ValueError("Rule contains invalid control characters")
        if len(cleaned) < 3:
            raise ValueError("Rule too short")
        return cleaned


class BlockedServicesPayload(BaseModel):
    ids: List[str] = Field(default_factory=list, max_length=150)

    @field_validator("ids")
    @classmethod
    def _validate_ids(cls, items: List[str]) -> List[str]:
        cleaned: List[str] = []
        seen = set()
        for raw_id in items:
            s = raw_id.strip().lower()
            if not _SERVICE_ID_RE.match(s):
                raise ValueError(f"Invalid service id: {raw_id}")
            if s not in seen:
                seen.add(s)
                cleaned.append(s)
        return cleaned


class RewritePayload(BaseModel):
    domain: str
    answer: str

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        return normalize_domain(v)

    @field_validator("answer")
    @classmethod
    def _validate_answer(cls, v: str) -> str:
        val = v.strip()
        if not val or len(val) > 253:
            raise ValueError("Invalid rewrite answer")
        try:
            ipaddress.ip_address(val)
            return val
        except ValueError:
            return normalize_domain(val)


class PeerPingPayload(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def _validate_tailscale_ip(cls, v: str) -> str:
        val = v.strip()
        try:
            addr = ipaddress.ip_address(val)
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc
        if addr.version == 4 and addr in _TAILSCALE_IPV4_NET:
            return str(addr)
        if addr.version == 6 and addr in _TAILSCALE_IPV6_NET:
            return str(addr)
        raise ValueError("IP must belong to Tailscale network range")
