from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Lease:
    ip: str; version: str; server: str; state: str
    mac: str = '-'; hostname: str = '-'; expires: str = '-'; starts: str = '-'
    vendor_class: str = '-'; duid: Optional[str] = None; valid_lft: Optional[str] = None


@dataclass
class Conflict:
    kind: str          # 'mac_multiple_active_ips' | 'ip_multiple_active_macs'
    severity: str      # 'HIGH'|'MEDIUM'|'LOW'
    detail: str
    ips: list = field(default_factory=list)
    macs: list = field(default_factory=list)
