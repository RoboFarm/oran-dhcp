from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class CapturedPacket:
    index: int; ts: float; eth_src: str; eth_dst: str; ethertype: int
    vlan: Optional[int]; l3: str; src_ip: Optional[str]; dst_ip: Optional[str]
    l4: Optional[str]; src_port: Optional[int]; dst_port: Optional[int]
    payload: bytes = b''; raw: bytes = b''


@dataclass
class DHCPv4Message:
    op: int; xid: int; ciaddr: str; yiaddr: str; siaddr: str; giaddr: str; chaddr: str
    msg_type: Optional[int]; msg_type_name: str
    requested_ip: Optional[str] = None; server_id: Optional[str] = None
    client_id: Optional[bytes] = None; client_id_str: Optional[str] = None
    vendor_class: Optional[str] = None; hostname: Optional[str] = None
    options: dict = field(default_factory=dict)


@dataclass
class DHCPv6Message:
    msg_type: int; msg_type_name: str; transaction_id: int
    client_duid: Optional[bytes] = None; server_duid: Optional[bytes] = None
    addresses: list = field(default_factory=list); vendor_class: Optional[str] = None
    options: dict = field(default_factory=dict)


@dataclass
class Transaction:
    key: str; version: str; xid: int
    packets: list = field(default_factory=list)   # list of (CapturedPacket, decoded msg)
    macs: list = field(default_factory=list)       # distinct chaddr
    eth_srcs: list = field(default_factory=list)
    offered_ips: list = field(default_factory=list)
    requested_ips: list = field(default_factory=list)


@dataclass
class Finding:
    id: str; title: str; severity: str   # HIGH|MEDIUM|LOW|INFO
    category: str; description: str
    evidence: list = field(default_factory=list)
    standards: list = field(default_factory=list)
    recommendation: str = ''
