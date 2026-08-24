# dhcp-oru-toolkit -- shared contract

This file is the source of truth shared by every agent working on the repo.
The scaffold agent owns `src/dhcp_toolkit/leases/models.py` and
`src/dhcp_toolkit/forensics/models.py`; everyone else imports from them and
must match the function signatures below exactly.

## PACKAGE LAYOUT (src layout)

```
src/dhcp_toolkit/__init__.py            (version "2.1.1", short docstring; NO eager submodule imports)
src/dhcp_toolkit/leases/__init__.py
src/dhcp_toolkit/leases/models.py       (dataclasses: Lease, Conflict)            [scaffold owns]
src/dhcp_toolkit/leases/parsers.py      [leases agent]
src/dhcp_toolkit/leases/kea_config.py   [leases agent]   (Kea config discovery)
src/dhcp_toolkit/leases/display.py      [leases agent]
src/dhcp_toolkit/leases/conflicts.py    [leases agent]
src/dhcp_toolkit/leases/cli.py          [leases agent]   -> entrypoint main(argv=None)->int
src/dhcp_toolkit/forensics/__init__.py
src/dhcp_toolkit/forensics/models.py    (dataclasses below)                       [scaffold owns]
src/dhcp_toolkit/forensics/pcap.py      [fdecode agent]
src/dhcp_toolkit/forensics/dhcp.py      [fdecode agent]
src/dhcp_toolkit/forensics/transactions.py [fdetect agent]
src/dhcp_toolkit/forensics/detectors.py    [fdetect agent]
src/dhcp_toolkit/forensics/report.py       [fdetect agent]
src/dhcp_toolkit/forensics/cli.py          [fdetect agent] -> main(argv=None)->int
tools/make_fixtures.py                  [fixtures agent] (writes raw bytes; pure stdlib)
tests/                                  [tests agent] + tests/run_all.py stdlib runner
packaging/debian/...                    [packaging agent]
docs/, README.md                        [docs agent]
configs/dhcpd.conf, configs/dhcpd6.conf [scaffold copies]
samples/oru_real_capture.pcap           [scaffold copies from _scout]
```

## DATA MODELS (scaffold writes these EXACTLY; everyone imports from them)

### leases/models.py

```python
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
```

### forensics/models.py

```python
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
    requested_ip: Optional[str]=None; server_id: Optional[str]=None
    client_id: Optional[bytes]=None; client_id_str: Optional[str]=None
    vendor_class: Optional[str]=None; hostname: Optional[str]=None
    options: dict = field(default_factory=dict)
@dataclass
class DHCPv6Message:
    msg_type: int; msg_type_name: str; transaction_id: int
    client_duid: Optional[bytes]=None; server_duid: Optional[bytes]=None
    addresses: list = field(default_factory=list); vendor_class: Optional[str]=None
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
```

## PUBLIC FUNCTION SIGNATURES (implementers must match exactly)

```
leases.parsers: parse_isc_v4(path)->list[Lease]; parse_isc_v6(path)->list[Lease];
                parse_kea_v4(path)->list[Lease]; parse_kea_v6(path)->list[Lease];
                extract_mac_from_duid(duid_raw:str)->str   (preserve ALL original bugfix logic, changelog 1.0->1.3)
                mac_from_duid_bytes(duid:bytes)->str       (byte-level core shared by the ISC and Kea decoders)
                mac_from_kea_duid(duid_text:str)->str; mac_from_kea_client_id(client_id_text:str)->str
                hex_to_bytes(text:str)->bytes; kea_unescape(value:str)->str
                epoch_to_datetime(epoch_str)->str          (UTC; ISC lease files are UTC too)
                kea_lease_files(path)->list[str]           (primary + LFC .completed/.2/.1, oldest first)
leases.kea_config: discover_lease_source(family:str, config_dirs=None)->KeaLeaseSource;
                find_config(family:str, config_dirs=None)->Optional[str];
                read_kea_config(path)->Optional[dict]; strip_json_comments(text)->str;
                expand_includes(text, base_dir, depth=0)->str
                KeaLeaseSource(family, backend, path, persist, config_path, note) with .readable
leases.display: is_expired(s)->bool; state_color(state,expires)->str; print_leases(leases, show_expired=False, filter_state=None, use_color=True)->None
leases.conflicts: find_conflicts(leases:list[Lease])->list[Conflict]
forensics.pcap: read_pcap(path)->list[CapturedPacket]   (classic pcap LE/BE, microsecond+nanosecond magic; minimal pcapng; EN10MB linktype 1; strip 802.1Q + QinQ; IPv4/IPv6/UDP; tolerate truncation -> skip bad records, never crash)
forensics.dhcp: decode_dhcpv4(payload:bytes)->Optional[DHCPv4Message]; decode_dhcpv6(payload:bytes)->Optional[DHCPv6Message]; plus DHCPV4_TYPES, DHCPV6_TYPES dicts
forensics.transactions: build_transactions(packets:list[CapturedPacket])->list[Transaction]   (decode each UDP/67/68 or 546/547 payload, group v4 by xid)
forensics.detectors: run_all(transactions, packets)->list[Finding]; individual: detect_shared_xid, detect_foreign_offer_reaction, detect_missing_client_id, detect_chaddr_ethsrc_mismatch, detect_duplicate_grants
forensics.report: summarize_capture(packets)->dict (ethertype/protocol histogram, dhcp v4/v6 counts); build_report(findings, transactions, capture_summary, meta)->dict; render_text(report, use_color=True)->str
forensics.cli: main(argv=None)->int   usage: dhcp-forensics PCAP [--json] [--leases FILE] [--config FILE] [--no-color]; exit 0 if no HIGH findings else 2
leases.cli: main(argv=None)->int  preserve original argparse (--server, --v4-lease, --v6-lease, --all, --state, --v4-only, --v6-only, --version) and ADD --conflicts (run find_conflicts and print) and --kea-config-dir
            --server gained the choices auto (DEFAULT) and both; isc/kea still force one server
            helpers: sniff_server(path)->'kea'|'isc'|None; detect_servers(args, config_dirs)->list[str];
                     kea_lease_path(family, explicit, config_dirs)->(path, note)
```

## pyproject.toml

name `dhcp-oru-toolkit`, version `2.1.1`, src layout, `requires-python>=3.8`,
no runtime deps, `[project.scripts]` `dhcp-lease-list = dhcp_toolkit.leases.cli:main`
and `dhcp-forensics = dhcp_toolkit.forensics.cli:main`, optional
`[project.optional-dependencies] test = ["pytest"]`.

## TOOLING CONSTRAINTS

Python 3.12, but NO scapy/dpkt/tshark/tcpdump. ALL pcap parsing must be pure
stdlib. `dpkg-deb`, `fakeroot`, `git` ARE available. No network assumed: do NOT
rely on pip installing anything; run code with `PYTHONPATH=src` and make tests
runnable WITHOUT pytest (a stdlib fallback runner in `tests/run_all.py`). The
repo is pure stdlib.

## THE BUG (context for detectors)

Multiple O-RUs on one L2 segment all emit the SAME DHCPv4 transaction-id (xid),
so each unit reacts to broadcast OFFERs meant for others and races to REQUEST
the offered IP -> IP theft, duplicate leases on one unit, others get none.
Three defects:

1. shared xid across units [RFC 2131 4.1]
2. O-RUs accept OFFERs whose chaddr != their own [RFC 2131 4.4.1]
3. no DHCPv4 option 61 client-id [RFC 4361 / O-RAN.WG4.MP section 6.2.4]

DHCPv6 is UNAFFECTED (unique DUID+IAID per unit).
