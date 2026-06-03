# Capture Analysis: what the uploaded pcap actually contains

This document records, honestly and precisely, what is and is not in the packet
capture that shipped with the bug report, and how the `dhcp-forensics` analyzer
is validated despite the real capture lacking the relevant traffic.

## TL;DR

- The uploaded capture (`samples/oru_real_capture.pcap`, originally
  `packets.pcap`) is the **O-RU's own fronthaul capture**. It is dominated by
  PTP, with a single DHCPv6 message and **zero DHCPv4 packets**.
- The **server-side `dhcpv4_debug.pcap`** named in the bug report's
  "Supporting Evidence" section — the capture that actually holds the
  xid-reuse / IP-theft evidence — **was not part of the upload.**
- Therefore the DHCPv4 defect **cannot be observed in the real file**. To
  validate the analyzer, the repository includes a **synthesized fixture**,
  `tests/fixtures/oru_xid_reuse.pcap`, reconstructed byte-for-byte from the two
  documented transaction sequences in the bug report. The analyzer flags all
  three defects on that fixture (10 HIGH findings, verdict `AFFECTED`).

---

## 1. What is in `samples/oru_real_capture.pcap`

Format: classic pcap, little-endian, microsecond timestamps, linktype `1`
(`EN10MB` / Ethernet), snaplen 300. Parsed entirely with the Python standard
library (no scapy/tshark/tcpdump).

Running the analyzer:

```
$ PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli samples/oru_real_capture.pcap --no-color
```

produces:

```
==============================================================================
DHCP-ORU FORENSIC REPORT  (toolkit v2.0.0)
==============================================================================
Source pcap : samples/oru_real_capture.pcap
Note        : capture contains no DHCPv4 traffic; DHCPv4 defect cannot be observed in this file
Verdict     : NO DHCPv4 TRAFFIC

CAPTURE SUMMARY
------------------------------------------------------------------------------
Total frames : 555
DHCPv4 msgs  : 0
DHCPv6 msgs  : 1
Ethertypes   : 0x88f7=539, 0x8809=10, 0x86dd=5, 0x0800=1
VLANs        : none=553, 201=2

TRANSACTIONS (1)
------------------------------------------------------------------------------
Transaction v6:0xdd6ab9  [DHCPv6]  packets=1
  duids : 00020000cf9c33343a66653a39653a33643a61663a3563
  offered: fd00:8b36:f2a9:0000:0000:0000:0000:0168
  time          eth_src            type          addresses
  ------------------------------------------------------------
  00:01:42.376  34:fe:9e:3d:af:5c  RENEW         fd00:8b36:f2a9:0000:0000:0000:0000:0168

FINDINGS (0)
------------------------------------------------------------------------------
No issues detected.

STANDARDS VIOLATIONS
------------------------------------------------------------------------------
(none)

==============================================================================
VERDICT: NO DHCPv4 TRAFFIC   (HIGH=0, MEDIUM=0, LOW=0, INFO=0)
==============================================================================
```

Exit status: `0` (no HIGH findings).

### Frame breakdown (555 frames total)

| Ethertype | Protocol | Count |
| --- | --- | --- |
| `0x88f7` | PTP / IEEE 1588 (precision time) | 539 |
| `0x8809` | Slow protocols (LACP / OAM) | 10 |
| `0x86dd` | IPv6 | 5 |
| `0x0800` | IPv4 | 1 |

VLAN tagging: 553 frames are untagged; **2 frames carry VLAN 201** (the M-Plane
VLAN). One of those VLAN-201 frames is the lone DHCPv6 message; the other is the
single IPv4 frame, which is **not** DHCPv4 (no UDP/67 or /68).

### The single DHCP packet

Exactly **one** DHCP message of any kind is present: a **DHCPv6** message on
UDP 546 -> 547, on VLAN 201, sourced from `34:fe:9e:3d:af:5c` (Apple #2's MAC).
The analyzer decodes its message-type byte as **`5` = RENEW**.

> **Honesty note on "SOLICIT vs RENEW".** Project notes loosely described this
> as "one DHCPv6 SOLICIT." The actual message-type byte in the capture is `5`,
> which is **RENEW** in DHCPv6 (SOLICIT would be type `1`). Both the raw bytes
> and the analyzer agree it is a RENEW. This is expected: a RENEW from an O-RU
> that already holds a lease is exactly the kind of steady-state M-Plane traffic
> you would see in the unit's own fronthaul capture. Either way, it confirms the
> bug report's claim that **DHCPv6 is healthy** -- one unit, one unique
> DUID+IAID, one address, no contention.

## 2. What is NOT in the capture

- **No DHCPv4 traffic at all.** Zero DISCOVER / OFFER / REQUEST / ACK / NAK
  packets. The shared-xid IP-theft behaviour is a DHCPv4 phenomenon and simply
  is not present in this file.
- **No `dhcpv4_debug.pcap`.** The bug report (Section 10, "Supporting
  Evidence") cites a server-side capture taken with `tcpdump -e` on the DHCP
  server interface. *That* file is where the xid-reuse evidence lives. It was
  **not included in the upload**, so it cannot be analyzed here.

The reason is straightforward: the uploaded `packets.pcap` was taken on the
**O-RU's fronthaul interface**, which is dominated by PTP and carries only this
unit's own steady-state M-Plane chatter -- not the broadcast DHCPv4 contention
seen from the **server** during a simultaneous multi-unit boot.

## 3. How the analyzer is validated: the synthesized fixture

Because the real DHCPv4 evidence was not uploaded, the repository ships a
**synthesized reconstruction**, `tests/fixtures/oru_xid_reuse.pcap`, built by
`tools/make_fixtures.py` directly from the two transaction sequences documented
in the bug report (4.1 xid `0x8fc37a94`, 4.2 xid `0xcb07f611`), including the
exact MACs, timestamps, offered IPs, ACK/NAK outcomes, the opt 60 vendor class,
and the deliberate **absence of opt 61**. It is a faithful, deterministic
stand-in for the missing `dhcpv4_debug.pcap`, not a real capture.

Running the analyzer on the fixture:

```
$ PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli tests/fixtures/oru_xid_reuse.pcap --no-color
```

reproduces all three defects (full output abridged for the two transactions and
the finding headers):

```
Source pcap : tests/fixtures/oru_xid_reuse.pcap
Verdict     : AFFECTED

CAPTURE SUMMARY
------------------------------------------------------------------------------
Total frames : 14
DHCPv4 msgs  : 14
DHCPv6 msgs  : 0
Ethertypes   : 0x0800=14
VLANs        : 201=14

TRANSACTIONS (2)
------------------------------------------------------------------------------
Transaction v4:0x8fc37a94  [DHCPv4]  packets=6
  macs  : 34:fe:9e:3d:ad:c8, 34:fe:9e:3d:af:5c
  offered: 192.168.36.171
  time          eth_src            chaddr             type      ip
  --------------------------------------------------------------------------
  13:45:03.843  34:fe:9e:3d:ad:c8  34:fe:9e:3d:ad:c8  DISCOVER  -
  13:45:04.844  02:00:5e:00:00:01  34:fe:9e:3d:ad:c8  OFFER     192.168.36.171
  13:45:04.966  34:fe:9e:3d:ad:c8  34:fe:9e:3d:ad:c8  REQUEST   192.168.36.171
  13:45:04.970  02:00:5e:00:00:01  34:fe:9e:3d:ad:c8  ACK       192.168.36.171
  13:45:04.990  34:fe:9e:3d:af:5c  34:fe:9e:3d:af:5c  REQUEST   192.168.36.171
  13:45:04.994  02:00:5e:00:00:01  34:fe:9e:3d:af:5c  NAK       -

Transaction v4:0xcb07f611  [DHCPv4]  packets=8
  macs  : 34:fe:9e:3d:ad:a8, 34:fe:9e:3d:ad:c8, 34:fe:9e:3d:af:5c
  offered: 192.168.36.172
  time          eth_src            chaddr             type      ip
  --------------------------------------------------------------------------
  13:45:08.244  34:fe:9e:3d:ad:a8  34:fe:9e:3d:ad:a8  DISCOVER  -
  13:45:09.245  02:00:5e:00:00:01  34:fe:9e:3d:ad:a8  OFFER     192.168.36.172
  13:45:09.336  34:fe:9e:3d:ad:c8  34:fe:9e:3d:ad:c8  REQUEST   192.168.36.172
  13:45:09.340  02:00:5e:00:00:01  34:fe:9e:3d:ad:c8  ACK       192.168.36.172
  13:45:09.370  34:fe:9e:3d:ad:a8  34:fe:9e:3d:ad:a8  REQUEST   192.168.36.172
  13:45:09.374  02:00:5e:00:00:01  34:fe:9e:3d:ad:a8  NAK       -
  13:45:09.387  34:fe:9e:3d:af:5c  34:fe:9e:3d:af:5c  REQUEST   192.168.36.172
  13:45:09.391  02:00:5e:00:00:01  34:fe:9e:3d:af:5c  NAK       -

FINDINGS (10)
------------------------------------------------------------------------------
== HIGH (10) ==
  [SHARED_XID]               xid 0x8fc37a94 shared by 2 MACs (RFC 2131 4.1)
  [SHARED_XID]               xid 0xcb07f611 shared by 3 MACs (RFC 2131 4.1)
  [FOREIGN_OFFER_REACTION]   af:5c requested .171 OFFERed to ad:c8 (RFC 2131 4.4.1)
  [FOREIGN_OFFER_REACTION]   ad:c8 + af:5c requested .172 OFFERed to ad:a8 (RFC 2131 4.4.1)
  [MISSING_CLIENT_ID]        no option 61 on ad:c8 / af:5c / ad:a8 (RFC 4361, O-RAN.WG4.MP 6.2.4)
  [DUPLICATE_GRANT_MAC]      ad:c8 granted both .171 and .172
  [DUPLICATE_GRANT_IP]       .171 contested by 2 MACs; .172 contested by 3 MACs

==============================================================================
VERDICT: AFFECTED   (HIGH=10, MEDIUM=0, LOW=0, INFO=0)
==============================================================================
```

Exit status: `2` (HIGH findings present).

The finding text shown above is condensed; the tool emits full per-finding
descriptions, standards references, recommended fixes, and packet-level
evidence. See the man page `dhcp-forensics(8)` and run the command yourself to
see the complete report.

## 4. Bottom line

| Question | Answer |
| --- | --- |
| Does the uploaded pcap contain the DHCPv4 defect? | **No** -- it has zero DHCPv4 packets. |
| What does it actually contain? | 555 frames: 539 PTP, 10 LACP, 5 IPv6, 1 IPv4; exactly one DHCP message -- a healthy DHCPv6 RENEW on VLAN 201. |
| Where is the real evidence? | In the server-side `dhcpv4_debug.pcap`, which was **not uploaded**. |
| How is the analyzer validated? | Against `tests/fixtures/oru_xid_reuse.pcap`, a synthesized reconstruction of the bug report's documented sequences. It correctly flags shared-xid, foreign-OFFER reaction, missing option 61, and the resulting duplicate grants. |
