# Firmware Bug Report

## O-RU DHCPv4 Transaction ID (xid) Reuse Across Units

| Field | Value |
| --- | --- |
| **Report Date** | 2026-03-31 |
| **Severity** | HIGH — Causes IP address theft between O-RU units |
| **Affected Product** | O-RU models: 44R26-N25N66-DC, 44R14-N77a (FJ vendor prefix) |
| **Affected Interface** | DHCPv4 client on `fheth0` / `fheth0.201` (M-Plane VLAN) |
| **DHCPv6 Status** | NOT affected — DHCPv6 operates correctly with unique DUID+IAID per unit |
| **DHCP Server** | ISC DHCP 4.4.3-P1 on Ubuntu 24.04 (LXC container, Proxmox VE) |
| **O-RAN Spec Reference** | O-RAN.WG4.MP.0-R004-v16.01, Section 6.2.4 (RFC 4361 compliance) |

---

## 1. Executive Summary

A critical defect has been identified in the DHCPv4 client implementation of
FJ-series O-RU units. When multiple O-RUs boot on the same Layer 2 broadcast
domain, all units generate identical DHCP transaction IDs (xid values). Because
DHCPv4 OFFER and REQUEST messages are broadcast, each O-RU intercepts OFFER
messages intended for other units and, matching on the shared xid, sends
competing DHCPREQUEST messages to claim the offered IP address.

The result is that the fastest-responding O-RU steals IP addresses intended for
other units, leaving some O-RUs with no valid IPv4 lease while accumulating
multiple leases on a single unit. This defect does not affect DHCPv6, which
operates correctly.

---

## 2. Detailed Bug Description

### 2.1 Three Interrelated Defects

| Bug # | Title | Description |
| --- | --- | --- |
| **1** | Shared xid across O-RUs | All O-RU units on the same L2 segment generate identical DHCPv4 transaction IDs (xid). Per RFC 2131 Section 4.1, xid must be a random number chosen by the client. Identical xids make it impossible for clients to distinguish their own OFFER from another unit's OFFER. |
| **2** | O-RUs react to foreign OFFERs | Because the xid matches (Bug #1), when the DHCP server broadcasts an OFFER intended for Unit A, Units B and C also interpret this as their own OFFER and send competing DHCPREQUEST messages for the same IP address. The fastest responder wins the lease. |
| **3** | Missing DHCPv4 client-identifier (option 61) | No option 61 is present in any DHCPv4 packet. O-RAN WG4 M-Plane spec Section 6.2.4 requires RFC 4361 compliance with stable client identifiers. Without option 61, the server cannot distinguish clients with conflicting xids and has no mechanism to reject a REQUEST from the wrong client. |

### 2.2 Why DHCPv6 Is Not Affected

The DHCPv6 implementation correctly uses unique DUID (DHCP Unique Identifier)
and IAID (Identity Association Identifier) values per unit. These fields are
carried inside the DHCPv6 message body and are used by the server for client
identification, independent of the Ethernet source address. The DHCPv6
transaction-id appears to be generated independently per unit. All four O-RU
interfaces obtained correct, unique IPv6 leases throughout testing.

---

## 3. Test Environment

### 3.1 Topology

Three O-RU units connected to a single L2 switch, each on an individual switch
port. The switch carries VLAN 201 (M-Plane) to the DHCP server. No L2 bridging
or daisy-chaining is involved — each O-RU has an independent physical path to
the server.

| Unit | Model | fheth0 MAC | Serial (from opt 60) | Switch Port |
| --- | --- | --- | --- | --- |
| Apple #1 | 44R26-N25N66-DC | `34:fe:9e:3d:ad:a8` | A2256600363 | Individual |
| Apple #2 | 44R14-N77a | `34:fe:9e:3d:af:5c` | A1770000213 | Individual |
| Apple #3 | 44R26-N25N66-DC | `34:fe:9e:3d:ad:c8` | A2256600222 | Individual |

### 3.2 DHCP Server Configuration

ISC DHCP 4.4.3-P1, listening on `ens20.201` (VLAN 201). The server uses vendor
class matching (option 60) to assign O-RUs to product-specific address pools.
The `ATTn25n66` pool range is `192.168.36.170–179`; the `ATTn77` pool range is
`192.168.36.160–169`.

---

## 4. Packet Capture Evidence

All packets captured via `tcpdump` on the DHCP server interface (`ens20.201`)
with Ethernet headers (`-e` flag). Two complete DHCP transaction sequences were
captured during simultaneous O-RU boot.

### 4.1 Transaction Sequence #1 — xid 0x8fc37a94

| Time | Eth src | chaddr | Type | IP | Result |
| --- | --- | --- | --- | --- | --- |
| 13:45:03.843 | ad:c8 | ad:c8 | DISCOVER | — | Apple #3 legitimate request |
| 13:45:04.844 | server | ad:c8 | OFFER | .171 | Server offers .171 to ad:c8 |
| 13:45:04.966 | ad:c8 | ad:c8 | REQUEST | .171 | ACK'd — ad:c8 gets .171 |
| 13:45:04.990 | af:5c | af:5c | REQUEST | .171 | NAK'd — af:5c tried to claim .171! |

**Observation:** Apple #2 (af:5c, ATTn77 model) sent a DHCPREQUEST for .171
using the same xid, even though it never sent a DISCOVER in this transaction. It
reacted to the broadcast OFFER meant for ad:c8.

### 4.2 Transaction Sequence #2 — xid 0xcb07f611

This sequence demonstrates the full cascading failure with all three O-RUs
competing:

| Time | Eth src | chaddr | Type | IP | Result |
| --- | --- | --- | --- | --- | --- |
| 13:45:08.244 | ad:a8 | ad:a8 | DISCOVER | — | Apple #1 legitimate request |
| 13:45:09.245 | server | ad:a8 | OFFER | .172 | Server offers .172 to ad:a8 |
| 13:45:09.336 | ad:c8 | ad:c8 | REQUEST | .172 | ACK'd — ad:c8 STEALS .172! |
| 13:45:09.370 | ad:a8 | ad:a8 | REQUEST | .172 | NAK'd — legitimate owner rejected! |
| 13:45:09.387 | af:5c | af:5c | REQUEST | .172 | NAK'd — another intruder! |

**Key finding:** Apple #3 (ad:c8) sent its REQUEST 91ms after the OFFER, while
Apple #1 (ad:a8, the legitimate recipient) took 125ms. Apple #3 consistently
wins the race, accumulating multiple leases while other units receive none.

---

## 5. Resulting Lease State

### 5.1 DHCPv4 — Broken

| IP Address | Server Lease MAC | Actual User MAC | Correct? | O-RU Unit |
| --- | --- | --- | --- | --- |
| 192.168.36.171 | 34:fe:9e:3d:ad:c8 | 34:fe:9e:3d:ad:a8 | NO | Apple #1 |
| 192.168.36.172 | 34:fe:9e:3d:ad:c8 | 34:fe:9e:3d:ad:c8 | YES* | Apple #3 |

\* Apple #3 holds two leases (.171 + .172), which is incorrect. Apple #1 was
allocated .172 on the O-RU side but the server recorded it under ad:c8. Apple #2
(af:5c) failed to obtain any lease from its designated pool.

### 5.2 DHCPv6 — Correct

| IPv6 Address | MAC | O-RU Unit |
| --- | --- | --- |
| fd00:8b36:f2a9::178 | 34:fe:9e:3d:ad:c8 | Apple #3 |
| fd00:8b36:f2a9::179 | 34:fe:9e:3d:ad:a8 | Apple #1 |
| fd00:8b36:f2a9::168 | 34:fe:9e:3d:af:5c | Apple #2 |

All DHCPv6 leases are correctly allocated — one unique address per unit, no
duplicates, no cross-contamination.

---

## 6. Standards Violations

| Standard | Requirement | O-RU Behavior |
| --- | --- | --- |
| RFC 2131 §4.1 | xid: a random transaction identifier generated by the client, used to associate messages and responses. | All O-RUs on the segment generate the same xid value. No randomization observed. |
| RFC 2131 §4.4.1 | Client must check that chaddr and xid in DHCPOFFER match its own DHCPDISCOVER before accepting. | O-RU accepts OFFERs matching xid but with different chaddr (intended for another unit). |
| RFC 4361 / O-RAN WG4 §6.2.4 | O-RU implementing IPv4 shall support RFC 4361 behavior, using stable DHCPv4 node identifiers in dhcp-client-identifier option. | No option 61 (dhcp-client-identifier) present in any captured packet. |

---

## 7. Operational Impact

- O-RU units may fail to obtain a valid IPv4 management address, preventing
  NETCONF call-home and M-Plane connectivity over IPv4.
- DHCP server lease tables become inconsistent with actual O-RU interface
  assignments, making troubleshooting and inventory management unreliable.
- The problem is non-deterministic and timing-dependent — different units may
  win the race on each reboot cycle, making the failure intermittent and
  difficult to diagnose.
- Severity increases linearly with the number of O-RUs sharing a broadcast
  domain. In production deployments with many O-RUs, a large fraction may fail
  to obtain IPv4 addresses.
- Current workaround (DHCP server restart to force lease renewal) is disruptive
  and only temporarily effective.

---

## 8. Recommended Fixes

| Priority | Fix | Detail | Complexity |
| --- | --- | --- | --- |
| **P0** | Randomize xid per unit | Use a cryptographically random or MAC-seeded xid for each DHCP transaction. This alone would prevent the cross-contamination since each unit would ignore OFFERs with non-matching xids. | Low |
| **P0** | Validate chaddr in OFFERs | Before sending a DHCPREQUEST, verify that the chaddr field in the received DHCPOFFER matches the unit's own MAC address, per RFC 2131 Section 4.4.1. | Low |
| **P1** | Implement option 61 (RFC 4361) | Send a dhcp-client-identifier in all DHCPv4 messages, using a stable identifier as required by O-RAN WG4 M-Plane spec Section 6.2.4. This provides defense-in-depth even if xid collision occurs. | Medium |

---

## 9. Reproduction Steps

1. Connect two or more FJ-series O-RUs to the same L2 broadcast domain (VLAN 201).
2. Configure an ISC DHCP server with dynamic pools and vendor class matching for O-RAN option 60.
3. Start tcpdump on the DHCP server interface:
   `tcpdump -i <iface> -nn -vvv -e port 67 or port 68 -w capture.pcap`
4. Power-cycle (reboot) all O-RUs simultaneously.
5. Observe that all DHCPDISCOVER and DHCPREQUEST packets share the same xid value.
6. Observe that units other than the DISCOVER originator send REQUESTs for the offered IP.
7. Verify with `dhcp-lease-list` that the fastest unit accumulates multiple leases while other units have none or stale leases.

---

## 10. Supporting Evidence

- Packet capture file: `dhcpv4_debug.pcap` (tcpdump with `-e` flag on DHCP server interface)
- DHCP server syslog excerpts for MACs `34:fe:9e:3d:ad:c8`, `34:fe:9e:3d:ad:a8`, `34:fe:9e:3d:af:5c`
- O-RU `ifconfig` output confirming per-unit interface assignments and actual IP usage
- ISC DHCP server configuration files: `dhcpd.conf`, `dhcpd6.conf`
- `dhcp-lease-list` output (v1.3.0) showing IPv4 lease duplication and correct IPv6 leases

---

> **Note on this document.** This Markdown report is a faithful transcription of
> `oru_dhcpv4_bug_report.docx`. See [`ANALYSIS.md`](ANALYSIS.md) for what the
> uploaded `packets.pcap` (`samples/oru_real_capture.pcap`) actually contains and
> how the `dhcp-forensics` analyzer is validated against a synthesized
> reconstruction of the packet sequences above.
