# DHCP O-RU Toolkit - User Manual

**Version 2.1.0**

**Published 2026-06-03**

A pair of zero-dependency, pure standard-library command-line tools for inspecting DHCP lease state and forensically analyzing packet captures to detect and explain the Fujitsu O-RU shared-transaction-id DHCPv4 defect.

[[PAGEBREAK]]

# Table of Contents

1. Introduction and Overview
1. Background: The O-RU DHCPv4 Shared-XID Defect
1. Installation and Upgrade
1. Command Reference: dhcp-lease-list
1. Command Reference: dhcp-forensics
1. Supported Input Formats
1. Tutorials and Operational Workflows
1. Troubleshooting, FAQ, and Appendices

[[PAGEBREAK]]

# Introduction and Overview

The **DHCP O-RU Toolkit** version 2.1.0 is a pair of command-line tools for operating and troubleshooting DHCP on Fujitsu O-RAN radio units (O-RUs). This chapter explains what the toolkit is, the problem it solves, the two commands it installs, who should use it, and what has changed since the previous release.

## What the Toolkit Is

The toolkit gives you a way to inspect DHCP lease state and to forensically analyze packet captures for a specific O-RU defect, without installing any heavyweight network-analysis software. It ships as a single Python package, `dhcp_toolkit`, and installs two console commands on your `PATH`: `dhcp-lease-list` and `dhcp-forensics`.

When several Fujitsu FJ-series O-RUs boot on the same Layer 2 segment, they emit the **same DHCPv4 transaction-id (xid)**. Because of this, each unit reacts to broadcast `OFFER` messages meant for other units and races to `REQUEST` the offered IP address. The fastest unit accumulates multiple leases while other units get none. The O-RUs also accept `OFFER` messages whose hardware address (`chaddr`) is not their own, and they send no DHCP option 61 client-identifier for the server to tell them apart. DHCPv6 is not affected, because each unit uses a unique DUID and IAID. The full background appears in the chapter on the O-RU DHCPv4 shared-xid defect.

The toolkit helps you confirm whether you are seeing this defect in the field and provides the lease-table and packet-level evidence to support that conclusion.

## The Two Commands and How They Relate

The toolkit installs two commands that approach the same defect from two different angles. You typically use them together.

- **`dhcp-lease-list`** reads the lease database on your DHCP server (ISC `dhcpd` or Kea, IPv4 and IPv6) and shows you the current lease state. With the `--conflicts` flag it scans the parsed leases for the lease-table symptoms of the defect, such as one MAC holding several active IP addresses, or one IP held by several active MACs.
- **`dhcp-forensics`** reads a packet capture (classic `pcap` or minimal `pcapng`), decodes the DHCPv4 and DHCPv6 exchanges, groups them into transactions, and detects the shared-xid, foreign-offer-reaction, and missing-client-identifier defects directly from the wire traffic.

The relationship is straightforward. The lease viewer tells you what the **end state** of your address pool looks like, which is fast to check and runs against data you already have. The forensics analyzer tells you **how that state came about** by examining the packets that produced it. The forensics command can also fold lease data in with its `--leases` flag, cross-checking granted IPs against a lease database so that the two views reinforce each other.

Both commands report a problem the same way. When a HIGH-severity finding is present, the command exits with status `2`; otherwise it exits `0`. This makes either tool easy to wire into a monitoring script or a health check.

## Who Should Use This Toolkit

This manual is written for operators who work with DHCP and O-RAN fronthaul networks:

- Network and RAN operators who run O-RU deployments and need to confirm address-assignment problems.
- DHCP administrators who manage ISC `dhcpd` or Kea servers and inspect lease databases.
- Field engineers who collect packet captures on site and need to analyze them without specialized tooling.

You should be comfortable on a Linux command line and familiar with basic DHCP concepts (DISCOVER, OFFER, REQUEST, ACK, leases). You do not need any prior knowledge of packet-analysis frameworks.

## Design Principle: Pure Standard Library, Zero Dependencies

The toolkit is built entirely on the **Python standard library** and has **zero third-party dependencies**. There is no requirement for `scapy`, `dpkt`, `tshark`, or `tcpdump`. All pcap reading and all DHCPv4/DHCPv6 decoding are done with standard-library code. This means you can run the tools on a locked-down field laptop or a hardened server where installing extra packages is not an option, and you can trust that the behavior does not change with an upstream library upgrade.

The supported Python version is **Python 3.8 or newer** (`requires-python = ">=3.8"`). Because the package is pure Python with no compiled parts, the same code runs unchanged across supported interpreter versions.

## Confirming Your Version

You can verify which version you are running with the `--version` flag:

```
$ dhcp-lease-list --version
dhcp-lease-list 2.1.0
```

The package itself also reports `2.1.0` through `dhcp_toolkit.__version__`, and the forensics report header reads `DHCP-ORU FORENSIC REPORT  (toolkit v2.1.0)`.

## What's New in v2.1.0

Version 2.1.0 makes Kea DHCP a first-class server in `dhcp-lease-list` rather than a hardcoded pair of CSV paths. Kea had been nominally supported since v1.3.0, but on a real Kea host the viewer routinely showed nothing, showed stale state, or showed leases it could not tie to a unit.

- **The server is detected.** `--server` now defaults to `auto`, so a bare `dhcp-lease-list` works on a Kea-only host; a lease file named on the command line has its format sniffed; and `--server both` reports an ISC and a Kea section side by side.
- **Kea lease files are located from the Kea config,** through the `lease-database` block of `kea-dhcp4.conf` / `kea-dhcp6.conf`, instead of being assumed. Kea's comment and `<?include?>` extensions to JSON are handled, and `--kea-config-dir` points at a non-standard location. A MySQL or PostgreSQL lease backend, or a non-persistent `memfile`, is reported as such instead of yielding a silently empty table.
- **Lease File Cleanup generations are read.** While Kea's LFC is running - or permanently, if it was interrupted - most leases live in the `.1`, `.2` and `.completed` files rather than the primary one. They are now read alongside it, in Kea's own load order.
- **Kea's journal is replayed the way Kea replays it:** the last row for an address wins, and `valid_lifetime = 0` deletes it. Released, declined and reclaimed addresses are no longer displayed as still held.
- **MAC addresses are recovered** from the DHCPv6 DUID and the DHCPv4 option 61 client-identifier when Kea left the `hwaddr` column empty, so O-RUs are identifiable on either server.
- **Lease expiry is evaluated in UTC.** Kea epochs were being converted with the server's local clock under a column heading that says UTC, and expiry was compared against a local `now`. On a server east of UTC that hid still-valid leases from the default listing; west of it, expired leases lingered. This affected ISC leases as much as Kea ones.

The command-line interface is otherwise unchanged: every flag accepted by v2.0.0 still works, and `--server isc` still behaves exactly as before.

## What's New Since v1.3.0

Version 2.0.0 was a major step up from the v1.3.0 lease viewer.

- **The lease viewer was modularized.** The previously monolithic lease tool was reorganized into focused modules for parsing, display, and conflict detection, while preserving all of the original parsing behavior and command-line flags (`--server`, `--v4-lease`, `--v6-lease`, `--all`, `--state`, `--v4-only`, `--v6-only`, `--version`).
- **Conflict detection was added.** A new `--conflicts` flag scans the parsed leases for the IP-theft signature and reports each conflict with a severity. When a HIGH conflict is found, `dhcp-lease-list` exits with status `2`.
- **A new packet analyzer was added.** The entirely new `dhcp-forensics` command did not exist in v1.3.0. It decodes a capture, groups DHCP exchanges into transactions, and reports a verdict such as `AFFECTED` along with the specific findings it detected, exiting `0` when there are no HIGH findings and `2` otherwise.

The chapters that follow cover each command in detail, including every flag, the output format, exit codes, and worked examples against real and synthesized captures.

[[PAGEBREAK]]

# Background: The O-RU DHCPv4 Shared-XID Defect

This chapter explains **why the DHCP O-RU Toolkit exists**. If you operate an O-RAN fronthaul network and you have units that intermittently fail to obtain an IPv4 management address, or a DHCP server whose lease table no longer matches the radios in the field, the defect described here is the most likely cause. The toolkit's two commands, `dhcp-lease-list` and `dhcp-forensics`, were built specifically to detect and explain this fault from the evidence you already collect: lease files and packet captures.

You do not need to read the original engineering bug report to use the toolkit, but understanding the defect makes the tool output far easier to interpret. Read this chapter once, then return to the command reference chapters.

## What Goes Wrong, in Plain Terms

The defect affects the **DHCPv4 client** in the firmware of certain Fujitsu (FJ vendor prefix) O-RAN radio units, including models `44R26-N25N66-DC` and `44R14-N77a`, on their M-Plane management interface (`fheth0` / `fheth0.201`, VLAN 201). When several of these radios boot at the same time on the same Layer 2 broadcast domain, they fight over each other's IP addresses. The fastest radio steals addresses meant for its neighbours, ends up holding several leases, and leaves other radios with no valid IPv4 address at all.

The behaviour is **timing-dependent and intermittent**. Because the winner of each race is decided by milliseconds, a different radio may win on each reboot. A unit that comes up cleanly today may fail tomorrow, which is exactly what makes the fault so hard to diagnose without a tool that reads the packet evidence directly.

The single fault that operators observe is actually **three interrelated firmware defects** working together. The toolkit names and reports each one separately.

### Defect 1: A Shared Transaction ID (xid) Across Radios

Every DHCP exchange carries a **transaction ID**, called the `xid`. RFC 2131 section 4.1 requires the client to choose this as a random number, so that a radio can recognise which replies on the broadcast network belong to its own request. In the affected firmware, **all radios on the same segment generate the identical `xid`**. Once the `xid` is no longer unique, a radio can no longer tell its own server reply apart from a reply meant for a different unit. This is the root cause; the other two defects are what turn it into address theft.

### Defect 2: Reacting to a Foreign OFFER (Weak chaddr Validation)

DHCPv4 OFFER and REQUEST messages are broadcast, so every radio on the segment sees every OFFER. RFC 2131 section 4.4.1 requires a client to confirm that an OFFER is addressed to it, by checking that the OFFER's client hardware address (`chaddr`) and `xid` match its own DISCOVER, **before** it sends a REQUEST. The affected firmware checks the `xid` but not the `chaddr`. Because the `xid` is shared (Defect 1), a radio sees an OFFER intended for a different unit, treats it as its own, and fires off a competing REQUEST for that address. The radio that responds fastest wins the lease.

### Defect 3: Missing DHCP Option 61 (Client-Identifier)

DHCP option 61, the **client-identifier**, gives the server a stable way to tell clients apart independently of `chaddr` and `xid`. RFC 4361 and the O-RAN WG4 M-Plane specification, section 6.2.4, require the O-RU to send a stable client-identifier on every DHCPv4 message. The affected firmware sends **no option 61 at all**. With no client-identifier, the server has no second key to fall back on once the `xid` collides, and no basis to reject a REQUEST coming from the wrong unit. This removes the last line of defence.

### The Result: IP Theft and Duplicate Active Leases

Combined, these three defects produce **IP address theft and duplicate active leases**. A real boot sequence captured in the bug report shows radio `ad:c8` sending a REQUEST for address `.172` only 91 ms after the server OFFERed it to radio `ad:a8`, while the legitimate owner `ad:a8` took 125 ms and lost. The fast unit `ad:c8` ends up holding two leases (`.171` and `.172`), the legitimate owner is NAK'd off its own address, and a third unit obtains nothing from its assigned pool. The operational consequences are direct: radios that cannot get an IPv4 address cannot complete NETCONF call-home or M-Plane connectivity over IPv4, and the server's lease table no longer reflects which radio is actually using which address.

## Why DHCPv6 Is Unaffected

The same radios run **DHCPv6 correctly**. DHCPv6 identifies clients by a unique **DUID** (DHCP Unique Identifier) and **IAID** (Identity Association Identifier) carried inside the message body, rather than relying on the Ethernet source address or a shared transaction ID. Each unit presents a distinct DUID and IAID, so the server keys leases on identity rather than on a colliding `xid`. In testing, every O-RU obtained a correct, unique IPv6 lease with no duplication or cross-contamination. The defect is therefore strictly a **DHCPv4** problem, and the toolkit treats DHCPv6 traffic it finds as healthy evidence rather than as a fault.

## A Note on the Captured Evidence

This section documents an honest limitation you should understand before you trust any example output in this manual. The finding is recorded in full in `docs/ANALYSIS.md`.

The packet capture originally supplied with the bug report, shipped as `samples/oru_real_capture.pcap`, **does not contain the DHCPv4 defect**, because it does not contain any DHCPv4 traffic. That file is the **O-RU's own fronthaul capture**: 555 frames dominated by PTP (IEEE 1588) precision-time traffic, with a handful of slow-protocol and IPv6 frames, and exactly **one** DHCP message of any kind, a healthy DHCPv6 RENEW on VLAN 201. There are **zero** DHCPv4 DISCOVER, OFFER, REQUEST, ACK, or NAK packets in it. The server-side capture named `dhcpv4_debug.pcap` in the bug report, where the real shared-`xid` evidence lives, was never part of the upload. The shared-`xid` behaviour is a phenomenon you only see from the **server** during a simultaneous multi-unit boot, not from a single radio's steady-state fronthaul interface.

The toolkit handles this truthfully. When you run `dhcp-forensics` on a capture that contains no DHCPv4 traffic, it does not invent a defect. It reports the honest result:

```
Note        : capture contains no DHCPv4 traffic; DHCPv4 defect cannot be observed in this file
Verdict     : NO DHCPv4 TRAFFIC
```

On the real fronthaul capture the verdict is `NO DHCPv4 TRAFFIC`, the findings count is zero, and the command exits **0**:

```
$ PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli samples/oru_real_capture.pcap --no-color
...
VERDICT: NO DHCPv4 TRAFFIC   (HIGH=0, MEDIUM=0, LOW=0, INFO=0)
```

So that you can still see the analyzer detect the defect, the repository ships a **synthesized fixture**, `tests/fixtures/oru_xid_reuse.pcap`. It is reconstructed directly from the two transaction sequences documented in the bug report (`xid 0x8fc37a94` and `xid 0xcb07f611`), including the exact MAC addresses, timestamps, offered IPs, ACK and NAK outcomes, the option 60 vendor class, and the deliberate absence of option 61. It is a faithful, deterministic stand-in for the missing `dhcpv4_debug.pcap`, and the manual labels it as such everywhere it is used. It is **not** a real capture.

Run against that fixture, `dhcp-forensics` flags all three defects, reports `10` HIGH findings across the categories `SHARED_XID`, `FOREIGN_OFFER_REACTION`, `MISSING_CLIENT_ID`, `DUPLICATE_GRANT_IP`, and `DUPLICATE_GRANT_MAC`, returns the verdict `AFFECTED`, and exits **2**:

```
$ PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli tests/fixtures/oru_xid_reuse.pcap --no-color
...
VERDICT: AFFECTED   (HIGH=10, MEDIUM=0, LOW=0, INFO=0)
```

The exit codes are part of the tool's contract and are convenient in scripts: `dhcp-forensics` exits **2** when any HIGH finding is present and **0** otherwise.

## What This Means for the Rest of the Manual

Keep two facts in mind as you read on. First, the toolkit reports only what is in the capture or lease file you give it: a capture with no DHCPv4 traffic yields `NO DHCPv4 TRAFFIC`, not a false alarm. Second, to reproduce the `AFFECTED` verdict shown throughout this manual, you must point the tools at a capture that actually contains the contended DHCPv4 exchange, either the shipped fixture `tests/fixtures/oru_xid_reuse.pcap` or your own server-side capture taken with `tcpdump -e` on the DHCP server interface during a multi-unit boot. The chapters on `dhcp-lease-list` and `dhcp-forensics` show you how to gather that evidence and read every field of the report.

[[PAGEBREAK]]

# Installation and Upgrade

This chapter explains how to install, verify, upgrade, and remove the DHCP O-RU Toolkit, version 2.1.0. The toolkit ships two command-line tools, `dhcp-lease-list` and `dhcp-forensics`, both implemented in pure Python. Choose the Debian package for production servers, or a source install for development and ad-hoc use. Every command, path, and output shown below is taken directly from the version 2.1.0 sources and from running the tools.

## Requirements

The toolkit is intentionally **zero-dependency**. All pcap reading and all DHCPv4/DHCPv6 parsing are done with the Python standard library only.

- **Python 3.8 or newer.** The project metadata sets `requires-python = ">=3.8"`, and the Debian package declares `Depends: python3 (>= 3.8)`.
- **No third-party Python packages.** The `pyproject.toml` declares `dependencies = []`. You do not need `pip` to install anything beyond the toolkit itself.
- **No external capture tooling.** There is no dependency on `scapy`, `dpkt`, `tshark`, or `tcpdump`. If those tools are absent, the toolkit still works.
- **Operating system.** Linux (POSIX). The package is architecture-independent (`Architecture: all`); it contains no compiled code.

The only optional extra is the `test` group (`pytest`), used solely to run the bundled test suite. It is never required to use the tools.

## Installing from the Debian Package

This is the recommended method for a DHCP server. The package details, taken from `packaging/debian/control`, are:

| Field | Value |
| --- | --- |
| Package | `dhcp-oru-toolkit` |
| Version | `2.1.0` |
| Architecture | `all` |
| Section | `net` |
| Priority | `optional` |
| Depends | `python3 (>= 3.8)` |
| Maintainer | `labuser <labuser@dhcp-server>` |

The built artifact is named `dhcp-oru-toolkit_2.1.0_all.deb` and is produced into the `dist/` directory.

### Install the Package

From the directory that contains the `.deb` file (for example the repository's `dist/`), run the following.

```
sudo dpkg -i dist/dhcp-oru-toolkit_2.1.0_all.deb
```

If `dpkg` reports unmet dependencies (only `python3` could ever be missing), resolve them with the following.

```
sudo apt-get install -f
```

On a successful configure step, the `postinst` script prints a short confirmation.

```
dhcp-oru-toolkit 2.1.0 installed.
  dhcp-lease-list -> /usr/local/sbin/dhcp-lease-list
  dhcp-forensics  -> /usr/local/sbin/dhcp-forensics
```

### What the Package Installs

The package lays down the Python package, two thin wrapper commands, the man pages, and the standard documentation. The actual contents of the `.deb` are:

| Installed path | Purpose |
| --- | --- |
| `/usr/local/lib/dhcp-oru-toolkit/dhcp_toolkit/` | The `dhcp_toolkit` Python package (leases and forensics modules) |
| `/usr/local/sbin/dhcp-lease-list` | Wrapper command for the lease viewer |
| `/usr/local/sbin/dhcp-forensics` | Wrapper command for the pcap forensics analyzer |
| `/usr/share/man/man8/dhcp-lease-list.8.gz` | Manual page, section 8 |
| `/usr/share/man/man8/dhcp-forensics.8.gz` | Manual page, section 8 |
| `/usr/share/doc/dhcp-oru-toolkit/copyright` | MIT license / copyright file |
| `/usr/share/doc/dhcp-oru-toolkit/changelog.gz` | Debian changelog |

Each command in `/usr/local/sbin` is a small `sh` wrapper that sets `PYTHONPATH` to the install library directory and runs the matching module with `python3`. For example, `dhcp-lease-list` runs `python3 -m dhcp_toolkit.leases.cli` and `dhcp-forensics` runs `python3 -m dhcp_toolkit.forensics.cli`, each forwarding all arguments.

### Coexisting with a Distribution dhcp-lease-list

If a foreign `dhcp-lease-list` binary already exists at `/usr/local/sbin/dhcp-lease-list` when you install, the `postinst` script preserves it once as `/usr/local/sbin/dhcp-lease-list.distrib` before the toolkit's wrapper takes that name. It only backs up a binary that does not already belong to this toolkit, so re-running configure never clobbers the toolkit's own wrapper. The backup is restored automatically on removal (see Uninstalling).

## Installing from Source

Use this method for development or when you cannot install a system package. The two tools are exposed through the `[project.scripts]` entries `dhcp-lease-list = "dhcp_toolkit.leases.cli:main"` and `dhcp-forensics = "dhcp_toolkit.forensics.cli:main"`.

### With pip and the Bundled pyproject

From the repository root, a normal install builds and installs the package and places both commands on your `PATH`.

```
pip install .
```

For development, install in editable mode so that edits under `src/` take effect immediately.

```
pip install -e .
```

To also pull in the optional test dependency, install the `test` extra.

```
pip install -e ".[test]"
```

### Running Straight from the Source Tree

You do not have to install anything to run the tools. Because the code is pure standard library, you can run it in place by pointing `PYTHONPATH` at the `src/` directory and invoking the module.

```
PYTHONPATH=src python3 -m dhcp_toolkit.leases.cli --help
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli --help
```

This is exactly how the bundled `Makefile` runs the tools (it sets `export PYTHONPATH := src`), and it is the form used by the `make demo` and `make test` targets.

## Building the .deb Yourself

You can build the Debian package from a checkout. The build uses plain `dpkg-deb` and requires no `debhelper`. The simplest path is the `Makefile` target, which calls the build script for you.

```
make deb
```

That target runs `bash packaging/debian/build-deb.sh`, which you may also call directly from the repository root.

```
bash packaging/debian/build-deb.sh
```

The script stages the tree under `build/deb/`, copies the `dhcp_toolkit` package (stripping any `__pycache__` directories and `.pyc`/`.pyo` files), writes the two `sh` wrappers, installs the `control`, `postinst`, and `prerm` files, gzips the changelog and both man pages, sets ownership to `root` via `--root-owner-group`, and finally builds the archive. The result is written to the following path and the script prints both `dpkg-deb --info` and `dpkg-deb --contents` for the archive.

```
dist/dhcp-oru-toolkit_2.1.0_all.deb
```

The script requires a checkout that contains `src/dhcp_toolkit`; it exits with an error if that directory is missing.

## Verifying the Install

After installing (by any method), confirm the tools are present and report the expected version.

### Check the Lease Viewer

The `dhcp-lease-list` command supports `--version` and prints the program name and version.

```
$ dhcp-lease-list --version
dhcp-lease-list 2.1.0
```

Its help text confirms the available options.

```
$ dhcp-lease-list --help
usage: dhcp-lease-list [-h] [--version] [--server {auto,isc,kea,both}]
                       [--v4-lease V4_LEASE] [--v6-lease V6_LEASE]
                       [--kea-config-dir KEA_CONFIG_DIR] [--all]
                       [--state {active,free,expired,declined,released}]
                       [--v4-only] [--v6-only] [--conflicts]

Unified DHCP lease viewer for ISC and Kea DHCP v2.1.0
```

### Check the Forensics Analyzer

The `dhcp-forensics` command does not have a `--version` flag. It requires a `PCAP` argument, and it prints the toolkit version in its report header. Use `--help` to confirm it is installed and to see its options.

```
$ dhcp-forensics --help
usage: dhcp-forensics [-h] [--json] [--leases FILE] [--config FILE]
                      [--no-color]
                      PCAP

Analyze a pcap for the O-RU shared-xid DHCPv4 defect.
```

When you run it against a capture, the report banner reflects the version.

```
==============================================================================
DHCP-ORU FORENSIC REPORT  (toolkit v2.1.0)
==============================================================================
```

### Confirm Exit Codes

Both tools use exit codes to signal findings, which is useful in scripts and monitoring. When invoked through the installed wrappers (or via `python3 -m ...`), the codes are:

- `dhcp-lease-list --conflicts` returns `2` when at least one HIGH-severity conflict is found, otherwise `0`.
- `dhcp-forensics` returns `2` when the verdict is AFFECTED (any HIGH finding), otherwise `0`.

### Check the Man Pages

The package installs both manual pages in section 8.

```
man 8 dhcp-lease-list
man 8 dhcp-forensics
```

If `man` does not find them immediately after install, run `sudo mandb` to refresh the manual database.

## Upgrading from Version 1.3.0

Version 2.0.0 is a significant change from the old 1.3.0 release. Read this section before upgrading on a server that already runs the legacy tool.

**The package and the deliverable were renamed.** In 1.x the package was named `dhcp-lease-list`. In 2.0.0 it is named `dhcp-oru-toolkit`. The old single-file lease viewer (`dhcp_lease_list_v1.3.0.py`) has been refactored into the pure-stdlib `dhcp_toolkit` Python package and is superseded. The command `dhcp-lease-list` still exists and keeps its 1.3.0 argument interface (`--server`, `--v4-lease`, `--v6-lease`, `--all`, `--state`, `--v4-only`, `--v6-only`, `--version`), and 2.0.0 adds a new `--conflicts` mode plus an entirely new second tool, `dhcp-forensics`.

**Packaging was corrected.** The 1.x maintainer scripts backed up `/usr/sbin` while installing into `/usr/local/sbin`; the 2.0.0 `postinst` and `prerm` now back up and restore the same path they install into (`/usr/local/sbin`). The questionable `Replaces: isc-dhcp-server` control field from earlier packaging was dropped, so the new package no longer claims to replace the ISC server.

Because the package name changed, the new package does not automatically replace the old one. Remove the legacy `dhcp-lease-list` 1.3.0 package first, then install the new package.

```
sudo dpkg -r dhcp-lease-list
sudo dpkg -i dist/dhcp-oru-toolkit_2.1.0_all.deb
```

After upgrading, re-run the verification steps above to confirm that `dhcp-lease-list --version` reports `2.1.0` and that `dhcp-forensics --help` succeeds.

## Uninstalling

Remove the package with `dpkg -r`, using the new package name.

```
sudo dpkg -r dhcp-oru-toolkit
```

During removal the `prerm` script runs in its `remove`/`deconfigure` case. If a foreign binary was preserved at install time as `/usr/local/sbin/dhcp-lease-list.distrib`, the script restores it back to `/usr/local/sbin/dhcp-lease-list` and prints a confirmation.

```
Restored original /usr/local/sbin/dhcp-lease-list
```

To remove the package together with its documentation directory, use `dpkg --purge` (`-P`) instead.

```
sudo dpkg -P dhcp-oru-toolkit
```

If you installed from source with `pip` rather than from the Debian package, uninstall through `pip` using the project name.

```
pip uninstall dhcp-oru-toolkit
```

A source-tree run started with `PYTHONPATH=src` installs nothing, so there is nothing to uninstall in that case; simply stop invoking it or delete the checkout.

[[PAGEBREAK]]

# Command Reference: dhcp-lease-list

The `dhcp-lease-list` command is the unified lease viewer in the DHCP O-RU Toolkit version 2.1.0. It reads lease files from either an ISC DHCP server or a Kea DHCP server, normalizes IPv4 and IPv6 leases into a single tabular view, and can optionally scan the parsed leases for the MAC/IP conflicts that are the lease-table fingerprint of the O-RU shared-transaction-ID defect.

This chapter is the complete reference for the command. Every flag documented here is taken directly from the command's argument parser, and every example shows output captured from a real run against the toolkit's bundled fixtures.

## Synopsis

The package is invoked through its source tree. If the toolkit is installed as a console script, the program name is `dhcp-lease-list`; the underlying entry point is `dhcp_toolkit.leases.cli:main`.

```
dhcp-lease-list [-h] [--version] [--server {auto,isc,kea,both}]
                [--v4-lease V4_LEASE] [--v6-lease V6_LEASE]
                [--kea-config-dir KEA_CONFIG_DIR] [--all]
                [--state {active,free,expired,declined,released}]
                [--v4-only] [--v6-only] [--conflicts]
```

The command takes no positional arguments. All input is selected through the options below.

## Flags

The following table lists every flag accepted by `dhcp-lease-list`. The `Argument` column shows the value the flag expects; flags marked as a switch take no value.

| Flag | Argument | Default | Description |
| --- | --- | --- | --- |
| `-h`, `--help` | none | n/a | Show the usage message and exit. |
| `--version` | none | n/a | Print the program name and version (`dhcp-lease-list 2.1.0`) and exit. |
| `--server` | `auto`, `isc`, `kea`, or `both` | `auto` | Select the DHCP server type. `auto` detects what is installed, `both` reports each server in its own section, and `isc`/`kea` force a single server. This choice also picks the lease-file paths and the parser used. |
| `--v4-lease` | path | resolved from `--server` | Path to the IPv4 lease file. When omitted, the path for the selected server is used. |
| `--v6-lease` | path | resolved from `--server` | Path to the IPv6 lease file. When omitted, the path for the selected server is used. |
| `--kea-config-dir` | path | `/etc/kea`, then `/usr/local/etc/kea` | Directory holding `kea-dhcp4.conf` and `kea-dhcp6.conf`. Use it when the Kea config lives outside the standard locations. |
| `--all` | none (switch) | off | Show all leases, including expired active leases and free leases. Without this flag, active leases whose expiry is in the past are hidden. |
| `--state` | one of `active`, `free`, `expired`, `declined`, `released` | unset (no state filter) | Restrict the listing to a single binding state. |
| `--v4-only` | none (switch) | off | Show IPv4 leases only; skip the IPv6 file entirely. |
| `--v6-only` | none (switch) | off | Show IPv6 leases only; skip the IPv4 file entirely. |
| `--conflicts` | none (switch) | off | After listing, scan the parsed leases for MAC/IP conflicts and print a conflict section. Exit code 2 if any HIGH-severity conflict is found. |

A note on `--v4-only` and `--v6-only`: these flags are independent switches, not mutually exclusive choices. Internally, IPv4 output is shown whenever `--v6-only` is not set, and IPv6 output is shown whenever `--v4-only` is not set. Passing neither shows both families; passing both suppresses both listings.

## Default Lease-File Locations

When you omit `--v4-lease` or `--v6-lease`, the command works out the path itself.

| Server (`--server`) | IPv4 lease file | IPv6 lease file |
| --- | --- | --- |
| `isc` | `/var/lib/dhcp/dhcpd.leases` | `/var/lib/dhcp/dhcpd6.leases` |
| `kea` | from the Kea config (see below) | from the Kea config (see below) |

For ISC these are fixed conventional locations. For Kea the path is **read from the server's own configuration** - the `name` entry of the `lease-database` block in `kea-dhcp4.conf` / `kea-dhcp6.conf` - because that path is site-configurable and frequently is not the compiled-in default. Kea's configuration is JSON with extensions, and the toolkit handles the whole dialect: `//`, `#` and `/* */` comments and `<?include "file"?>` directives are pre-processed before parsing. If no config can be found or parsed, the command falls back to Kea's own defaults, `/var/lib/kea/kea-leases4.csv` and `/var/lib/kea/kea-leases6.csv`, and says so.

The `--server` value also determines which parser is applied. ISC files are parsed as text `lease`/`ia-na` blocks; Kea files are parsed as CSV. You do **not** have to match `--server` to the file format by hand: under the default `--server auto`, a file you name with `--v4-lease`/`--v6-lease` has its format sniffed and the matching parser chosen. Forcing the wrong pairing explicitly (`--server isc` against a Kea CSV) still misparses, as before.

If a lease file does not exist, the command prints a yellow `[WARN]` line and treats that family as having zero leases rather than aborting. If a file exists but cannot be read, it prints a red `[ERROR] Permission denied` line (suggesting `sudo`) and likewise continues with zero leases for that family.

## Choosing the Server

`--server` defaults to `auto`, so a bare `dhcp-lease-list` produces a useful listing on an ISC host, a Kea host, or a host running both. Detection works in this order:

1. If `--v4-lease` or `--v6-lease` names a file, that file's format is sniffed - a Kea CSV header row, or ISC `lease` / `ia-na` blocks - and the matching parser is selected.
1. Otherwise ISC is reported when its lease files are present, and Kea is reported when a Kea config or lease file is present. A host running both DHCP servers gets a section for each, headed `--- ISC DHCP ---` and `--- Kea DHCP ---`.
1. If neither server is found, ISC is assumed, which reproduces the behaviour of earlier releases on a host with nothing installed.

Pass `--server isc` or `--server kea` to force one server, or `--server both` to report both regardless of what detection would have concluded.

## Reading Kea Lease Databases

Kea keeps leases differently enough from ISC that a few of its behaviours are worth knowing when you read a listing.

**Lease File Cleanup generations.** Kea's LFC does not rewrite the lease file in place. It moves the current file aside and consolidates the old generations through `<name>.1`, `<name>.2` and `<name>.completed`. While a cleanup is in flight - or indefinitely, if LFC was interrupted by a crash or a power cut - most of the leases live in those files and the primary file holds only what has been written since. The command reads them alongside the primary file, in the same order Kea itself reloads them, and prints a `[NOTE]` line naming each generation it included. Reading only the primary file, as earlier releases did, could report a fraction of a healthy server's leases, or none at all.

**Journal semantics.** The Kea lease file is a journal: every lease update appends a row. It is replayed the way Kea replays it, so the **last** row for an address is authoritative and a row whose `valid_lifetime` is `0` marks the lease deleted and removes the address from the listing. Released, declined and reclaimed addresses are therefore reported in their true state rather than being displayed as still held.

**MAC addresses.** Kea fills the `hwaddr` column only when it could derive a link-layer address from the exchange, and leaves it empty otherwise - for a relayed exchange, for instance. Where it is empty the MAC is recovered from the DHCPv6 DUID (DUID-LLT, DUID-LL, and the O-RAN ASCII DUID-EN), exactly as the ISC DHCPv6 parser does, and for DHCPv4 from the option 61 client-identifier in either its RFC 2132 or RFC 4361 form. O-RUs stay identifiable by MAC on either server.

**Non-file lease backends.** Kea can store leases in MySQL or PostgreSQL instead of a `memfile`, and a `memfile` can be configured with `"persist": false` so that leases are never written to disk at all. In those cases there is no lease file to read. The command reports the backend it found and why the listing is empty, for example:

```
--- Kea DHCP ---
[NOTE] Kea DHCPv6 uses the 'mysql' lease backend, not memfile; there is no CSV lease file to read (query the database, or use kea-shell with the lease6-get-all command)
[ DHCPv6 Leases ]  no lease file to read
```

Nothing is parsed for that family, and no `[WARN] lease file not found` is printed for a file that was never meant to exist.

**Timestamps.** Kea records lease expiry as a Unix epoch; it is rendered in UTC, matching the ISC lease files and the `Expires (UTC)` column heading. Expiry is evaluated against UTC as well, so the same lease is judged the same way on a server in any time zone.

## Output Format

For each address family that is shown, the command prints a section header followed by a fixed-column lease table. The header line reports the source file, the total number of leases parsed, and the number that are currently active and not expired, for example:

```
[ DHCPv4 Leases ]  file: /var/lib/dhcp/dhcpd.leases  total: 4  active: 3
```

The lease table has six columns, in this order:

- **IP Address** - the leased IPv4 or IPv6 address.
- **MAC / DUID** - the client hardware address. For DHCPv6 on either server this is the MAC extracted from the client DUID whenever the server did not record a hardware address of its own; for Kea DHCPv4 it falls back to the option 61 client-identifier. A dash (`-`) appears when no MAC could be determined.
- **Hostname** - the client hostname, or `-` if none was recorded. ISC DHCPv6 leases always show `-` in this column.
- **State** - the binding state: `active`, `free`, `expired`, `declined`, or `released`.
- **Expires (UTC)** - the lease expiry as `YYYY/MM/DD HH:MM:SS`, or `-` if unknown. For Kea sources, the stored Unix epoch is converted to this format.
- **Vendor Class** - the vendor-class identifier for ISC DHCPv4 leases (often the O-RU model string), or `-` when not present. Kea does not record the vendor class in its lease file by default; where a deployment stores it in the lease's user context it is shown here, and otherwise Kea and IPv6 leases show `-`.

Column widths are sized to the content of the rows being printed, and rows are sorted by IP address. On an interactive terminal, the table is rendered with ANSI color (active leases in green, free/released dimmed, other states yellow). When output is captured to a file or pipe, you may wish to strip the escape sequences for clean text; the examples below show the de-colored equivalent.

Two visibility rules govern which rows appear:

1. Active leases whose expiry timestamp is in the past are hidden unless `--all` is given. Leases in other states (such as `free`, `declined`, or `released`) are listed regardless of `--all`.
1. If `--state` is set, only leases in that exact binding state are shown.

If, after filtering, a section has no rows to display, the command prints `No leases to display.` in place of the table.

## The --conflicts Scan

When you pass `--conflicts`, the command runs a conflict detector over every lease it parsed (across both families that were listed) and prints a `[ Lease Conflicts ]` section after the lease tables. Only genuinely active, non-expired leases are considered, and placeholder MAC values (`-` or empty) are ignored.

The detector recognizes exactly two kinds of conflict, both of which are reported at **HIGH** severity:

- **`mac_multiple_active_ips`** - one MAC address holds more than one distinct active IP within the same address family. This is the signature of a single O-RU that has hoarded several leases. IPv4 and IPv6 leases for the same unit are grouped separately, so a unit holding one IPv4 and one IPv6 address does not trip the detector.
- **`ip_multiple_active_macs`** - one IP address is actively claimed by more than one distinct MAC. This is the signature of two units fighting over the same address.

Each detected conflict is printed on its own line, prefixed with its severity and kind, followed by a human-readable detail string listing the offending MACs and IPs. The conflict list is sorted deterministically (by kind, then by primary MAC or IP, then by detail), so repeated runs produce stable output. If nothing is found, the section prints `No conflicts detected.`

The exit code reflects the scan result. If any HIGH-severity conflict is found, the command returns exit code 2; otherwise it returns 0. Because both conflict kinds are always HIGH, in practice any detected conflict yields exit code 2. This makes `--conflicts` suitable as a gate in monitoring scripts. Without `--conflicts`, the command does not scan and returns 0 on a normal listing.

## Exit Codes

| Exit code | Meaning |
| --- | --- |
| 0 | Success. The listing completed; with `--conflicts`, no HIGH-severity conflict was found. |
| 2 | A HIGH-severity lease conflict was found during a `--conflicts` scan. |

Note that a missing or unreadable lease file does not by itself change the exit code: the command warns and continues, and still returns 0 unless a HIGH conflict is detected. Invalid command-line usage (for example, an unknown flag or an invalid `--state` value) is rejected by the argument parser with its own usage error before the program runs.

## Worked Examples

The following examples were run against the fixtures shipped with the toolkit under `tests/fixtures/`. Color escape sequences have been removed for readability; on a terminal the same tables appear with color.

### Example 1: List ISC Leases (Both Families)

This is the default mode. It reads the ISC IPv4 and IPv6 lease files and shows active, non-expired leases.

```
dhcp-lease-list --server isc \
    --v4-lease tests/fixtures/dhcpd.leases \
    --v6-lease tests/fixtures/dhcpd6.leases
```

Captured output:

```
=== ISC DHCP Unified Lease List  v2.1.0 ===
Active leases shown. Use --all to include expired/free.

[ DHCPv4 Leases ]  file: tests/fixtures/dhcpd.leases  total: 4  active: 3
IP Address       MAC / DUID          Hostname   State    Expires (UTC)          Vendor Class
192.168.36.160   34:fe:9e:3d:af:5c   -          free     2020/01/01 00:00:00    -
192.168.36.170   34:fe:9e:3d:ad:a8   oru-ada8   active   2099/12/31 23:59:59    o-ran-ru2/FJ/44R26-N25N66-DC/A2256600363
192.168.36.171   34:fe:9e:3d:ad:c8   oru-adc8   active   2099/12/31 23:59:59    o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222
192.168.36.172   34:fe:9e:3d:ad:c8   oru-adc8   active   2099/12/31 23:59:59    o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222

[ DHCPv6 Leases ]  file: tests/fixtures/dhcpd6.leases  total: 3  active: 3
IP Address     MAC / DUID          Hostname State    Expires (UTC)          Vendor Class
fd00:36::171   34:fe:9e:3d:ad:a8   -        active   2099/12/31 23:59:59    -
fd00:36::172   34:fe:9e:3d:ad:c8   -        active   2099/12/31 23:59:59    -
fd00:36::173   34:fe:9e:3d:af:5c   -        active   2099/12/31 23:59:59    -
```

The command exits with code 0. Note that the `free` lease for `192.168.36.160` is shown even though `--all` was not given, because the visibility rule only hides expired active leases. Note also that MAC `34:fe:9e:3d:ad:c8` appears on two active IPv4 addresses (`.171` and `.172`) - a conflict that Example 3 surfaces explicitly.

### Example 2: Filter Kea Leases by State

Here the source is a Kea server, output is limited to IPv4 with `--v4-only`, and only `declined` leases are shown with `--state declined`. The IPv6 file is not read because of `--v4-only`.

```
dhcp-lease-list --server kea \
    --v4-lease tests/fixtures/kea-leases4.csv \
    --v6-lease tests/fixtures/kea-leases6.csv \
    --v4-only --state declined
```

Captured output:

```
=== Kea DHCP Unified Lease List  v2.1.0 ===
Active leases shown. Use --all to include expired/free.

--- Kea DHCP ---
[ DHCPv4 Leases ]  file: tests/fixtures/kea-leases4.csv  total: 6  active: 4
IP Address       MAC / DUID Hostname State        Expires (UTC)          Vendor Class
-------------------------------------------------------------------------------------
192.168.36.180   -   -   declined     2100/01/01 00:00:00    -
```

The command exits with code 0. The header still reports the full totals (6 parsed, 4 active) for the file, while the table is narrowed to the single `declined` lease by the `--state` filter. The MAC column shows `-` because the declined Kea entry carries neither a hardware address nor a client-identifier to recover one from.

Dropping `--state` and `--v4-only` and adding `--all` shows what the fixture exercises: an address that was bound and then released, one deleted with `valid_lifetime = 0` (absent from the listing entirely), a lease whose MAC came from its client-identifier, one whose vendor class came from its user context, and three IPv6 leases whose MACs were recovered from a DUID because Kea left the `hwaddr` column empty.

```
--- Kea DHCP ---
[ DHCPv4 Leases ]  file: tests/fixtures/kea-leases4.csv  total: 6  active: 4
IP Address       MAC / DUID          Hostname   State        Expires (UTC)          Vendor Class
------------------------------------------------------------------------------------------------
192.168.36.170   34:fe:9e:3d:ad:a8   oru-ada8   active       2100/01/01 00:00:00    -
192.168.36.171   34:fe:9e:3d:ad:c8   oru-adc8   active       2100/01/01 00:00:00    -
192.168.36.173   34:fe:9e:3d:af:5c   oru-af5c   released     2100/01/01 00:00:00    -
192.168.36.175   34:fe:9e:3d:ad:22   oru-ad22   active       2100/01/01 00:00:00    -
192.168.36.176   34:fe:9e:3d:ad:33   oru-ad33   active       2100/01/01 00:00:00    o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222
192.168.36.180   -                   -          declined     2100/01/01 00:00:00    -

[ DHCPv6 Leases ]  file: tests/fixtures/kea-leases6.csv  total: 5  active: 4
IP Address     MAC / DUID          Hostname   State        Expires (UTC)          Vendor Class
----------------------------------------------------------------------------------------------
fd00:36::171   34:fe:9e:3d:ad:a8   oru-ada8   active       2100/01/01 00:00:00    -
fd00:36::173   34:fe:9e:3d:ad:c8   oru-adc8   active       2100/01/01 00:00:00    -
fd00:36::174   34:fe:9e:3d:ad:44   -          active       2100/01/01 00:00:00    -
fd00:36::175   34:fe:9e:3d:ad:55   -          active       2100/01/01 00:00:00    -
fd00:36::180   34:fe:9e:3d:af:5c   -          declined     2100/01/01 00:00:00    -
```

### Example 3: Scan for Conflicts (Non-Zero Exit)

This run lists the ISC leases and then scans them with `--conflicts`. The shared MAC noted in Example 1 produces a HIGH-severity conflict.

```
dhcp-lease-list --server isc \
    --v4-lease tests/fixtures/dhcpd.leases \
    --v6-lease tests/fixtures/dhcpd6.leases \
    --conflicts
```

Captured conflict section (the lease tables above it are identical to Example 1):

```
[ Lease Conflicts ]
  [HIGH] mac_multiple_active_ips: MAC 34:fe:9e:3d:ad:c8 holds 2 distinct active IPv4 addresses: 192.168.36.171, 192.168.36.172
```

Because a HIGH-severity conflict was found, the command exits with code **2**. You can use this in a script to fail a health check:

```
dhcp-lease-list --server isc --v4-lease /var/lib/dhcp/dhcpd.leases --conflicts
if [ $? -eq 2 ]; then
    echo "Lease conflict detected - investigate O-RU xid reuse"
fi
```

### Example 4: A Clean Conflict Scan (Zero Exit)

Running the same scan against the Kea fixtures, where no MAC holds multiple active addresses, produces an empty conflict section and exit code 0.

```
dhcp-lease-list --server kea \
    --v4-lease tests/fixtures/kea-leases4.csv \
    --v6-lease tests/fixtures/kea-leases6.csv \
    --conflicts
```

Captured conflict section:

```
[ Lease Conflicts ]
  No conflicts detected.
```

The command exits with code 0, confirming that a `--conflicts` run only returns 2 when a HIGH-severity conflict is actually present.

## See Also

For deeper packet-level investigation of the O-RU shared transaction-ID and IP-theft behavior that produces these lease conflicts, see the chapter on the `dhcp-forensics` command.

[[PAGEBREAK]]

# Command Reference: dhcp-forensics

## Overview

`dhcp-forensics` reads a packet capture, decodes the DHCPv4 and DHCPv6 messages inside it, groups those messages into transactions, runs a fixed set of detectors, and prints a forensic report. The tool exists to find and prove the O-RU shared transaction-id DHCPv4 defect and the failures that travel with it: units reacting to address OFFERs meant for other units, missing client identifiers, spoofed source MACs, and duplicate or stolen leases.

The analyzer is pure Python standard library. It does not capture traffic itself and it does not need root; you point it at a file that already exists on disk. Captures may be classic `pcap` or minimal `pcapng`. The tool is deliberately defensive: a structurally invalid packet is skipped rather than crashing the run, and a capture that contains no DHCPv4 traffic produces an honest "nothing to see here" verdict instead of a false alarm.

This chapter is the complete reference for the command in toolkit version 2.1.0. The toolkit ships two commands, `dhcp-lease-list` and `dhcp-forensics`; this chapter covers only the latter.

## Synopsis

```
dhcp-forensics PCAP [--json] [--leases FILE] [--config FILE] [--no-color]
```

You can confirm the surface of the command at any time by running its help:

```
dhcp-forensics --help
```

which prints:

```
usage: dhcp-forensics [-h] [--json] [--leases FILE] [--config FILE]
                      [--no-color]
                      PCAP

Analyze a pcap for the O-RU shared-xid DHCPv4 defect.

positional arguments:
  PCAP           capture file (classic pcap or minimal pcapng)

options:
  -h, --help     show this help message and exit
  --json         print the report as JSON instead of text
  --leases FILE  also parse this lease file and fold conflicts in
  --config FILE  ISC dhcpd config to note configured pools
  --no-color     disable ANSI colour in text output
```

## Arguments and Flags

The command takes exactly one positional argument, the capture file, plus four optional flags. There are no other flags; do not assume one exists unless it appears in the table below.

| Argument or flag | Type | Default | Behavior |
| --- | --- | --- | --- |
| `PCAP` | positional, required | none | Path to the capture file to analyze. Accepts classic pcap or minimal pcapng. If the file is missing the tool prints `error: pcap not found` to stderr and exits 2. If the file cannot be read or parsed it prints `error: failed to read pcap` and exits 2. |
| `--json` | switch | off | Emit the full report as a JSON document on stdout instead of the human-readable text report. |
| `--leases FILE` | string | none | Also parse this lease file, detect lease conflicts in it, and fold any conflicts into the findings list as extra findings tagged `LEASE_*`. The format is auto-detected across ISC and Kea, v4 and v6. |
| `--config FILE` | string | none | Read this ISC dhcpd config and record its `subnet`, `range`, and `range6` lines as configured-pool notes in the report metadata. This is informational only and never raises a finding. |
| `--no-color` | switch | off (color on) | Disable ANSI color escape codes in the text report. Use this when writing to a file, a pager, or a log collector. The flag has no effect on `--json`, which is never colored. |

The `--leases` and `--config` inputs are best-effort. If a lease file cannot be parsed, or yields no conflicts, no extra findings are added and the run continues normally. If the config file cannot be opened, the pool notes are simply omitted.

## Exit Codes

The exit code is a machine-readable verdict, suitable for a CI gate or a shell `if`.

| Exit code | Meaning |
| --- | --- |
| 0 | The run completed and there is no HIGH-severity finding. This covers both a clean DHCPv4 capture and a capture with no DHCPv4 traffic at all. |
| 2 | At least one HIGH-severity finding was raised, or the capture file could not be found or read. |

The HIGH test is exact: the tool counts findings by severity and returns 2 only when the HIGH count is greater than zero. MEDIUM, LOW, and INFO findings are reported but do not by themselves change the exit code from 0.

## How a Capture Is Analyzed

Understanding the pipeline makes the report easy to read. The tool runs these steps in order:

1. Read the capture into a flat list of frames, recording timestamp, Ethernet source and destination, ethertype, VLAN, and the UDP payload.
1. Decode each UDP payload on ports 67/68 as DHCPv4 (BOOTP per RFC 2131, options per RFC 2132) and each payload on ports 546/547 as DHCPv6 (RFC 8415). Anything that does not decode is silently ignored.
1. Group decoded messages into transactions. DHCPv4 messages are keyed by their 32-bit transaction id (`xid`); DHCPv6 messages by their 24-bit transaction id. A transaction keeps its packets in time order and rolls up the distinct client hardware addresses, Ethernet sources, and offered or requested IPs it saw.
1. Run every detector against the transactions and concatenate the findings.
1. If `--leases` was given, append any lease-file conflicts as findings.
1. Summarize the capture, assemble the report, and print it as text or JSON.

A transaction is the unit of evidence. Because the detectors key on `xid`, a single shared `xid` collects the DISCOVER, OFFER, REQUEST, ACK, and NAK traffic of several distinct units into one transaction, which is exactly what makes the defect visible.

## Detectors

The analyzer runs five detectors. Each turns a specific pattern in the transactions into a `Finding` with a precise per-packet evidence trail and the standard it violates. A detector only fires when there is concrete evidence; a well-formed exchange produces no findings.

| Detector | What it finds | Severity | Standard cited |
| --- | --- | --- | --- |
| `detect_shared_xid` | One DHCPv4 transaction id used by two or more distinct client hardware addresses. The shared `xid` is the root defect: it lets each unit react to broadcast OFFERs meant for others. | HIGH | RFC 2131 section 4.1 |
| `detect_foreign_offer_reaction` | A unit sends a REQUEST for an address that was OFFERed to a different chaddr, or sends a REQUEST in a transaction whose DISCOVER came from another unit. The client failed to verify the OFFER was addressed to it. | HIGH | RFC 2131 section 4.4.1 |
| `detect_missing_client_id` | A client-originated DHCPv4 message (DISCOVER, REQUEST, DECLINE, RELEASE, INFORM, or any BOOTREQUEST) carries no option 61 client identifier. Reported once per offending unit. Server replies legitimately omit option 61 and are never flagged. | HIGH | RFC 4361 and O-RAN.WG4.MP section 6.2.4 |
| `detect_chaddr_ethsrc_mismatch` | A client-originated DHCPv4 frame whose Ethernet source MAC does not match the BOOTP chaddr field, indicating spoofing or relaying that hides which unit actually sent the frame. Server frames (OFFER, ACK, NAK) are excluded because they carry the server MAC. | MEDIUM | RFC 2131 section 4.4.1 |
| `detect_duplicate_grants` | IP theft and duplicate leases, scoped strictly to a single shared-xid transaction. It reports one IP requested by two or more distinct chaddrs inside the same shared-xid transaction (`DUPLICATE_GRANT_IP`), and one chaddr that won ACKs for two or more distinct IPs via shared-xid contention (`DUPLICATE_GRANT_MAC`). | HIGH | RFC 2131 section 4.1 and RFC 2131 section 4.4.1 |

A note on the scoping of the last detector. Duplicate-grant detection never aggregates across independent transactions with different `xid` values, because that would mistake ordinary sequential lease churn, such as one address being reassigned to a new MAC later, for theft. Contention is only counted inside a transaction whose `xid` is genuinely shared by two or more units, which is precisely the documented O-RU collision.

When `--leases` is supplied, lease-file conflicts are appended as additional findings with ids of the form `LEASE_<KIND>`, category `lease-conflict`, and the standard RFC 2131 section 4.3.1. Their severity comes from the conflict itself and defaults to MEDIUM.

## The Text Report

The default text report mirrors the structure of the original defect report and is organized into clearly ruled sections. The header shows the toolkit version, the source pcap path, an optional honest note, and the verdict. The verdict is colored unless `--no-color` is set: red for AFFECTED, green for CLEAN, yellow otherwise.

### Capture Summary

This section is a histogram of the whole file, independent of DHCP decoding. It reports the total frame count, the number of decoded DHCPv4 and DHCPv6 messages, the ethertype distribution, and the VLAN distribution (where `none` means untagged). Use it as a sanity check: if DHCPv4 msgs is 0, no DHCPv4 defect can possibly be present in this file.

### Transactions

Each transaction is printed as a timeline. The heading gives the transaction key, the DHCP version, and the packet count, followed by the distinct client identities (`macs` for v4, `duids` for v6) and the offered addresses. Below that is a per-packet table. For DHCPv4 the columns are time, Ethernet source, chaddr, message type, and IP; for DHCPv6 they are time, Ethernet source, message type, and addresses. Timestamps are rendered as `HH:MM:SS.mmm` in UTC so they are stable across hosts.

### Findings

Findings are grouped by severity in the order HIGH, MEDIUM, LOW, INFO. Each finding prints its id and title, a wrapped description, the standards it cites, a suggested fix, and an indented `evidence:` list. Every evidence line is a real packet rendered as `ts=... eth_src=... chaddr=... type=... ip=...`, often with a trailing `<-` clause that names the exact reason the packet is suspect. If there are no findings, this section prints `No issues detected.` in green.

A `STANDARDS VIOLATIONS` table follows, listing each distinct (severity, standard, finding-id) triple, sorted by severity. The report closes with a verdict footer that repeats the verdict and the per-severity counts.

### AFFECTED Versus Not Affected

The verdict is computed from the findings and the capture, and it takes exactly one of three values:

- **AFFECTED** means at least one HIGH-severity finding was raised. The defect is proven in this capture and the exit code is 2.
- **CLEAN** means DHCPv4 traffic was present but no HIGH finding was raised. The exchange was well-formed; exit code 0.
- **NO DHCPv4 TRAFFIC** means the capture contained no decodable DHCPv4 messages at all, so the DHCPv4 defect cannot be observed in this file. This is the honest result, not a pass; exit code 0. When this verdict is reached, the report also carries an explanatory `Note` line.

## JSON Output

With `--json`, the tool prints one JSON object on stdout (indented, key order preserved) and nothing else. The object has these top-level keys:

| Key | Type | Contents |
| --- | --- | --- |
| `version` | string | The report format version, `2.0.0`. |
| `generated_meta` | object | Run metadata: always `pcap` and `tool`; plus `leases` and `config` when those flags are used, `config_pools` when the config yielded pool lines, and `note` when the capture has no DHCPv4 traffic. |
| `capture` | object | The capture summary: `total`, `ethertypes`, `dhcpv4`, `dhcpv6`, `vlans`. |
| `transactions` | array | One object per transaction, each with `key`, `version`, `xid`, `packet_count`, `macs`, `eth_srcs`, `offered_ips`, `requested_ips`, and a `timeline` array of per-packet rows. |
| `findings` | array | One object per finding, each with `id`, `title`, `severity`, `category`, `description`, `evidence`, `standards`, and `recommendation`. |
| `severity_counts` | object | Counts keyed `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `verdict` | string | `AFFECTED`, `CLEAN`, or `NO DHCPv4 TRAFFIC`. |

A DHCPv4 timeline row contains `ts`, `eth_src`, `eth_dst`, `type`, `chaddr`, `ciaddr`, `yiaddr`, `requested_ip`, `client_id` (hex or null), and `vendor_class`. A DHCPv6 row substitutes `transaction_id`, `client_duid`, and `addresses` for the v4-specific fields. Reading the verdict and `severity_counts.HIGH` is the simplest programmatic check; both align with the exit code.

## Worked Example A: An Affected Capture

This example uses the bundled fixture that reproduces the shared-xid defect. The `--no-color` flag keeps the output clean for the page.

```
dhcp-forensics tests/fixtures/oru_xid_reuse.pcap --no-color
```

The capture holds 14 DHCPv4 frames on VLAN 201, grouped into two transactions. In the first, `xid 0x8fc37a94`, the server OFFERs `192.168.36.171` to unit `...ad:c8`, that unit wins the ACK, and then a second unit `...af:5c` reaches in and REQUESTs the same address (and is NAKed). The second transaction, `xid 0xcb07f611`, shows three units racing for one offered `192.168.36.172`. The transaction timelines are printed in full; the header and findings are shown trimmed below.

```
==============================================================================
DHCP-ORU FORENSIC REPORT  (toolkit v2.1.0)
==============================================================================
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

FINDINGS (10)
------------------------------------------------------------------------------
== HIGH (10) ==
  [SHARED_XID] Shared DHCPv4 transaction-id across multiple units
    DHCPv4 transaction-id 0x8fc37a94 is shared by 2 distinct client hardware
    addresses (34:fe:9e:3d:ad:c8, 34:fe:9e:3d:af:5c). ...
    standards: RFC 2131 section 4.1
    evidence:
      - ts=13:45:04.990 eth_src=34:fe:9e:3d:af:5c chaddr=34:fe:9e:3d:af:5c type=REQUEST ip=192.168.36.171
  [FOREIGN_OFFER_REACTION] Unit reacted to a DHCPv4 OFFER addressed to another unit
    ...
    evidence:
      - ts=13:45:04.990 ... type=REQUEST ip=192.168.36.171  <- REQUEST from 34:fe:9e:3d:af:5c but DISCOVER was sent by 34:fe:9e:3d:ad:c8
  [DUPLICATE_GRANT_IP] Single IP contested by multiple units (IP theft)
    IP address 192.168.36.171 was requested by 2 distinct hardware addresses
    (34:fe:9e:3d:ad:c8, 34:fe:9e:3d:af:5c) within the same DHCPv4 transaction
    (shared xid 0x8fc37a94) ...
  [DUPLICATE_GRANT_MAC] Single unit granted multiple DHCPv4 leases
    Hardware address 34:fe:9e:3d:ad:c8 was granted 2 distinct IP addresses
    (192.168.36.171, 192.168.36.172) ...

STANDARDS VIOLATIONS
------------------------------------------------------------------------------
  severity   standard                      finding
  ----------------------------------------------------------------------
  HIGH       O-RAN.WG4.MP section 6.2.4    MISSING_CLIENT_ID
  HIGH       RFC 2131 section 4.1          SHARED_XID
  HIGH       RFC 2131 section 4.4.1        FOREIGN_OFFER_REACTION
  HIGH       RFC 4361                      MISSING_CLIENT_ID

==============================================================================
VERDICT: AFFECTED   (HIGH=10, MEDIUM=0, LOW=0, INFO=0)
==============================================================================
```

All five HIGH-raising detectors fire on this file, for a total of 10 findings: two `SHARED_XID`, two `FOREIGN_OFFER_REACTION`, three `MISSING_CLIENT_ID` (one per unit), two `DUPLICATE_GRANT_IP`, and one `DUPLICATE_GRANT_MAC`. The verdict is AFFECTED and the process exits 2. Note how the `DUPLICATE_GRANT_MAC` finding ties the two transactions together: unit `...ad:c8` won an ACK in each, so it ended up holding two leases through the collision.

## Worked Example B: A Capture with No DHCPv4

This example uses the real-world sample capture, which contains O-RAN fronthaul and control traffic but no DHCPv4 exchange. It demonstrates the honest verdict.

```
dhcp-forensics samples/oru_real_capture.pcap --no-color
```

```
==============================================================================
DHCP-ORU FORENSIC REPORT  (toolkit v2.1.0)
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

The file is mostly PTP (ethertype `0x88f7`) with a single DHCPv6 RENEW. Because there is no DHCPv4 to analyze, the tool refuses to invent a result: it prints the explanatory note, reports NO DHCPv4 TRAFFIC, raises zero findings, and exits 0. This is the expected outcome whenever you point the analyzer at a capture that does not include the DHCPv4 handshake; capture the DHCP discovery phase if you need to test for the defect. For the full background on why the real capture lacks DHCPv4, see the chapter on the O-RU DHCPv4 shared-xid defect.

## Practical Notes

- To gate a pipeline on the result, run the command and branch on the exit code: exit 2 means a HIGH finding is present. You do not need to parse output to make that decision.
- For archival or log ingestion, combine `--json` with redirection. The JSON `verdict` and `severity_counts.HIGH` fields agree with the exit code and are stable to consume.
- Use `--no-color` whenever the output is not going to an interactive terminal, so ANSI escape codes do not contaminate files or logs.
- `--leases` and `--config` enrich a report but never change the core DHCPv4 verdict on their own unless a lease conflict happens to be HIGH severity. Treat them as supplementary context, not as the primary defect test.

[[PAGEBREAK]]

# Supported Input Formats

This chapter is a reference for every input file the DHCP O-RU Toolkit version 2.1.0 can read. It covers the lease files consumed by `dhcp-lease-list`, the packet captures consumed by `dhcp-forensics`, the DHCP message formats decoded inside those captures, and the rules used to extract a MAC address from a DHCPv6 DUID. Each section also states clearly what is **not** supported, so you can tell in advance whether a given file will parse.

The two commands map to two distinct input domains:

- `dhcp-lease-list` reads **server lease databases** (ISC and Kea, IPv4 and IPv6).
- `dhcp-forensics` reads **packet captures** (classic pcap and minimal pcapng) and may also fold in a lease file through its `--leases` option.

All parsers are pure standard-library Python with no third-party dependency (no scapy, dpkt, or tshark). They are written defensively: a malformed record is skipped rather than aborting the whole file.

## Lease File Inputs (dhcp-lease-list)

The `dhcp-lease-list` command reads two families of lease database, selected with `--server`:

- `--server isc` reads ISC `dhcpd` text lease files.
- `--server kea` reads Kea `memfile` CSV lease files.
- `--server auto` (the default) picks whichever is present, and `--server both` reads both.

For either server type you may point at specific files with `--v4-lease` and `--v6-lease`; under `auto` the format of a file you name is detected from its contents, so the flag does not need `--server` alongside it. If you omit those flags, the tool resolves the paths itself.

| Server | IPv4 lease file | IPv6 lease file |
| --- | --- | --- |
| isc | `/var/lib/dhcp/dhcpd.leases` | `/var/lib/dhcp/dhcpd6.leases` |
| kea | `lease-database.name` from `kea-dhcp4.conf` | `lease-database.name` from `kea-dhcp6.conf` |

The Kea paths come from the server's own config (searched in `/etc/kea` and then `/usr/local/etc/kea`, or wherever `--kea-config-dir` points), falling back to `/var/lib/kea/kea-leases4.csv` and `/var/lib/kea/kea-leases6.csv`. Kea's config is JSON extended with `//`, `#` and `/* */` comments and `<?include "file"?>` directives; all of these are pre-processed before the JSON is parsed. A `mysql` or `postgresql` lease backend, or a `memfile` with `"persist": false`, has no lease file to read, and the command reports that rather than showing an empty table.

Alongside the primary Kea lease file, the toolkit reads the generations left by Lease File Cleanup - `<name>.completed`, or else `<name>.2` and `<name>.1` - in the order Kea itself reloads them, so leases are still listed while a cleanup is in flight or after one was interrupted.

A missing lease file is not fatal. The parser prints a yellow `[WARN]` line and returns zero leases, so a host that runs only DHCPv4 still produces a clean DHCPv4 listing. A file you lack permission to read prints a red `[ERROR]` line suggesting `sudo`, and likewise returns zero leases.

### ISC dhcpd.leases (IPv4)

The IPv4 ISC parser scans the file for `lease IP { ... }` blocks. From each block it pulls the following fields by name. Any field that is absent is shown as `-`.

| Field shown | Source token in the block |
| --- | --- |
| IP address | the `lease <ip> {` header |
| State | `binding state <word>;` |
| MAC | `hardware ethernet <mac>;` |
| Hostname | `client-hostname "<name>";` |
| Expires | the date in `ends <weekday> <date time>;` |
| Starts | the date in `starts <weekday> <date time>;` |
| Vendor class | `option vendor-class-identifier "<text>";` |

When the same IP appears in more than one block (ISC appends rather than rewrites), the parser keeps the most representative entry: an `active` lease always wins over a non-active one, and between two leases in the same state the later `ends` value wins. This is why a single listing never shows the same IPv4 address twice.

### ISC dhcpd6.leases (IPv6)

The IPv6 ISC parser scans for `ia-na "<duid>" { ... }` blocks, each of which nests an `iaaddr <addr> { ... }` block. The quoted `ia-na` key is the raw DUID material (with a 4-byte IAID prepended); the toolkit converts it to a MAC using the DUID rules described later in this chapter. From the nested address block it reads the leased IPv6 address, the `binding state`, and the `ends` expiry; the `cltt` line supplies the start time. There is no hostname or vendor-class field in this format, so both are shown as `-`. The same active-beats-inactive, later-expiry deduplication is applied per IPv6 address.

### Kea CSV Lease Files (v4 and v6)

Kea lease files are CSV with a header row. The toolkit reads them with a dictionary CSV reader, so columns are matched **by header name**, not by position; extra columns from newer Kea releases are ignored, missing ones are tolerated, and column order does not matter.

Kea writes a new row on each update, making the file a journal, and it is replayed with Kea's own semantics: rows are applied in order, the **last** row for an address wins, and a row whose `valid_lifetime` is `0` is Kea's delete marker and removes the address from the listing. (This differs from the ISC parsers, which keep whichever block is `active`. Applying that rule to Kea left released and reclaimed addresses on display as though they were still held, which is why the two now differ.)

Where a value would break the CSV - most often a comma inside a `user_context` JSON blob - Kea escapes it as an XML-style hex entity such as `&#x2c;`. Those escapes are decoded on the way in.

The Kea **state** column is a numeric code, mapped as follows. Any unrecognized code is shown verbatim as `state-<code>`.

| Code | Meaning shown |
| --- | --- |
| 0 | active |
| 1 | declined |
| 2 | expired |
| 3 | released |

For the IPv4 file (`kea-leases4.csv`) the parser expects these columns:

```
address, hwaddr, client_id, valid_lifetime, expire, subnet_id,
fqdn_fwd, fqdn_rev, hostname, state, user_context, pool_id
```

Of those it uses `address` (the IP), `hwaddr` (the MAC), `client_id`, `hostname`, `state`, `expire`, `valid_lifetime`, and `user_context`. An empty `address` row is skipped. When `hwaddr` is empty the MAC is recovered from `client_id`, which carries it in one of two encodings: the RFC 2132 form (htype `0x01` followed by the six MAC bytes) or the RFC 4361 form (type `0xff` followed by a four-byte IAID and a DUID). A client-identifier that carries no link-layer address at all - an opaque string, say - leaves the column as `-`.

`expire` is a Unix epoch and is rendered in UTC. The lease start time is derived as `expire - valid_lifetime`, which is the client-last-transaction time the ISC parsers put in the same field. A vendor class stored under a `vendor-class` key in `user_context`, at any nesting depth, is shown in the Vendor Class column.

For the IPv6 file (`kea-leases6.csv`) the parser expects these columns:

```
address, duid, valid_lifetime, expire, subnet_id, pref_lifetime,
lease_type, iaid, prefix_len, fqdn_fwd, fqdn_rev, hostname,
hwaddr, state, user_context, hwtype, hwaddr_source, pool_id
```

Kea v6 stores the client hardware address in the `hwaddr` column when it could derive one, and that value is used in preference to anything else. It is not always populated, though - it depends on Kea's `mac-sources` setting and on the exchange itself - and where it is empty the MAC is decoded from the `duid` column instead, using the same DUID rules described later in this chapter. Kea stores the bare DUID as colon-separated hex with no IAID prefix (the IAID is a column of its own), unlike ISC, which prepends four IAID bytes inside the `ia-na` key; both are handled. The `duid` column is preserved as supplied.

The `lease_type` column controls what is shown: type `0` is an IA_NA address lease and is listed; type `2` is a prefix delegation (IA_PD) and is **skipped**, because the listing shows leased addresses only.

In both Kea formats the `expire` column is a Unix epoch timestamp. The toolkit converts it to a `YYYY/MM/DD HH:MM:SS` string; a value it cannot parse becomes `-`.

### DUID Handling (extract_mac_from_duid)

ISC DHCPv6 lease files identify a client by DUID, not by MAC. To present a familiar hardware address, the toolkit decodes the DUID stored in the `ia-na` key. That key carries a 4-byte IAID before the DUID itself, so the decoder first strips those 4 bytes, then reads the 2-byte DUID type and extracts the MAC according to the type.

| DUID type | Name | How the MAC is recovered |
| --- | --- | --- |
| 1 | DUID-LLT | Skip the 2-byte hardware type and 4-byte time field, then take the 6 link-layer bytes (DUID bytes 8 through 13). |
| 3 | DUID-LL | Skip the 2-byte hardware type, then take the 6 link-layer bytes (DUID bytes 4 through 9). |
| 2 | DUID-EN | No link-layer address is defined; the decoder scans the enterprise data as ASCII for an embedded colon-separated MAC string and returns the first match. |

The DUID-EN case is a best-effort heuristic: it only succeeds when the vendor happens to embed a printable `xx:xx:xx:xx:xx:xx` MAC inside the enterprise-specific identifier. If the type is unrecognized, the DUID is too short, or no MAC pattern is found, the result is `-`.

The bundled `dhcpd6.leases` fixture deliberately contains one block of each type (DUID-LLT, DUID-LL, and an ASCII-embedded DUID-EN), and all three resolve to a real MAC in the listing, which makes it a convenient test of this decoder.

## Capture Inputs (dhcp-forensics)

The `dhcp-forensics` command takes one positional argument, the capture file:

```
dhcp-forensics PCAP [--json] [--leases FILE] [--config FILE] [--no-color]
```

The reader auto-detects the container format from the first four bytes of the file, so you do not declare whether it is pcap or pcapng. A file shorter than 4 bytes, or one whose leading bytes match no known magic, yields zero packets rather than an error. If the path does not exist, the command writes `error: pcap not found: <path>` to standard error and exits with code 2.

### Classic pcap

A classic libpcap file begins with a 24-byte global header whose 32-bit magic number encodes both the byte order and the timestamp resolution. All four standard variants are recognized:

| Magic | Byte order | Timestamp resolution |
| --- | --- | --- |
| 0xa1b2c3d4 | big-endian | microsecond |
| 0xd4c3b2a1 | little-endian | microsecond |
| 0xa1b23c4d | big-endian | nanosecond |
| 0x4d3cb2a1 | little-endian | nanosecond |

The link type is read from the global header. Each packet then has a 16-byte record header (`ts_sec`, `ts_frac`, `incl_len`, `orig_len`) followed by the captured frame bytes. The reader honors the byte order and the timestamp divisor from the magic so timestamps are correct for both microsecond and nanosecond files.

### Minimal pcapng

A pcapng file begins with a Section Header Block whose block-type magic is `0x0a0d0d0a`. The reader does a best-effort walk of the block stream and understands a minimal but practical subset:

- **Section Header Block (SHB)** establishes the byte order from the byte-order magic in its body.
- **Interface Description Block (IDB)** records each interface's link type, in order.
- **Enhanced Packet Block (EPB)** carries a captured frame, its interface id, and a 64-bit timestamp.
- **Simple Packet Block (SPB)** carries a frame with no per-packet metadata; it is associated with the first interface and given a zero timestamp.

Blocks the reader does not recognize are skipped by their declared length, so the walk continues past them. pcapng timestamps are interpreted with a microsecond scale.

### Link-Layer, VLAN, and L3/L4 Decoding

Only **Ethernet** (link type 1, `EN10MB`) frames are interpreted at layers 2 through 4. A frame on any other link type is still recorded as a packet with its raw bytes preserved, but its addresses, VLAN, and protocol fields are left empty, so it cannot contribute a decoded DHCP message.

For each Ethernet frame the reader extracts the destination and source MAC and the ethertype, then strips VLAN tags before looking at the network layer:

- It strips up to **two** stacked VLAN tags, covering both 802.1Q (`0x8100`) and 802.1ad / QinQ (`0x88a8`).
- It records the **inner** VLAN id and resolves the ethertype to the innermost encapsulated type.

After VLAN stripping it decodes the network and transport layers:

- **IPv4** (`0x0800`): reads the header length, protocol, and source/destination addresses; if the protocol is UDP it parses the UDP header.
- **IPv6** (`0x86dd`): reads the source/destination addresses and walks past hop-by-hop (0), routing (43), and destination-options (60) extension headers to find the upper-layer protocol; if that is UDP it parses the UDP header.
- **UDP** (protocol 17): reads the source and destination ports and the payload, clamped to the captured frame length, which becomes the candidate DHCP payload.

Any frame that is not IPv4 or IPv6 over Ethernet is recorded with an `l3` value of `other` and contributes no DHCP message.

### DHCP Message Decoding Inside Captures

UDP payloads recovered from the capture are handed to two defensive decoders. A payload that does not match the expected structure returns nothing rather than raising, and individual malformed options are skipped.

**DHCPv4 / BOOTP** decoding (RFC 2131 / 2132) requires a payload of at least 240 bytes with the BOOTP magic cookie `63:82:53:63` at offset 236. The decoder reads the fixed BOOTP header (operation, transaction id, the `ciaddr` / `yiaddr` / `siaddr` / `giaddr` address fields, and the client hardware address selected by `hlen`), then walks the option TLV stream until option 255 (End), honoring option 0 (Pad). All options are kept raw, and these well-known options are surfaced by name:

| Option | Name |
| --- | --- |
| 53 | DHCP message type |
| 50 | Requested IP address |
| 54 | Server identifier |
| 61 | Client identifier |
| 60 | Vendor class identifier |
| 12 | Host name |

The message type (option 53) is mapped to a name: DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, or INFORM. A valid BOOTP payload with no option 53 is reported as `BOOTP`; an unrecognized type code is reported as `UNKNOWN`.

**DHCPv6** decoding (RFC 8415) reads the 1-byte message type and 3-byte transaction id from a payload of at least 4 bytes, then walks the option TLVs. It recognizes client-id (option 1, a DUID), server-id (option 2, a DUID), IA_NA (option 3, into which it recurses to pull leased addresses from nested IAADDR sub-options, code 5), and vendor-class (option 16). The message type is mapped to a name such as SOLICIT, ADVERTISE, REQUEST, RENEW, REPLY, RELEASE, RELAY-FORW, or RELAY-REPL; an unrecognized type is reported as `UNKNOWN`. A truncated option (one whose declared length runs past the payload) marks the whole DHCPv6 payload malformed and yields nothing.

### What Is Not Supported

The reader is deliberately narrow. Be aware of these limits:

- **Non-Ethernet link types** are not decoded. Raw IP, Linux cooked capture, 802.11, and similar link types yield only opaque packet records with no DHCP content.
- **More than two VLAN tags** are not stripped. Triple-stacked tags leave the inner ethertype unresolved, so the frame is treated as `other`.
- **Truncated frames** are skipped. In a classic pcap a final record whose declared length runs past the end of the file, or whose included length is zero, stops the walk cleanly; earlier records are preserved. A frame shorter than the 14-byte Ethernet header is dropped.
- **Truncated or malformed blocks** in a pcapng file are skipped, and the walk stops if a block declares a length that overruns the file.
- **Non-UDP transports** (TCP, ICMP, and so on) carry no DHCP payload and produce no DHCP message, even though the packet itself is recorded.
- **Compressed, encrypted, or third-party container formats** are not supported; only classic pcap and the minimal pcapng subset above are read.

## Bundled Fixtures and Samples

The toolkit ships with ready-to-run lease files and captures. The lease and small-capture fixtures live under `/home/labuser/CCode/DHCP/tests/fixtures`, and a larger real-world capture lives under `/home/labuser/CCode/DHCP/samples`. Use them to confirm your installation and to see the expected output before pointing the tools at production data.

| File | Format | What it demonstrates |
| --- | --- | --- |
| `tests/fixtures/dhcpd.leases` | ISC dhcpd.leases (IPv4) | Four IPv4 leases including two active leases held by the same MAC and one free lease, the O-RU shared-xid symptom. |
| `tests/fixtures/dhcpd6.leases` | ISC dhcpd6.leases (IPv6) | One block each of DUID-LLT, DUID-LL, and DUID-EN, exercising all three MAC-extraction paths. |
| `tests/fixtures/kea-leases4.csv` | Kea CSV (v4) | Journal-style appended rows for one IP and a declined lease, exercising Kea v4 column parsing and dedup. |
| `tests/fixtures/kea-leases6.csv` | Kea CSV (v6) | Address and prefix-delegation rows; the IA_PD row is skipped while IA_NA addresses are listed. |
| `tests/fixtures/clean_dhcp.pcap` | classic pcap, little-endian microsecond | A healthy single-VLAN DHCPv4 exchange (8 frames, VLAN 201) with no defect. |
| `tests/fixtures/oru_xid_reuse.pcap` | classic pcap, little-endian microsecond | The shared-xid incident capture (14 DHCPv4 frames, VLAN 201) that the forensic detectors flag as AFFECTED. |
| `samples/oru_real_capture.pcap` | classic pcap, little-endian microsecond | A larger real capture (555 frames) mixing IPv4, IPv6, and non-IP traffic on VLAN 201. |

To list the ISC fixtures, including expired and free leases, run:

```
dhcp-lease-list --server isc \
  --v4-lease tests/fixtures/dhcpd.leases \
  --v6-lease tests/fixtures/dhcpd6.leases --all
```

That produces a listing whose DHCPv4 section shows the two same-MAC active leases (`.171` and `.172` both held by `34:fe:9e:3d:ad:c8`) and whose DHCPv6 section shows all three DUID types resolved to MAC addresses:

```
[ DHCPv4 Leases ]  file: tests/fixtures/dhcpd.leases  total: 4  active: 3
IP Address       MAC / DUID          Hostname   State    Expires (UTC)
192.168.36.160   34:fe:9e:3d:af:5c   -          free     2020/01/01 00:00:00
192.168.36.170   34:fe:9e:3d:ad:a8   oru-ada8   active   2099/12/31 23:59:59
192.168.36.171   34:fe:9e:3d:ad:c8   oru-adc8   active   2099/12/31 23:59:59
192.168.36.172   34:fe:9e:3d:ad:c8   oru-adc8   active   2099/12/31 23:59:59

[ DHCPv6 Leases ]  file: tests/fixtures/dhcpd6.leases  total: 3  active: 3
fd00:36::171   34:fe:9e:3d:ad:a8   -   active   2099/12/31 23:59:59
fd00:36::172   34:fe:9e:3d:ad:c8   -   active   2099/12/31 23:59:59
fd00:36::173   34:fe:9e:3d:af:5c   -   active   2099/12/31 23:59:59
```

To read a capture, pass it as the positional argument:

```
dhcp-forensics tests/fixtures/oru_xid_reuse.pcap --no-color
```

The capture summary confirms how the reader interpreted the file, including the recovered ethertype and VLAN distribution:

```
CAPTURE SUMMARY
Total frames : 14
DHCPv4 msgs  : 14
DHCPv6 msgs  : 0
Ethertypes   : 0x0800=14
VLANs        : 201=14
```

A DHCPv4 transaction recovered from that capture shows the decoded BOOTP fields, including the message type names and the offered address, which is the input on which the forensic detectors operate:

```
time          eth_src            chaddr             type      ip
13:45:03.843  34:fe:9e:3d:ad:c8  34:fe:9e:3d:ad:c8  DISCOVER  -
13:45:04.844  02:00:5e:00:00:01  34:fe:9e:3d:ad:c8  OFFER     192.168.36.171
13:45:04.966  34:fe:9e:3d:ad:c8  34:fe:9e:3d:ad:c8  REQUEST   192.168.36.171
13:45:04.970  02:00:5e:00:00:01  34:fe:9e:3d:ad:c8  ACK       192.168.36.171
```

Because this fixture is the shared-xid incident, the command reports a verdict of `AFFECTED` and exits with code 2; the clean capture `tests/fixtures/clean_dhcp.pcap` exits 0.

[[PAGEBREAK]]

# Tutorials and Operational Workflows

This chapter contains end-to-end procedures for the **DHCP O-RU Toolkit** version 2.1.0. Each workflow is a numbered procedure with the exact commands to run and the result you should expect. The toolkit ships two commands, `dhcp-lease-list` and `dhcp-forensics`, both pure Python standard library with no third-party dependencies.

The examples assume you are running from a source checkout at the repository root and have not installed the package. In that mode, prefix each invocation with `PYTHONPATH=src` and call the module, for example `PYTHONPATH=src python3 -m dhcp_toolkit.leases.cli`. If you installed the Debian package or ran `pip install -e .`, the commands are available directly on your `PATH` as `dhcp-lease-list` and `dhcp-forensics`, and you can drop the `PYTHONPATH=src python3 -m ...` wrapper. Every workflow below shows the source-tree form so the commands are copy-pasteable in a fresh checkout.

Two facts underpin all of these procedures. First, both tools are silent about third-party software: there is no dependency on scapy, dpkt, tshark, or tcpdump. Second, both tools signal severity through their **process exit code**: exit code `2` means a HIGH-severity problem was found, and exit code `0` means none was. This makes the tools safe to drop into scripts, CI pipelines, and monitoring jobs.

## Workflow 1: Triage a Suspected Duplicate-IP or IP-Theft Incident on the Lease Server

Use this workflow when an operator reports that two radio units appear to be fighting over an address, that a unit keeps losing its lease, or that the DHCP pool is draining faster than the number of deployed units can explain. The `dhcp-lease-list` command reads the server's lease database directly and, with `--conflicts`, flags the lease-table signature of the O-RU defect: one MAC holding several active IPs, or one IP held by several active MACs.

### Procedure

1. Identify the lease files for your server. For ISC DHCP (the default) these are `/var/lib/dhcp/dhcpd.leases` (IPv4) and `/var/lib/dhcp/dhcpd6.leases` (IPv6). For Kea, pass `--server kea`, which defaults to `/var/lib/kea/kea-leases4.csv` and `/var/lib/kea/kea-leases6.csv`. You can override either path with `--v4-lease` and `--v6-lease`.

1. Run the lease viewer in conflict-scan mode. Against the bundled fixtures the command is:

```
PYTHONPATH=src python3 -m dhcp_toolkit.leases.cli --conflicts \
  --v4-lease tests/fixtures/dhcpd.leases \
  --v6-lease tests/fixtures/dhcpd6.leases
```

1. Read the listing first, then the conflict section. The tool prints the active leases per address family, then a labelled `[ Lease Conflicts ]` block. With the fixture data the output is:

```
=== ISC DHCP Unified Lease List  v2.1.0 ===
Active leases shown. Use --all to include expired/free.

[ DHCPv4 Leases ]  file: tests/fixtures/dhcpd.leases  total: 4  active: 3
IP Address       MAC / DUID          Hostname   State    Expires (UTC)         Vendor Class
192.168.36.160   34:fe:9e:3d:af:5c   -          free     2020/01/01 00:00:00   -
192.168.36.170   34:fe:9e:3d:ad:a8   oru-ada8   active   2099/12/31 23:59:59   o-ran-ru2/FJ/...363
192.168.36.171   34:fe:9e:3d:ad:c8   oru-adc8   active   2099/12/31 23:59:59   o-ran-ru2/FJ/...222
192.168.36.172   34:fe:9e:3d:ad:c8   oru-adc8   active   2099/12/31 23:59:59   o-ran-ru2/FJ/...222

[ Lease Conflicts ]
  [HIGH] mac_multiple_active_ips: MAC 34:fe:9e:3d:ad:c8 holds 2 distinct active IPv4 addresses: 192.168.36.171, 192.168.36.172
```

1. Interpret the conflict. In the example, the single hardware address `34:fe:9e:3d:ad:c8` (the unit `oru-adc8`) holds two distinct active IPv4 leases, `192.168.36.171` and `192.168.36.172`. That is the textbook IP-theft signature: one O-RU has accumulated multiple addresses while a peer unit got none. A `mac_multiple_active_ips` conflict means one MAC owns several IPs; the inverse signature, one IP claimed by several MACs, is reported under a corresponding IP-keyed conflict kind.

1. Check the exit code to confirm severity programmatically:

```
echo $?
```

A `HIGH` conflict makes the command exit `2`; if no HIGH conflict is found it exits `0`. In this example it exits `2`.

### Notes and Variations

- The plain listing (without `--conflicts`) shows only active leases. Add `--all` to include expired and free entries, which is useful when you want to see the freed `192.168.36.160` row in context.
- Narrow the view with `--state {active,free,expired,declined,released}`, or restrict to one family with `--v4-only` or `--v6-only`.
- The DHCPv6 section is shown for completeness. The O-RU defect is DHCPv4-only, because each unit uses a unique DUID and IAID for DHCPv6, so you should not expect IPv6 conflicts from this defect.

## Workflow 2: Analyze a Packet Capture from the Field

Use this workflow when you have a `.pcap` (or minimal `.pcapng`) from a span port or fronthaul tap and you need to determine whether the O-RU shared-xid DHCPv4 defect is actually present in the traffic. The `dhcp-forensics` command decodes DHCPv4 and DHCPv6 from the capture, groups packets into transactions, runs the detectors, and prints a forensic report ending in a verdict.

### Procedure

1. Run the analyzer against your capture. Against the synthesized reproduction fixture:

```
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli \
  tests/fixtures/oru_xid_reuse.pcap
```

1. Read the report top-down. It opens with the source pcap and a one-word verdict, then a capture summary (frame and message counts, ethertypes, VLANs), then per-transaction packet timelines, then the findings grouped by severity, then a standards-violations table, and finally a `VERDICT` line with severity counts. The affected fixture produces:

```
DHCP-ORU FORENSIC REPORT  (toolkit v2.1.0)
Source pcap : tests/fixtures/oru_xid_reuse.pcap
Verdict     : AFFECTED

CAPTURE SUMMARY
Total frames : 14
DHCPv4 msgs  : 14
DHCPv6 msgs  : 0
Ethertypes   : 0x0800=14
VLANs        : 201=14
```

1. Confirm whether the defect is present by reading the findings and the final verdict. On the reproduction fixture, all of the defect's detectors fire:

```
FINDINGS (10)
== HIGH (10) ==
  [SHARED_XID] Shared DHCPv4 transaction-id across multiple units
  [FOREIGN_OFFER_REACTION] Unit reacted to a DHCPv4 OFFER addressed to another unit
  [MISSING_CLIENT_ID] DHCPv4 messages omit option 61 (client identifier)
  [DUPLICATE_GRANT_IP] Single IP contested by multiple units (IP theft)
  [DUPLICATE_GRANT_MAC] Single unit granted multiple DHCPv4 leases

VERDICT: AFFECTED   (HIGH=10, MEDIUM=0, LOW=0, INFO=0)
```

1. Read the per-transaction timeline to see the evidence in raw form. Each transaction is keyed by its DHCPv4 xid, and the packet table shows the time, Ethernet source, `chaddr`, message type, and IP. The defect is visible directly: two distinct units share xid `0x8fc37a94`, and a unit issues a `REQUEST` for an address the server `OFFER`ed to a different `chaddr`.

1. The verdict is authoritative. `AFFECTED` (with `HIGH > 0`) means the defect is present and the command exits `2`.

### Confirming a Clean Capture

Run the same command against a capture with well-behaved clients. The clean fixture yields a `CLEAN` verdict, no findings, and exit code `0`:

```
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli \
  tests/fixtures/clean_dhcp.pcap
```

```
Verdict     : CLEAN
FINDINGS (0)
No issues detected.
VERDICT: CLEAN   (HIGH=0, MEDIUM=0, LOW=0, INFO=0)
```

### When the Capture Has No DHCPv4 Traffic

If the capture contains no DHCPv4 messages, the tool will not invent a verdict. It reports honestly that the defect cannot be observed and exits `0`. For example, the bundled real fronthaul capture is dominated by O-RAN fronthaul ethertypes and carries a single DHCPv6 message:

```
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli \
  samples/oru_real_capture.pcap
```

```
Note        : capture contains no DHCPv4 traffic; DHCPv4 defect cannot be observed in this file
Verdict     : NO DHCPv4 TRAFFIC
Total frames : 555
DHCPv4 msgs  : 0
DHCPv6 msgs  : 1
Ethertypes   : 0x88f7=539, 0x8809=10, 0x86dd=5, 0x0800=1
```

A `NO DHCPv4 TRAFFIC` verdict is not a pass or a fail. It means you captured at the wrong point or time: the DHCPv4 evidence lives on a server-side capture. Re-capture where the DHCPv4 DISCOVER, OFFER, REQUEST, and ACK frames are visible, then rerun.

### Disabling Color for Files and Logs

The text report is colorized for terminals. When redirecting to a file, pasting into a ticket, or piping to another tool, add `--no-color` to strip ANSI escape codes:

```
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli \
  tests/fixtures/oru_xid_reuse.pcap --no-color > report.txt
```

## Workflow 3: Correlate a Capture Against the Live Lease Database

Use this workflow to confirm that the addresses being raced for in a capture actually landed as conflicting leases on the server. The `--leases` flag tells `dhcp-forensics` to parse a lease file and fold any lease conflicts into the same report as additional findings, so packet evidence and lease-table evidence appear together with a single verdict.

### Procedure

1. Run the analyzer with both the capture and the lease file:

```
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli \
  tests/fixtures/oru_xid_reuse.pcap \
  --leases tests/fixtures/dhcpd.leases
```

1. Compare the findings count against the capture-only run from Workflow 2. Folding in the lease conflicts adds a finding, and the new entry is clearly labelled with a `LEASE_` prefix:

```
Verdict     : AFFECTED
FINDINGS (11)
  [LEASE_MAC_MULTIPLE_ACTIVE_IPS] Lease-file conflict: mac_multiple_active_ips
VERDICT: AFFECTED   (HIGH=11, MEDIUM=0, LOW=0, INFO=0)
```

The capture-only run reported `HIGH=10`; with the lease database correlated it reports `HIGH=11`. The extra HIGH is the same `mac_multiple_active_ips` conflict that Workflow 1 surfaces standalone, now confirming that the in-flight race in the capture did persist as a duplicate lease on the server.

1. You do not need to declare the lease-file format. The `--leases` parser tries ISC v4, ISC v6, Kea v4, and Kea v6 in turn and keeps whichever yields the most leases, so the same flag works for either server type.

### Adding Configured-Pool Context with --config

To annotate the report with the address ranges your ISC `dhcpd.conf` defines, add `--config`. The tool extracts `subnet`, `range`, and `range6` lines and records them as pool notes in the report metadata. This is most visible in the JSON output (see Workflow 4); for example, with the bundled config the metadata includes:

```
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli \
  tests/fixtures/oru_xid_reuse.pcap \
  --leases tests/fixtures/dhcpd.leases \
  --config configs/dhcpd.conf --json
```

```
"config": "configs/dhcpd.conf",
"config_pools": [
  "subnet 192.168.36.0 netmask 255.255.255.0 {",
  "range 192.168.36.100 192.168.36.109",
  "range 192.168.36.180 192.168.36.189"
]
```

Use this to verify that the contested addresses fall inside an expected, configured pool rather than a static or out-of-range allocation. The `--config` flag affects only the recorded pool notes; it does not change the verdict or the exit code.

## Workflow 4: Use the Tools in CI or Monitoring

Both commands are built to gate automation through their exit code. A HIGH-severity result exits `2`; everything else exits `0`. You never need to parse text output to make a pass or fail decision, although the JSON report is available when you do want structured data.

### Exit-Code Contract

| Command | Condition | Exit code |
| --- | --- | --- |
| dhcp-lease-list --conflicts | A HIGH lease conflict found | 2 |
| dhcp-lease-list --conflicts | No HIGH conflict | 0 |
| dhcp-forensics | Verdict AFFECTED (HIGH greater than zero) | 2 |
| dhcp-forensics | Verdict CLEAN or NO DHCPv4 TRAFFIC | 0 |
| dhcp-forensics | pcap missing or unreadable | 2 |

### Procedure for a Pipeline Gate

1. Invoke the tool and let its exit code propagate. In a shell pipeline you can fail the job explicitly on exit `2`:

```
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli \
  tests/fixtures/oru_xid_reuse.pcap --no-color
status=$?
if [ "$status" -eq 2 ]; then
  echo "FAIL: O-RU DHCPv4 defect detected in capture"
  exit 1
elif [ "$status" -ne 0 ]; then
  echo "ERROR: analyzer could not process the capture"
  exit 1
else
  echo "PASS: no HIGH findings"
fi
```

1. For a monitoring cron job against the live lease database, gate on the lease scanner the same way and alert on exit `2`:

```
PYTHONPATH=src python3 -m dhcp_toolkit.leases.cli --conflicts \
  --v4-lease /var/lib/dhcp/dhcpd.leases \
  --v6-lease /var/lib/dhcp/dhcpd6.leases > /dev/null
if [ $? -eq 2 ]; then
  echo "ALERT: HIGH lease conflict on DHCP server" | logger -t dhcp-oru
fi
```

The `dhcp-lease-list` command does not accept `--no-color`; only `dhcp-forensics` does. For the lease scanner in non-interactive jobs, redirect output as shown above rather than expecting a color toggle.

1. For machine-readable forensic results, add `--json` to `dhcp-forensics`. The report is a JSON object with these top-level keys: `version`, `generated_meta`, `capture`, `transactions`, `findings`, `severity_counts`, and `verdict`. To make a decision in a script, read `severity_counts.HIGH` or `verdict`:

```
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli \
  tests/fixtures/oru_xid_reuse.pcap --json
```

```
"severity_counts": { "HIGH": 10, "MEDIUM": 0, "LOW": 0, "INFO": 0 },
"verdict": "AFFECTED"
```

Even when you parse the JSON, the process still exits `2` on a HIGH finding, so the exit-code gate and the JSON body always agree.

## Workflow 5: Run the Bundled Demonstration

The repository ships a one-command demonstration through the Makefile. Use it to validate a fresh checkout, to see both tools run against known-good fixtures, or to give a new operator a guided first look without crafting any arguments.

### Procedure

1. From the repository root, run the demo target:

```
make demo
```

1. Understand what it does. The `demo` target depends on the `fixtures` target, so it first regenerates the deterministic test fixtures, then runs `dhcp-forensics` on the affected reproduction pcap, and finally runs `dhcp-lease-list --all` on the fixture lease files. Each tool invocation is wrapped so the demo always completes even when a tool exits `2`. The opening lines are:

```
PYTHONPATH=src python3 tools/make_fixtures.py
Writing deterministic fixtures to .../tests/fixtures
  wrote oru_xid_reuse.pcap       4742 bytes
  wrote clean_dhcp.pcap          2684 bytes
  wrote dhcpd.leases             1564 bytes
  ...
Done: 6 fixtures.
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli tests/fixtures/oru_xid_reuse.pcap || true
DHCP-ORU FORENSIC REPORT  (toolkit v2.1.0)
Verdict     : AFFECTED
```

1. Read the two reports the demo emits. The forensics run reproduces the `AFFECTED` report from Workflow 2, and the lease listing reproduces the `--all` view from Workflow 1 against the fixture lease files. Because the demo wraps each command, the `make demo` process itself exits `0` regardless of the individual tool verdicts; the demo is for inspection, not for gating.

1. To regenerate only the fixtures without running the tools, use the `fixtures` target on its own:

```
make fixtures
```

### Related Makefile Targets

| Target | Purpose |
| --- | --- |
| make demo | Build fixtures, then run both tools for a guided end-to-end demo |
| make fixtures | Regenerate the deterministic test pcaps and lease files |
| make test | Run the unit tests (pytest if available, else the stdlib runner) |
| make deb | Build the Debian package under dist |
| make clean | Remove build artifacts, caches, and compiled files |

After running the demo, you have seen each tool produce a real verdict against real fixture data, and you are ready to point them at your own lease databases and field captures using Workflows 1 through 4.

[[PAGEBREAK]]

# Troubleshooting, FAQ, and Appendices

This chapter helps you resolve the situations operators most commonly hit while running the two tools in the **DHCP O-RU Toolkit** version 2.1.0: `dhcp-lease-list` and `dhcp-forensics`. Part A walks through symptoms and fixes. Part B answers frequent questions. Part C provides reference tables for exit codes, terminology, and the standards the tools cite. Every behavior described here is grounded in the shipped code; the tools are read-only and never modify lease files, captures, or server state.

## Part A: Troubleshooting

### Command Not Found After Install

If your shell reports `dhcp-lease-list: command not found` or `dhcp-forensics: command not found` immediately after installing the Debian package, the wrapper directory is not on your `PATH`. The package installs the `dhcp_toolkit` Python library under `/usr/local/lib/dhcp-oru-toolkit` and places both commands as thin wrappers in `/usr/local/sbin`.

- `/usr/local/sbin` is typically on `root`'s `PATH` but may be absent from an unprivileged user's `PATH`. Run the command with `sudo`, or add `/usr/local/sbin` to your `PATH`.
- Invoke the tool by its absolute path to confirm it is installed, for example `/usr/local/sbin/dhcp-lease-list --version`. A correct install prints `dhcp-lease-list 2.1.0`.
- The package depends only on `python3 (>= 3.8)`. If `python3` is missing, the wrappers cannot run. Install Python 3.8 or newer.

If you are running from a source tree rather than the installed package, invoke the entry points directly, for example `PYTHONPATH=src python3 -c "from dhcp_toolkit.leases.cli import main; main()" --version`.

### No Leases Shown, or the Wrong Lease Path

`dhcp-lease-list` resolves the lease-file paths itself when you do not pass `--v4-lease` or `--v6-lease`.

| Server | IPv4 lease file | IPv6 lease file |
| --- | --- | --- |
| `isc` | `/var/lib/dhcp/dhcpd.leases` | `/var/lib/dhcp/dhcpd6.leases` |
| `kea` | `lease-database.name` from `kea-dhcp4.conf` | `lease-database.name` from `kea-dhcp6.conf` |

If the resolved path does not match your deployment, the parser cannot find the file and the tool prints a yellow warning, then reports zero leases for that family:

```
[WARN] DHCPv4 lease file not found: /var/lib/dhcp/dhcpd.leases
[ DHCPv4 Leases ]  file: /var/lib/dhcp/dhcpd.leases  total: 0  active: 0
```

To fix this:

- Pass the real path explicitly with `--v4-lease PATH` and `--v6-lease PATH`. Under the default `--server auto` the file's format is detected from its contents, so you do not also need `--server`.
- Check which server was selected. The banner names it (`=== Kea DHCP Unified Lease List ===`) and each section is headed `--- ISC DHCP ---` or `--- Kea DHCP ---`. Force the choice with `--server isc`, `--server kea`, or `--server both`.
- Remember that, by default, only **active** leases are shown. If a lease exists but is expired, free, declined, or released, it is hidden until you add `--all`. Use `--state` to filter to a single binding state (`active`, `free`, `expired`, `declined`, or `released`).
- Use `--v4-only` or `--v6-only` if you intend to view just one family; without them, both families are listed.

### Kea Shows Few Leases, or None, on a Server That Is Clearly Working

Three Kea-specific causes account for most of this, and the tool now handles or reports all three. If you are on an older release, they are worth checking by hand.

- **The lease file is not where you think.** `lease-database.name` in `/etc/kea/kea-dhcp4.conf` is site-configurable and often is not `/var/lib/kea/kea-leases4.csv`. Confirm with `grep -A5 lease-database /etc/kea/kea-dhcp4.conf`. Point `--kea-config-dir` at the config if it lives outside `/etc/kea`.
- **Lease File Cleanup is in flight, or was interrupted.** Kea's LFC moves the lease file aside and consolidates through `<name>.1`, `<name>.2` and `<name>.completed`; the primary file then holds only what has been written since. Check with `ls -l /var/lib/kea/`. If those files are present, the leases in them are real - a `[NOTE]` line tells you which ones were included in the listing.
- **The leases are not in a file at all.** A `mysql` or `postgresql` lease backend, or a `memfile` with `"persist": false`, has nothing on disk to read. The command reports the backend it found. Query the database directly, or use `kea-shell` with the `lease4-get-all` / `lease6-get-all` commands.

If the count looks right but addresses you expect to be free are still shown as held, note that Kea's lease file is a journal and the **last** row for an address is the truth. A row with `valid_lifetime = 0` means the lease was deleted.

### A Kea Lease Shows No MAC Address

Kea fills the `hwaddr` column of its lease file only when it could derive a link-layer address from the exchange - it depends on Kea's `mac-sources` setting, and a relayed exchange may not supply one. The MAC is recovered from the DHCPv6 DUID or the DHCPv4 option 61 client-identifier where the column is empty, so this is uncommon.

A `-` in the MAC column means there was genuinely nothing to decode: no `hwaddr`, and a DUID or client-identifier that carries no link-layer address (a DUID-UUID, or an opaque string client-id). A declined address recorded before any client identification is the usual case.

### dhcp-forensics Reports No DHCPv4 Traffic

If `dhcp-forensics` prints a `Note` line and a verdict of `NO DHCPv4 TRAFFIC`, this is **expected and correct** for any capture that contains no DHCPv4 packets. It is not an error. The analyzer detects a DHCPv4 defect, so a capture with zero DHCPv4 messages gives it nothing to flag. The tool says so honestly:

```
Note        : capture contains no DHCPv4 traffic; DHCPv4 defect cannot be observed in this file
Verdict     : NO DHCPv4 TRAFFIC
```

This is exactly what the toolkit's own sample capture `samples/oru_real_capture.pcap` produces: 555 frames dominated by PTP, with a single healthy DHCPv6 message and zero DHCPv4 packets. The exit code in this case is `0`, because no HIGH finding is present.

The reason is that the O-RU's own fronthaul capture carries this unit's steady-state M-Plane chatter, not the broadcast DHCPv4 contention a server sees during a simultaneous multi-unit boot. The shared-xid IP-theft behavior is a DHCPv4 phenomenon that lives in a server-side capture. For the full background on why the real capture lacks DHCPv4 and how the analyzer is validated against the synthesized fixture `tests/fixtures/oru_xid_reuse.pcap`, see the chapter on the O-RU DHCPv4 shared-xid defect.

To see the analyzer flag the defect, run it against a capture that actually contains the contended DHCPv4 transactions, for example the bundled fixture, which yields verdict `AFFECTED` and exit code `2`.

### Colors Look Wrong in Logs or Redirected Output

Both tools emit ANSI color by default for terminal readability. When you pipe output to a file, a log collector, or a pager that does not interpret ANSI, you may see raw escape sequences such as `[36m` or `[1m` interleaved with the text.

- For `dhcp-forensics`, pass `--no-color` to disable ANSI coloring in the text report.
- For `dhcp-lease-list`, there is no `--no-color` flag in this version. If you must strip color from its output, filter the escape sequences downstream, for example by piping through a `sed` expression that removes ANSI codes.
- `dhcp-forensics --json` emits plain JSON with no color, which is the cleanest option for machine consumption or archival.

### File-Permission Issues Reading Lease Files

Lease files on a production server are often readable only by the DHCP service account or `root`. If `dhcp-lease-list` cannot read a lease file because of permissions, it prints a red error naming the file and suggesting elevation, then continues with zero leases for that family:

```
[ERROR] Permission denied: /var/lib/dhcp/dhcpd.leases (try sudo)
```

Resolve this by running the command with `sudo` (or as a user that can read the file). The tools never write to or modify these files, so reading them under elevation is safe.

### Unsupported or Unreadable Capture Format

`dhcp-forensics` reads capture files with a pure-Python reader that understands classic libpcap (both byte orders, microsecond or nanosecond timestamps) and a best-effort subset of pcapng. It interprets `LINKTYPE_ETHERNET` frames at L2/L3/L4. Two distinct situations can look like "nothing happened":

- **File not found.** The tool writes `error: pcap not found: PATH` to standard error and exits with code `2`. Check the path and your read permission.
- **Unreadable or unrecognized container.** If the file does not begin with a recognized pcap or pcapng magic number, the reader returns zero frames rather than raising. You then get a normal report with `Total frames : 0` and verdict `NO DHCPv4 TRAFFIC`, exit code `0`. If you expected packets, confirm the file is a genuine `.pcap` or `.pcapng` capture and is not gzip-compressed, truncated at the header, or a text file.

The reader is deliberately robust: a malformed or truncated record is skipped rather than aborting the whole parse, so a damaged tail never discards the records that preceded it. Link types other than Ethernet are preserved as raw frames but are not decoded into DHCP, so a non-Ethernet capture will also report zero DHCP messages.

## Part B: FAQ

### Does the Toolkit Modify Anything?

No. Both tools are strictly read-only. `dhcp-lease-list` parses lease files and prints them; `dhcp-forensics` reads a capture and prints a report. Neither writes to lease files, captures, configuration, or DHCP server state.

### Does It Need Root?

Not in general. Root (or `sudo`) is needed only to read protected files, such as a lease file owned by the DHCP service account or a capture you cannot otherwise open. When `dhcp-lease-list` hits a permission error it tells you to try `sudo`.

### Does It Need scapy, dpkt, or tshark?

No. The toolkit is zero-dependency and uses only the Python standard library. The capture reader and DHCP decoding are implemented in pure Python, and the package depends only on `python3 (>= 3.8)`. You do not need scapy, dpkt, tcpdump, or tshark installed.

### Is DHCPv6 Affected by the Shared-xid Bug?

No. The defect is a DHCPv4 phenomenon: a shared transaction id (xid) across units, reaction to foreign OFFERs, and a missing option 61 client identifier. DHCPv6 uses a different identity model (DUID plus IAID) and is healthy in the observed traffic. `dhcp-forensics` reports DHCPv6 transactions for completeness but does not flag them for the DHCPv4 defect.

### What Do the Exit Codes Mean?

In short: `0` means clean, `2` means a HIGH-severity result or a fatal read error. See the exit-codes table in Part C for the per-command detail.

### Why Does dhcp-lease-list Exit 2 Even Though It Printed Leases?

`dhcp-lease-list` only returns a nonzero code when you pass `--conflicts` and the scan finds at least one HIGH-severity conflict, for example one MAC holding multiple distinct active IPv4 addresses, or one IP held by multiple active MACs. Without `--conflicts`, the command exits `0` after listing.

## Part C: Appendices

### Appendix C.1: Exit-Codes Reference

| Command | Exit code | Meaning |
| --- | --- | --- |
| `dhcp-lease-list` | 0 | Leases listed successfully; no HIGH conflict (or `--conflicts` not used) |
| `dhcp-lease-list` | 2 | `--conflicts` was set and at least one HIGH-severity conflict was found |
| `dhcp-forensics` | 0 | Report produced; no HIGH finding present (includes the no-DHCPv4 case) |
| `dhcp-forensics` | 2 | At least one HIGH finding present, or the pcap could not be found or read |

Note that both commands also return the standard argparse code `2` when invoked with invalid arguments (for example an unknown flag or a missing required `PCAP` positional), and `0` after printing `--help` or `--version`.

### Appendix C.2: Glossary

| Term | Meaning |
| --- | --- |
| xid | DHCP transaction id; a per-exchange identifier that ties a client request to the server reply. Reused across O-RUs in the DHCPv4 defect. |
| chaddr | Client hardware address field in a DHCPv4 message; normally the client MAC. |
| DUID | DHCP Unique Identifier; the per-client identity used in DHCPv6, independent of the interface MAC. |
| IAID | Identity Association Identifier; names a specific address association a DHCPv6 client requests, paired with its DUID. |
| OFFER / ACK | DHCPv4 server replies: OFFER proposes an address to a DISCOVER; ACK confirms the address in response to a REQUEST. A NAK refuses it. |
| O-RU | O-RAN Radio Unit; the radio hardware that obtains its management address over DHCP. |
| fronthaul | The network segment between the O-RU and the distributed unit, carrying PTP, M-Plane, and related traffic. |

### Appendix C.3: Standards Referenced

| Standard | Relevance in the toolkit |
| --- | --- |
| RFC 2131 | DHCPv4 protocol; cited for the unique-xid requirement (section 4.1) and correct client reaction to OFFERs (section 4.4.1) that the analyzer checks. |
| RFC 4361 | Node-specific DHCPv4 client identifiers (option 61); its absence is the MISSING_CLIENT_ID finding. |
| O-RAN.WG4.MP | O-RAN WG4 Management Plane specification; cited (section 6.2.4) for the client-identifier expectation on O-RU DHCP requests. |