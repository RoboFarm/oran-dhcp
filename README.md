# dhcp-oru-toolkit

Zero-dependency (pure Python standard library) tooling for operating and
troubleshooting DHCP on **Fujitsu O-RAN radio units (O-RUs)**. It bundles two
command-line tools:

- **`dhcp-lease-list`** — a unified ISC/Kea DHCP lease viewer (IPv4 + IPv6) with
  a `--conflicts` mode that flags the lease-table symptoms of the O-RU defect.
- **`dhcp-forensics`** — a pure-stdlib pcap/DHCP analyzer that decodes a capture
  and detects the O-RU DHCPv4 transaction-id (xid) reuse / IP-theft defect.

No third-party packages are required. There is **no** dependency on scapy,
dpkt, tshark, or tcpdump — all pcap and DHCP parsing is done with the Python
standard library.

## The bug, in three sentences

When several FJ-series O-RUs boot on the same Layer 2 segment, they all emit the
**same DHCPv4 transaction-id (xid)**, so each unit reacts to broadcast OFFERs
meant for other units and races to REQUEST the offered IP. The fastest unit
steals addresses — accumulating multiple leases while other units get none —
because the O-RUs also **accept OFFERs whose `chaddr` is not their own** and send
**no option 61 client-identifier** for the server to disambiguate them. DHCPv6 is
unaffected, because each unit uses a unique DUID + IAID.

See [`docs/oru_dhcpv4_xid_bug_report.md`](docs/oru_dhcpv4_xid_bug_report.md) for
the full report, and [`docs/ANALYSIS.md`](docs/ANALYSIS.md) for what the uploaded
capture actually contains.

## Repository layout

```
src/dhcp_toolkit/
  leases/        ISC/Kea lease parsers, display, conflict finder, CLI
  forensics/     pcap reader, DHCPv4/v6 decoders, transaction grouping,
                 defect detectors, report rendering, CLI
configs/         example ISC dhcpd.conf / dhcpd6.conf (O-RAN vendor-class match)
samples/         oru_real_capture.pcap  (the O-RU's own fronthaul capture)
tools/           make_fixtures.py  (writes deterministic test pcaps/leases)
tests/           unit tests + run_all.py (stdlib runner; pytest optional)
  fixtures/      oru_xid_reuse.pcap (synthesized), clean_dhcp.pcap, lease files
packaging/debian/  control, postinst, prerm, man pages, build-deb.sh
docs/            bug report (Markdown) and capture analysis
```

## Install

### From source (editable)

```sh
pip install -e .
```

This exposes `dhcp-lease-list` and `dhcp-forensics` on your `PATH`.

To run straight from a checkout without installing, set `PYTHONPATH`:

```sh
PYTHONPATH=src python3 -m dhcp_toolkit.leases.cli --help
PYTHONPATH=src python3 -m dhcp_toolkit.forensics.cli --help
```

### From the Debian package

```sh
bash packaging/debian/build-deb.sh          # -> dist/dhcp-oru-toolkit_2.0.0_all.deb
sudo dpkg -i dist/dhcp-oru-toolkit_2.0.0_all.deb
```

The package installs the `dhcp_toolkit` Python package under
`/usr/local/lib/dhcp-oru-toolkit` and two thin `python3` wrappers
(`dhcp-lease-list`, `dhcp-forensics`) into `/usr/local/sbin`. Man pages are
installed in section 8: `man 8 dhcp-lease-list`, `man 8 dhcp-forensics`.

## Usage

### `dhcp-lease-list` — view leases and find conflicts

```
$ dhcp-lease-list --all --v4-lease tests/fixtures/dhcpd.leases --v6-lease tests/fixtures/dhcpd6.leases

=== ISC DHCP Unified Lease List  v2.0.0 ===
Active leases shown. Use --all to include expired/free.

[ DHCPv4 Leases ]  file: tests/fixtures/dhcpd.leases  total: 4  active: 3
IP Address       MAC / DUID          Hostname   State    Expires (UTC)         Vendor Class
-------------------------------------------------------------------------------------------
192.168.36.160   34:fe:9e:3d:af:5c   -          free     2020/01/01 00:00:00   -
192.168.36.170   34:fe:9e:3d:ad:a8   oru-ada8   active   2099/12/31 23:59:59   o-ran-ru2/FJ/44R26-N25N66-DC/A2256600363
192.168.36.171   34:fe:9e:3d:ad:c8   oru-adc8   active   2099/12/31 23:59:59   o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222
192.168.36.172   34:fe:9e:3d:ad:c8   oru-adc8   active   2099/12/31 23:59:59   o-ran-ru2/FJ/44R26-N25N66-DC/A2256600222
```

Add `--conflicts` to flag the IP-theft signature (one MAC holding several active
IPs, or one IP held by several active MACs). Exit status is `2` when a HIGH
conflict is found:

```
$ dhcp-lease-list --conflicts --v4-lease tests/fixtures/dhcpd.leases --v6-lease tests/fixtures/dhcpd6.leases
...
[ Lease Conflicts ]
  [HIGH] mac_multiple_active_ips: MAC 34:fe:9e:3d:ad:c8 holds 2 distinct active IPv4 addresses: 192.168.36.171, 192.168.36.172
```

Other useful flags: `--server {isc,kea}`, `--v4-only`, `--v6-only`,
`--state {active,free,expired,declined,released}`, `--version`. See
`man 8 dhcp-lease-list`.

### `dhcp-forensics` — analyze a capture for the defect

On the **real uploaded capture** (the O-RU's own fronthaul dump), the tool
honestly reports that there is no DHCPv4 traffic to judge:

```
$ dhcp-forensics samples/oru_real_capture.pcap
...
Note        : capture contains no DHCPv4 traffic; DHCPv4 defect cannot be observed in this file
Verdict     : NO DHCPv4 TRAFFIC
Total frames : 555
DHCPv4 msgs  : 0
DHCPv6 msgs  : 1
Ethertypes   : 0x88f7=539, 0x8809=10, 0x86dd=5, 0x0800=1
```

On the **synthesized reproduction fixture** (rebuilt from the bug report's
documented packet sequences), it flags all three defects and exits `2`:

```
$ dhcp-forensics tests/fixtures/oru_xid_reuse.pcap
...
VERDICT: AFFECTED   (HIGH=10, MEDIUM=0, LOW=0, INFO=0)
  [SHARED_XID]             xid 0x8fc37a94 / 0xcb07f611 shared across units (RFC 2131 4.1)
  [FOREIGN_OFFER_REACTION] units REQUEST an IP OFFERed to another chaddr (RFC 2131 4.4.1)
  [MISSING_CLIENT_ID]      no DHCPv4 option 61 present (RFC 4361 / O-RAN.WG4.MP 6.2.4)
  [DUPLICATE_GRANT_MAC]    one MAC granted .171 and .172
  [DUPLICATE_GRANT_IP]     one IP contested by multiple MACs (IP theft)
```

Flags: `--json` (machine-readable report), `--leases FILE` (cross-check granted
IPs against a lease database), `--config FILE` (map vendor classes / pools from
an ISC `dhcpd.conf`), `--no-color`. Exit status is `0` when there are no HIGH
findings and `2` otherwise. See `man 8 dhcp-forensics`.

> **Important:** the uploaded `packets.pcap` does **not** contain the DHCPv4
> evidence — that lives in a server-side `dhcpv4_debug.pcap` which was not
> uploaded. `tests/fixtures/oru_xid_reuse.pcap` is a faithful synthesized
> reconstruction used to validate the analyzer. Full details in
> [`docs/ANALYSIS.md`](docs/ANALYSIS.md).

## Running the tests

Tests are pure stdlib and run with or without `pytest`:

```sh
make test          # uses pytest if available, else tests/run_all.py
# or directly:
PYTHONPATH=src python3 tests/run_all.py
```

Regenerate the deterministic fixtures with `make fixtures`, and a quick
end-to-end demo with `make demo`.

## Documentation

- [`docs/USER_MANUAL.md`](docs/USER_MANUAL.md) — the full operator user manual
  (install, both command references, supported formats, tutorials, FAQ). This is
  the source for the bundled Word version,
  `docs/DHCP_Toolkit_v2.0.0_User_Manual.docx`.
- [`docs/oru_dhcpv4_xid_bug_report.md`](docs/oru_dhcpv4_xid_bug_report.md) —
  the full bug report (unit/MAC table, both transaction sequences, standards
  violations, recommended fixes).
- [`docs/ANALYSIS.md`](docs/ANALYSIS.md) — what the uploaded capture really
  contains and how the analyzer is validated.
- `man 8 dhcp-lease-list`, `man 8 dhcp-forensics` — command reference.

### Rebuilding the Word manual

The `.docx` is generated from `docs/USER_MANUAL.md` by a dependency-free
converter (`tools/md_to_docx.py`) — no pandoc, LibreOffice, or `python-docx`
required:

```sh
make manual         # renders docs/DHCP_Toolkit_v2.0.0_User_Manual.docx
```

Edit the Markdown and re-run `make manual` to refresh the Word document.

## License

MIT. See [`LICENSE`](LICENSE).
