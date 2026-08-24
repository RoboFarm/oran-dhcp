"""dhcp-oru-toolkit: tooling for diagnosing a DHCPv4 defect on Fujitsu O-RAN radio units.

This package bundles two zero-dependency tools:

* ``dhcp_toolkit.leases``    -- an ISC/Kea DHCP lease viewer and conflict finder.
* ``dhcp_toolkit.forensics`` -- a pure-stdlib pcap/DHCP analyzer that detects the
  O-RU shared-xid / IP-theft defect described in the bug report.

Nothing is imported eagerly at package level; import the submodule you need.
"""

__version__ = "2.1.1"
