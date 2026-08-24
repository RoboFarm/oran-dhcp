# dhcp-oru-toolkit -- developer tasks
# All code is pure stdlib; tests run with or without pytest.

PY ?= python3
export PYTHONPATH := src

# User-manual sources/outputs (rendered with the bundled stdlib-only converter;
# this environment has no pandoc / LibreOffice / python-docx).
MANUAL_MD  ?= docs/USER_MANUAL.md
MANUAL_DOCX ?= docs/DHCP_Toolkit_v2.1.2_User_Manual.docx
MANUAL_TITLE ?= DHCP O-RU Toolkit v2.1.2 - User Manual
MANUAL_DATE  ?= 2026-08-24T00:00:00Z

.PHONY: test fixtures deb demo manual clean

test:
	PYTHONPATH=src $(PY) -m pytest -q tests || PYTHONPATH=src $(PY) tests/run_all.py

fixtures:
	PYTHONPATH=src $(PY) tools/make_fixtures.py

deb:
	bash packaging/debian/build-deb.sh

demo: fixtures
	PYTHONPATH=src $(PY) -m dhcp_toolkit.forensics.cli tests/fixtures/oru_xid_reuse.pcap || true
	PYTHONPATH=src $(PY) -m dhcp_toolkit.leases.cli --all --v4-lease tests/fixtures/dhcpd.leases --v6-lease tests/fixtures/dhcpd6.leases || true

manual:
	$(PY) tools/md_to_docx.py "$(MANUAL_MD)" "$(MANUAL_DOCX)" --title "$(MANUAL_TITLE)" --created "$(MANUAL_DATE)"

clean:
	rm -rf build dist *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	rm -rf .pytest_cache
