#!/bin/bash
# build-deb.sh -- assemble and build the dhcp-oru-toolkit .deb.
#
# Run from the repository root:
#     bash packaging/debian/build-deb.sh
# Produces: dist/dhcp-oru-toolkit_2.1.1_all.deb
#
# Pure dpkg-deb build; no debhelper required. Installs the dhcp_toolkit Python
# package under /usr/local/lib/dhcp-oru-toolkit and ships two thin python3
# wrappers (dhcp-lease-list, dhcp-forensics) to /usr/local/sbin.
set -euo pipefail

PKG="dhcp-oru-toolkit"
VERSION="2.1.1"
ARCH="all"

# --- Resolve paths (repo root = two levels up from this script) -------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEBIAN_DIR="${SCRIPT_DIR}"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

SRC_PKG="${REPO_ROOT}/src/dhcp_toolkit"
if [[ ! -d "${SRC_PKG}" ]]; then
    echo "ERROR: ${SRC_PKG} not found; run from a checkout with src/dhcp_toolkit." >&2
    exit 1
fi

BUILD_DIR="${REPO_ROOT}/build/deb"
STAGE="${BUILD_DIR}/${PKG}"
DIST="${REPO_ROOT}/dist"

LIBDIR="/usr/local/lib/${PKG}"          # where dhcp_toolkit is installed
SBINDIR="/usr/local/sbin"               # where the wrappers go
DOCDIR="/usr/share/doc/${PKG}"
MANDIR="/usr/share/man/man8"

echo ">> Cleaning staging tree ${STAGE}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/DEBIAN"
mkdir -p "${STAGE}${LIBDIR}"
mkdir -p "${STAGE}${SBINDIR}"
mkdir -p "${STAGE}${DOCDIR}"
mkdir -p "${STAGE}${MANDIR}"

# --- Copy the Python package, excluding caches ------------------------------
echo ">> Copying dhcp_toolkit package"
cp -a "${SRC_PKG}" "${STAGE}${LIBDIR}/dhcp_toolkit"
find "${STAGE}${LIBDIR}/dhcp_toolkit" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "${STAGE}${LIBDIR}/dhcp_toolkit" -type f -name '*.py[co]' -delete

# --- Write the two thin wrappers --------------------------------------------
echo ">> Writing wrappers"
cat > "${STAGE}${SBINDIR}/dhcp-lease-list" <<EOF
#!/bin/sh
# dhcp-oru-toolkit wrapper for the lease viewer.
PYTHONPATH="${LIBDIR}\${PYTHONPATH:+:\$PYTHONPATH}" \\
    exec python3 -m dhcp_toolkit.leases.cli "\$@"
EOF

cat > "${STAGE}${SBINDIR}/dhcp-forensics" <<EOF
#!/bin/sh
# dhcp-oru-toolkit wrapper for the pcap/DHCP forensics analyzer.
PYTHONPATH="${LIBDIR}\${PYTHONPATH:+:\$PYTHONPATH}" \\
    exec python3 -m dhcp_toolkit.forensics.cli "\$@"
EOF

# --- Control + maintainer scripts -------------------------------------------
echo ">> Installing control files"
install -m 0644 "${DEBIAN_DIR}/control"   "${STAGE}/DEBIAN/control"
install -m 0755 "${DEBIAN_DIR}/postinst"  "${STAGE}/DEBIAN/postinst"
install -m 0755 "${DEBIAN_DIR}/prerm"     "${STAGE}/DEBIAN/prerm"

# --- Docs: copyright + changelog (changelog gzip -9n) -----------------------
echo ">> Installing docs"
install -m 0644 "${DEBIAN_DIR}/copyright" "${STAGE}${DOCDIR}/copyright"
gzip -9nc "${DEBIAN_DIR}/changelog" > "${STAGE}${DOCDIR}/changelog.gz"

# --- Man pages (gzip -9n) ----------------------------------------------------
echo ">> Installing man pages"
gzip -9nc "${DEBIAN_DIR}/dhcp-lease-list.8" > "${STAGE}${MANDIR}/dhcp-lease-list.8.gz"
gzip -9nc "${DEBIAN_DIR}/dhcp-forensics.8"  > "${STAGE}${MANDIR}/dhcp-forensics.8.gz"

# --- Permissions ------------------------------------------------------------
echo ">> Setting permissions"
chmod 0755 "${STAGE}${SBINDIR}/dhcp-lease-list" "${STAGE}${SBINDIR}/dhcp-forensics"
find "${STAGE}${LIBDIR}" -type d -exec chmod 0755 {} +
find "${STAGE}${LIBDIR}" -type f -exec chmod 0644 {} +
chmod 0644 \
    "${STAGE}${DOCDIR}/copyright" \
    "${STAGE}${DOCDIR}/changelog.gz" \
    "${STAGE}${MANDIR}/dhcp-lease-list.8.gz" \
    "${STAGE}${MANDIR}/dhcp-forensics.8.gz"

# --- Build -------------------------------------------------------------------
echo ">> Building package"
mkdir -p "${DIST}"
OUT="${DIST}/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "${STAGE}" "${OUT}"

echo ">> Built ${OUT}"
dpkg-deb --info "${OUT}" | sed 's/^/   /'
echo ">> Contents:"
dpkg-deb --contents "${OUT}" | sed 's/^/   /'
