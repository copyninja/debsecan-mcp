#!/usr/bin/env bash
# setup-dev-venv.sh — Create/recreate the development venv with system-site-packages
# access so that apt_pkg (from python3-apt) is importable.
#
# Run once after cloning, or after wiping the venv:
#   bash setup-dev-venv.sh
#
# Background
# ----------
# uv uses its own managed Python whose site-packages do not include the system
# dist-packages directory (/usr/lib/python3/dist-packages/).  apt_pkg lives
# there (installed by the python3-apt Debian package), so without this step
# the non-Debian origin detection falls back to dpkg-query and every package
# is treated as Debian-sourced (safe default but defeats the filtering).

set -euo pipefail

echo "Creating venv with system-site-packages..."
UV_VENV_CLEAR=1 uv venv --system-site-packages

# pyvenv.cfg created by uv's managed Python won't see /usr/lib/python3/dist-packages
# because that path belongs to the system Python's search space, not uv's.
# Explicitly enable system site-packages in the venv config so the stdlib path
# resolution picks up apt_pkg.
PYVENV_CFG=".venv/pyvenv.cfg"
if grep -q "include-system-site-packages = false" "$PYVENV_CFG"; then
    sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' "$PYVENV_CFG"
    echo "Patched pyvenv.cfg: include-system-site-packages = true"
fi

# Belt-and-suspenders: add a .pth file pointing at the system dist-packages so
# apt_pkg is always on the path even if pyvenv.cfg is reset by a future uv update.
SITE_PACKAGES=$(uv run python -c "import site; print([p for p in site.getsitepackages() if 'site-packages' in p][0])" 2>/dev/null)
PTH_FILE="${SITE_PACKAGES}/system-dist-packages.pth"
echo "/usr/lib/python3/dist-packages" > "$PTH_FILE"
echo "Created ${PTH_FILE}"

echo "Installing project dependencies..."
uv sync

echo ""
echo "Verifying apt_pkg is accessible..."
if uv run python -c "import apt_pkg" 2>/dev/null; then
    echo "  apt_pkg: OK"
else
    echo "  apt_pkg: NOT FOUND — non-Debian origin detection will use dpkg-query fallback"
fi

echo ""
echo "Dev venv ready. Run 'uv run tox' to verify all tests pass."
