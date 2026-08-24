#!/usr/bin/env bash
set -uo pipefail

pg_ctlcluster 17 main start 2>/dev/null || service postgresql start 2>/dev/null || true
sleep 1

echo "postgres roles:"
su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='firmadyne'\"" 2>&1 || true

echo "binwalk import:"
PYTHONPATH=/opt/FirmAE/binwalk-2.3.4:/usr/lib/python3/dist-packages \
  python -c "import binwalk, magic; print(binwalk.__file__); print(magic.__file__)" 2>&1 || true

echo "done"
