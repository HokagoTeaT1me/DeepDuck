#!/usr/bin/env bash
set -uo pipefail

FIRMWARE="${1:?usage: firmae_extract_debug.sh <firmware>}"

pg_ctlcluster 17 main start 2>/dev/null || service postgresql start 2>/dev/null || true
sleep 1

su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='firmadyne'\"" 2>/dev/null | grep -q 1 \
  || su postgres -c "psql -c \"CREATE USER firmadyne WITH PASSWORD 'firmadyne';\"" 2>/dev/null || true

su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='firmware'\"" 2>/dev/null | grep -q 1 \
  || {
    su postgres -c "createdb -O firmadyne firmware" 2>/dev/null || true
    su postgres -c "psql -d firmware -f /opt/FirmAE/database/schema" 2>/dev/null || true
  }

cd /opt/FirmAE
timeout 60 env PYTHONPATH=/usr/lib/python3/dist-packages \
  python ./sources/extractor/extractor.py -b tp-link -sql 127.0.0.1 -np -nk "${FIRMWARE}" images 2>&1 | tail -80
echo "RC=${PIPESTATUS[0]}"

echo "--- exact run.sh extraction command ---"
timeout --preserve-status --signal SIGINT 60 \
  env PYTHONPATH=/usr/lib/python3/dist-packages \
  ./sources/extractor/extractor.py -b router -sql 127.0.0.1 -np -nk "${FIRMWARE}" images 2>&1 >/dev/null
echo "EXACT_RC=$?"
