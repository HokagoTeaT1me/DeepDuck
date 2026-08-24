#!/usr/bin/env bash
set -uo pipefail

FIRMWARE="${1:?usage: firmae_boot_debug.sh <firmware>}"

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
set -x
timeout 180 env PYTHONPATH=/usr/lib/python3/dist-packages \
  ./run.sh -r router "${FIRMWARE}" > /tmp/firmae-run.out 2>&1
echo "RC=$?"
tail -150 /tmp/firmae-run.out
