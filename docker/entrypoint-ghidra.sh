#!/usr/bin/env bash
set -euo pipefail

export GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
export GHIDRA_PROJECT_DIR="${GHIDRA_PROJECT_DIR:-/workspace/ghidra_projects}"
export GHIDRA_SCRIPT_DIR="${GHIDRA_SCRIPT_DIR:-/opt/fwagent/ghidra_scripts}"
export MAXMEM="${MAXMEM:-4G}"

if [[ "${1:-}" == "ghidra-version" ]]; then
  exec "$GHIDRA_HOME/support/analyzeHeadless" -version
fi

exec "$@"

