#!/usr/bin/env bash
set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
GHIDRA_PROJECT_DIR="${GHIDRA_PROJECT_DIR:-/workspace/ghidra_projects}"
GHIDRA_SCRIPT_DIR="${GHIDRA_SCRIPT_DIR:-/opt/fwagent/ghidra_scripts}"

java -version >/tmp/fwagent-java-version.txt 2>&1

test -d "$GHIDRA_HOME"
test -x "$GHIDRA_HOME/support/analyzeHeadless"
test -d "$GHIDRA_SCRIPT_DIR"
test -r "$GHIDRA_SCRIPT_DIR/ExportBinarySummary.java"

mkdir -p "$GHIDRA_PROJECT_DIR"
touch "$GHIDRA_PROJECT_DIR/.fwagent-write-test"
rm "$GHIDRA_PROJECT_DIR/.fwagent-write-test"

"$GHIDRA_HOME/support/analyzeHeadless" -version >/tmp/fwagent-ghidra-version.txt 2>&1

echo "Ghidra environment OK"

