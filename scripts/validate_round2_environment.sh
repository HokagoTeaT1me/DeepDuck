#!/usr/bin/env bash
set -uo pipefail

RET2TEXT_PATH="${RET2TEXT_PATH:-/samples/ret2text}"
FIRMWARE_PATH="${FIRMWARE_PATH:-/samples/firmware.bin}"
VALIDATION_WORKSPACE="${VALIDATION_WORKSPACE:-/work/workspace/docker-validation}"
LOG_PATH="${LOG_PATH:-/work/logs/environment_validation.md}"
REPORT_PATH="${REPORT_PATH:-/work/reports/round2_validation.md}"

mkdir -p "$(dirname "$LOG_PATH")" "$(dirname "$REPORT_PATH")" "$VALIDATION_WORKSPACE"

PASS_COUNT=0
FAIL_COUNT=0
BLOCKED_COUNT=0
TEST_RESULTS=()

log() {
  printf '%s\n' "$*" | tee -a "$LOG_PATH" >/dev/null
}

record_result() {
  local name="$1"
  local status="$2"
  local detail="$3"
  TEST_RESULTS+=("${status}|${name}|${detail}")
  case "$status" in
    PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    BLOCKED) BLOCKED_COUNT=$((BLOCKED_COUNT + 1)) ;;
  esac
  log "- ${name}: ${status} - ${detail}"
}

run_capture() {
  local output_file="$1"
  shift
  "$@" >"$output_file" 2>&1
}

json_value() {
  local file="$1"
  local expr="$2"
  python - "$file" "$expr" <<'PY'
import json
import sys

path, expr = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
value = data
for part in expr.split("."):
    if part == "":
        continue
    if isinstance(value, list):
        value = value[int(part)]
    else:
        value = value.get(part)
print("" if value is None else value)
PY
}

latest_analysis_json() {
  find "$VALIDATION_WORKSPACE" -path '*/reports/analysis.json' -type f -printf '%T@ %p\n' \
    | sort -nr \
    | head -n 1 \
    | cut -d' ' -f2-
}

write_header() {
  cat >"$LOG_PATH" <<EOF
# Round 2 Environment Validation

- Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- Image runtime: Docker container
- Ret2text: ${RET2TEXT_PATH}
- Firmware: ${FIRMWARE_PATH}
- Workspace: ${VALIDATION_WORKSPACE}

EOF
}

write_header

log "## 1. Ghidra Environment Smoke Test"
DOCTOR_OUT="$VALIDATION_WORKSPACE/doctor.out"
if run_capture "$DOCTOR_OUT" fwagent doctor; then
  record_result "fwagent doctor" "PASS" "environment reports READY"
else
  record_result "fwagent doctor" "FAIL" "environment doctor failed"
fi
log '```text'
cat "$DOCTOR_OUT" | tee -a "$LOG_PATH" >/dev/null
log '```'

log ""
log "### Runtime Tool Versions"
for tool_spec in \
  "java -version|strict" \
  "${GHIDRA_HOME:-/opt/ghidra}/support/analyzeHeadless -version|output" \
  "unblob --help|strict" \
  "binwalk --help|strict" \
  "unsquashfs -version|output" \
  "7z i|strict" \
  "file --version|strict" \
  "readelf --version|strict" \
  "objdump --version|strict"; do
  IFS='|' read -r tool_command result_mode <<<"$tool_spec"
  TOOL_OUT="$VALIDATION_WORKSPACE/tool-$(printf '%s' "$tool_command" | tr '/ -' '___' | tr -cd 'A-Za-z0-9_.').out"
  if bash -lc "$tool_command" >"$TOOL_OUT" 2>&1; then
    FIRST_LINE="$(head -n 1 "$TOOL_OUT" | tr -d '\r')"
    record_result "tool ${tool_command}" "PASS" "${FIRST_LINE:-available}"
  elif [[ "$result_mode" == "output" && -s "$TOOL_OUT" ]]; then
    FIRST_LINE="$(head -n 1 "$TOOL_OUT" | tr -d '\r')"
    record_result "tool ${tool_command}" "PASS" "${FIRST_LINE:-available} (non-zero version exit accepted)"
  else
    record_result "tool ${tool_command}" "FAIL" "command failed; see ${TOOL_OUT}"
  fi
done

HEADLESS_OUT="$VALIDATION_WORKSPACE/analyzeHeadless.out"
"${GHIDRA_HOME:-/opt/ghidra}/support/analyzeHeadless" >"$HEADLESS_OUT" 2>&1
HEADLESS_EXIT=$?
if grep -qi "usage\|analyzeHeadless" "$HEADLESS_OUT"; then
  record_result "Ghidra analyzeHeadless usage" "PASS" "headless launcher produced usage/help output (exit ${HEADLESS_EXIT})"
else
  record_result "Ghidra analyzeHeadless usage" "FAIL" "headless launcher did not produce recognizable usage output"
fi

log ""
log "## 2. ret2text Ghidra Test"
RET_ANALYZE_JSON="$VALIDATION_WORKSPACE/ret2text-analyze.json"
if [[ ! -f "$RET2TEXT_PATH" ]]; then
  record_result "ret2text input" "BLOCKED" "missing ${RET2TEXT_PATH}"
else
  if run_capture "$RET_ANALYZE_JSON" fwagent binary analyze "$RET2TEXT_PATH" --workspace "$VALIDATION_WORKSPACE" --force --no-fallback; then
    RET_SUCCESS="$(json_value "$RET_ANALYZE_JSON" success)"
    RET_LANG="$(json_value "$RET_ANALYZE_JSON" result.summary.language)"
    RET_FUNCS="$(json_value "$RET_ANALYZE_JSON" result.summary.function_count)"
    if [[ "$RET_SUCCESS" == "True" || "$RET_SUCCESS" == "true" ]]; then
      record_result "ret2text Ghidra import" "PASS" "language=${RET_LANG}; functions=${RET_FUNCS}"
    else
      record_result "ret2text Ghidra import" "FAIL" "tool returned success=false"
    fi
  else
    record_result "ret2text Ghidra import" "FAIL" "fwagent binary analyze failed"
  fi

  RET_META_OUT="$VALIDATION_WORKSPACE/ret2text-metadata.out"
  python - "$RET_ANALYZE_JSON" >"$RET_META_OUT" 2>&1 <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
result = data.get("result", {})
functions = result.get("functions", [])
names = {item.get("name") for item in functions}
callgraph = result.get("callgraph", [])
refs = [edge for edge in callgraph if "system" in str(edge.get("callee", "")) or edge.get("caller") == "main"]
print(f"Architecture: {result.get('summary', {}).get('language')}")
print(f"Function count: {len(functions)}")
print(f"Has main: {'main' in names}")
print(f"User functions: {', '.join(sorted(name for name in names if name in {'main', 'secure', 'vulnerable'}))}")
print(f"Call/reference edges: {len(refs)}")
if not functions or 'main' not in names:
    raise SystemExit(1)
PY
  if [[ $? -eq 0 ]]; then
    record_result "ret2text functions/references" "PASS" "$(tr '\n' '; ' < "$RET_META_OUT")"
  else
    record_result "ret2text functions/references" "FAIL" "$(tr '\n' '; ' < "$RET_META_OUT")"
  fi

  RET_DECOMP_JSON="$VALIDATION_WORKSPACE/ret2text-decompile.json"
  if run_capture "$RET_DECOMP_JSON" fwagent binary decompile "$RET2TEXT_PATH" main --workspace "$VALIDATION_WORKSPACE"; then
    DECOMP_SUCCESS="$(json_value "$RET_DECOMP_JSON" success)"
    CODE_PRESENT="$(python - "$RET_DECOMP_JSON" <<'PY'
import json, sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
code=(data.get("result") or {}).get("decompiled_code") or ""
print("yes" if len(code.strip()) > 0 else "no")
PY
)"
    if [[ "$DECOMP_SUCCESS" == "True" || "$DECOMP_SUCCESS" == "true" ]] && [[ "$CODE_PRESENT" == "yes" ]]; then
      record_result "ret2text decompile" "PASS" "main decompiled"
    else
      record_result "ret2text decompile" "FAIL" "decompile success=${DECOMP_SUCCESS}; code_present=${CODE_PRESENT}"
    fi
  else
    record_result "ret2text decompile" "FAIL" "fwagent binary decompile command failed"
  fi
fi

log ""
log "## 3. Firmware Extraction Test"
FIRMWARE_ANALYZE_OUT="$VALIDATION_WORKSPACE/firmware-analyze.out"
FIRMWARE_REPORT=""
if [[ ! -f "$FIRMWARE_PATH" ]]; then
  record_result "firmware input" "BLOCKED" "missing ${FIRMWARE_PATH}"
else
  if run_capture "$FIRMWARE_ANALYZE_OUT" fwagent analyze "$FIRMWARE_PATH" --workspace "$VALIDATION_WORKSPACE" --timeout 900; then
    FIRMWARE_REPORT="$(latest_analysis_json)"
    if [[ -n "$FIRMWARE_REPORT" && -f "$FIRMWARE_REPORT" ]]; then
      EXTRACTION_SUCCESS="$(json_value "$FIRMWARE_REPORT" extraction.success)"
      ROOTFS="$(json_value "$FIRMWARE_REPORT" extraction.rootfs)"
      FILES="$(json_value "$FIRMWARE_REPORT" filesystem.total_files)"
      if [[ "$EXTRACTION_SUCCESS" == "True" || "$EXTRACTION_SUCCESS" == "true" ]] && [[ -d "$ROOTFS" ]]; then
        record_result "firmware extraction" "PASS" "rootfs=${ROOTFS}; files=${FILES}"
      else
        record_result "firmware extraction" "FAIL" "rootfs not extracted; report=${FIRMWARE_REPORT}"
      fi
    else
      record_result "firmware extraction" "FAIL" "analysis.json not found"
    fi
  else
    record_result "firmware extraction" "FAIL" "fwagent analyze failed"
  fi
fi

log ""
log "## 4. RootFS ELF Inventory"
if [[ -n "$FIRMWARE_REPORT" && -f "$FIRMWARE_REPORT" ]]; then
  ELF_COUNT="$(json_value "$FIRMWARE_REPORT" filesystem.elf_files)"
  ARCH="$(json_value "$FIRMWARE_REPORT" platform.architecture)"
  ROOTFS="$(json_value "$FIRMWARE_REPORT" extraction.rootfs)"
  if [[ "${ELF_COUNT:-0}" =~ ^[0-9]+$ ]] && [[ "$ELF_COUNT" -gt 0 ]]; then
    record_result "rootfs ELF inventory" "PASS" "elf_count=${ELF_COUNT}; architecture=${ARCH}; rootfs=${ROOTFS}"
  else
    record_result "rootfs ELF inventory" "FAIL" "no ELF files discovered"
  fi
else
  record_result "rootfs ELF inventory" "BLOCKED" "firmware analysis report unavailable"
fi

log ""
log "## 5. Top-priority ELF Ghidra Test"
TOP3_FILE="$VALIDATION_WORKSPACE/top3.txt"
if [[ -n "$FIRMWARE_REPORT" && -f "$FIRMWARE_REPORT" ]]; then
  python - "$FIRMWARE_REPORT" >"$TOP3_FILE" <<'PY'
import json
import os
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    report = json.load(handle)
rootfs = report.get("extraction", {}).get("rootfs")
for item in report.get("priority_binaries", [])[:3]:
    path = item.get("path")
    if not path:
        continue
    resolved = os.path.join(rootfs, path.lstrip("/")) if rootfs and path.startswith("/") else path
    print(f"{path}|{resolved}|{item.get('score')}")
PY
  if [[ -s "$TOP3_FILE" ]]; then
    TOP_PASS=0
    while IFS='|' read -r report_path resolved score; do
      [[ -z "$resolved" ]] && continue
      OUT_JSON="$VALIDATION_WORKSPACE/ghidra-$(basename "$resolved").json"
      if run_capture "$OUT_JSON" fwagent binary analyze "$resolved" --workspace "$VALIDATION_WORKSPACE" --force --no-fallback; then
        SUCCESS="$(json_value "$OUT_JSON" success)"
        FUNCS="$(json_value "$OUT_JSON" result.summary.function_count)"
        if [[ "$SUCCESS" == "True" || "$SUCCESS" == "true" ]] && [[ "${FUNCS:-0}" =~ ^[0-9]+$ ]] && [[ "$FUNCS" -gt 0 ]]; then
          record_result "firmware Ghidra ${report_path}" "PASS" "score=${score}; functions=${FUNCS}"
          TOP_PASS=$((TOP_PASS + 1))
        else
          record_result "firmware Ghidra ${report_path}" "FAIL" "analysis success=${SUCCESS}; functions=${FUNCS}"
        fi
      else
        record_result "firmware Ghidra ${report_path}" "FAIL" "fwagent binary analyze failed"
      fi
    done <"$TOP3_FILE"
    if [[ "$TOP_PASS" -gt 0 ]]; then
      record_result "top-priority ELF Ghidra aggregate" "PASS" "${TOP_PASS} top-priority binaries analyzed"
    else
      record_result "top-priority ELF Ghidra aggregate" "FAIL" "no top-priority binary completed Ghidra analysis"
    fi
  else
    record_result "top-priority ELF Ghidra aggregate" "BLOCKED" "no priority binaries in firmware report"
  fi
else
  record_result "top-priority ELF Ghidra aggregate" "BLOCKED" "firmware analysis report unavailable"
fi

log ""
log "## 6. Project Tests"
UNITTEST_OUT="$VALIDATION_WORKSPACE/unittest.out"
if run_capture "$UNITTEST_OUT" python -m unittest discover -s /work/tests -p 'test_*.py'; then
  record_result "project unittest suite" "PASS" "$(tail -n 1 "$UNITTEST_OUT" | tr -d '\r')"
else
  record_result "project unittest suite" "FAIL" "unit tests failed; see ${UNITTEST_OUT}"
fi

FINAL_STATUS="ROUND 2 READY"
if [[ "$FAIL_COUNT" -gt 0 || "$BLOCKED_COUNT" -gt 0 ]]; then
  FINAL_STATUS="ROUND 2 PARTIALLY READY"
fi
if [[ "$BLOCKED_COUNT" -gt 0 && "$PASS_COUNT" -eq 0 ]]; then
  FINAL_STATUS="ROUND 2 BLOCKED"
fi

{
  echo "# Round 2 Validation Report"
  echo
  echo "## 1. Changes"
  echo
  echo "- Docker runtime validation executed inside the analysis image."
  echo "- Detailed command output is in ${LOG_PATH}."
  echo
  echo "## 2. Docker"
  echo
  echo "- Build: recorded by host build log"
  echo "- Image: ${FWAGENT_IMAGE:-fwagent-round2:latest}"
  echo
  echo "## 3. Environment"
  echo
  grep '^\[.*\]' "$DOCTOR_OUT" || true
  echo
  echo "## 4. ret2text"
  echo
  for row in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r status name detail <<<"$row"
    [[ "$name" == ret2text* ]] && echo "- ${name}: ${status} - ${detail}"
  done
  echo
  echo "## 5. Firmware"
  echo
  for row in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r status name detail <<<"$row"
    [[ "$name" == firmware* || "$name" == rootfs* ]] && echo "- ${name}: ${status} - ${detail}"
  done
  echo
  echo "## 6. Firmware Ghidra"
  echo
  for row in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r status name detail <<<"$row"
    [[ "$name" == firmware\ Ghidra* || "$name" == top-priority* ]] && echo "- ${name}: ${status} - ${detail}"
  done
  echo
  echo "## 7. Agent"
  echo
  if [[ "$FAIL_COUNT" -eq 0 && "$BLOCKED_COUNT" -eq 0 ]]; then
    echo "- Pi integration: NOT EXECUTED in this validation pass."
  else
    echo "- Pi integration: BLOCKED until Docker, ret2text, firmware extraction, and firmware Ghidra gates pass."
  fi
  echo
  echo "## 8. Tests"
  echo
  for row in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r status name detail <<<"$row"
    echo "- ${status}: ${name} - ${detail}"
  done
  echo
  echo "## 9. Remaining Problems"
  if [[ "$FAIL_COUNT" -eq 0 && "$BLOCKED_COUNT" -eq 0 ]]; then
    echo "- None."
  else
    for row in "${TEST_RESULTS[@]}"; do
      IFS='|' read -r status name detail <<<"$row"
      if [[ "$status" == "FAIL" || "$status" == "BLOCKED" ]]; then
        echo "- ${status}: ${name} - ${detail}"
      fi
    done
  fi
  echo
  echo "## 10. Final Status"
  echo
  echo "${FINAL_STATUS}"
} >"$REPORT_PATH"

log ""
log "## Final Status"
log "- PASS: ${PASS_COUNT}"
log "- FAIL: ${FAIL_COUNT}"
log "- BLOCKED: ${BLOCKED_COUNT}"
log "- ${FINAL_STATUS}"

if [[ "$FAIL_COUNT" -gt 0 || "$BLOCKED_COUNT" -gt 0 ]]; then
  exit 1
fi
exit 0
