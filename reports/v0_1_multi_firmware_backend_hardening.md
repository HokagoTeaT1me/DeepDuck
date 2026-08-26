# DeepDuck V0.1 Multi-Firmware Backend Hardening

Generated: 2026-08-26

## Executive Summary

This pass hardened DeepDuck's local firmware backend across TP-Link SR20, D-Link DIR-815, and Huawei HG532e firmware families. The original MIPS Ghidra issue was reproduced and narrowed down to runtime/cache/script integration rather than unsupported MIPS binaries. After fixes, D-Link MIPS little-endian and Huawei MIPS big-endian binaries both complete real Dockerized Ghidra analysis with zero fallback.

No new vulnerability claims were promoted in this pass. Dynamic validation and model-backed validation were intentionally not executed in the multi-firmware regression runs, so all reported security outcomes remain conservative.

## Scope

- Preserve the existing DeepDuck architecture and conservative finding semantics.
- Improve Windows + Docker Desktop behavior for real firmware extraction and binary analysis.
- Diagnose MIPS Ghidra failures before changing higher-level pipeline behavior.
- Keep local-only firmware validation: no public probing, exploit attempts, RCE, brute force, or unsafe network behavior.

## Changes Implemented

### Ghidra Runtime

- Updated `ExportStrings.java` for Ghidra 12.1.3 by replacing the removed `DefinedDataIterator.definedStrings(...)` API with `DefinedDataIterator.byDataInstance(...)`.
- Hardened all Ghidra JSON exporters to escape all JSON control characters, not only quotes/newlines.
- Added execution metadata for real Ghidra runs, including backend, exit code, timeout flag, duration, and Docker worker image.
- Bumped the Ghidra cache configuration version to invalidate stale static-fallback cache entries produced before the exporter/runtime fixes.

### RootFS Semantics

- Added explicit RootFS artifact fields for canonical Linux rootfs, host readability, host-safe view, Linux semantic preservation, and semantic fidelity.
- Hardened Windows traversal against inaccessible Linux symlink/reparse-point artifacts created by Docker/SquashFS extraction.
- Updated filesystem inventory, service discovery, secret scanning, rootfs validation, and target selection to use safe path probing.
- Refreshed existing DIR-815/HG532e artifacts so Huawei keeps the canonical Linux rootfs distinct from the host-safe copy.

### Extraction Backend

- Added `liblzma-dev` to the Docker worker build so `sasquatch` can compile with XZ/LZMA support.
- Confirmed `sasquatch`, JDK 21, and Ghidra 12.1.3 are available in `fwagent-round2:latest`.
- Replaced Docker extraction shell invocation with direct argv execution, fixing vendor filenames containing parentheses such as `SR20(US)_V1_180518.zip`.
- Added archive-contained firmware fallback: when a vendor archive extracts to an embedded firmware image but no rootfs, DeepDuck retries the embedded image through Docker/binwalk.

## Root Cause Findings

### MIPS Ghidra

The failure was not a MIPS architecture limitation. Direct and product-level tests confirmed:

- D-Link DIR-815 `/sbin/httpd`: `MIPS:LE:32:default`, Dockerized Ghidra exit code `0`.
- Huawei HG532e `/bin/telnetd`: `MIPS:BE:32:default`, Dockerized Ghidra exit code `0`.

The previous 0-real-Ghidra state was caused by stale fallback cache entries and runtime environment failures, including Docker permission/cache state and a Ghidra 12.1.3 script API mismatch.

### Windows RootFS Traversal

Huawei extraction exposed Windows host limitations around Linux symlink/reparse-point files, especially direct probes of paths such as `/etc/passwd`. The pipeline now treats these as semantic Linux rootfs artifacts and skips inaccessible reparse entries during host-side inventory instead of failing the pipeline.

### Archive Wrapper Extraction

TP-Link SR20 was available locally as a vendor ZIP, while the originally referenced `.bin` path was absent. The ZIP contains the real firmware image plus a license PDF. DeepDuck now detects and retries embedded firmware images after archive extraction.

## Validation Matrix

| Firmware | Task ID | Input | Arch | Endian | RootFS Files | ELF | Web | Extraction | Ghidra Real | Fallback | Findings |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| TP-Link SR20 | `tplink-sr20-hardening-bin-01` | extracted `.bin` | ARM | little | 2165 | 457 | 596 | `docker-binwalk` | 27/27 | 0 | 0 |
| TP-Link SR20 ZIP | `tplink-sr20-hardening-zip-01` | vendor ZIP | ARM | little | 2165 | 457 | 596 | `embedded-docker-binwalk` | skipped fast mode | 0 | 0 |
| D-Link DIR-815 | `dir815-hardening-02` | `.bin` | MIPS | little | 1199 | 150 | 934 | `docker-binwalk` | 14/14 | 0 | 0 |
| Huawei HG532e | `hg532e-hardening-03` | `.bin` | MIPS | big | 106 | 74 | 0 | `docker-binwalk` | 16/16 | 0 | 0 |

## Generated Reports

- `workspace/tplink-sr20-hardening-bin-01/reports/report.md`
- `workspace/tplink-sr20-hardening-bin-01/reports/report.json`
- `workspace/tplink-sr20-hardening-bin-01/reports/report.html`
- `workspace/tplink-sr20-hardening-zip-01/reports/report.md`
- `workspace/dir815-hardening-02/reports/report.md`
- `workspace/dir815-hardening-02/reports/report.json`
- `workspace/dir815-hardening-02/reports/report.html`
- `workspace/hg532e-hardening-03/reports/report.md`
- `workspace/hg532e-hardening-03/reports/report.json`
- `workspace/hg532e-hardening-03/reports/report.html`

## Test Coverage

Targeted regression tests were added or updated for:

- Ghidra cache version invalidation.
- No-fallback Ghidra failure metadata.
- Windows reparse-point traversal safety.
- Secret scanning around inaccessible `/etc/passwd`.
- RootFS artifact host-safe view separation.
- Docker extraction argv handling for filenames with parentheses.
- Embedded firmware fallback after archive extraction.

Validation command:

```powershell
python -m unittest tests.unit.test_v01_extraction_recovery tests.unit.test_filesystem tests.unit.test_ghidra_runtime tests.unit.test_ghidra_api -v
```

Result: 48 tests passed, 2 skipped due Windows symlink privilege limitations.

Full regression command:

```powershell
python -m unittest discover -v
```

Result: 572 tests passed, 8 skipped for disabled real-provider/real-dynamic acceptance gates and Windows symlink privilege limitations.

## Residual Gaps

- The multi-firmware regression runs used `--no-dynamic`; runtime validation remains intentionally skipped for this pass.
- Provider/model-backed report generation remains deferred.
- The host Java warning still appears because the host has Java 11, but Dockerized Ghidra uses JDK 21 and completes successfully.
- Ghidra emits a harmless hostname warning under `--network none`; analysis exit codes remain `0`.

## Conclusion

DeepDuck now handles the tested ARM, MIPS little-endian, and MIPS big-endian firmware paths with real Dockerized Ghidra analysis and no static fallback for scheduled deep-static targets. The extraction backend is more resilient on Windows, including legacy SquashFS/LZMA recovery, archive-contained firmware retry, and Linux rootfs semantic separation from host-safe views.
