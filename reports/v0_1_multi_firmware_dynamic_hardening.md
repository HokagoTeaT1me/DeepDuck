# DeepDuck V0.1 Multi-Firmware Dynamic Validation Hardening

Date: 2026-08-28
Scope: local authorized TP-Link SR20, D-Link DIR-815, and Huawei HG532e firmware only

## Outcome

DeepDuck now makes an evidence-driven distinction between executable feasibility, service progress, endpoint reachability, request delivery, and response observation. Both MIPS endian variants executed real firmware binaries in the actual `fwagent-round2:latest` Docker worker. No application response was forced for D-Link or Huawei: D-Link reached a stable firmware `httpd` process without a trustworthy configuration-derived endpoint, while Huawei reached real `upnp` syscalls and stopped at a verified missing vendor Unix-domain IPC endpoint.

Final status: **DEEPDUCK V0.1 MULTI-FIRMWARE DYNAMIC BACKEND HARDENED**.

## Regression matrix

| Firmware | Architecture | Static Ghidra | Selected Dynamic Service | Runtime Backend | Binary Smoke | Process Started | Endpoint Established | Request Sent | Response Observed | RuntimeRepair | Real DynamicEvidence | Dynamic Status | Findings |
|---|---|---:|---|---|---|---|---|---|---|---|---:|---|---:|
| TP-Link SR20 | ARM32 little-endian | PASS — 27/27 real, 0 fallback | `device_manager.fcgi` via `/services/device_manager/` | FastCGI integration | PASS | YES | YES | YES | YES — application SOAP fault behavior observed | `RR-3501` | 4 | FEASIBLE / response observed | 0 |
| D-Link DIR-815 | MIPS32 little-endian | PASS — 14/14 real, 0 fallback | `httpd` (`/sbin/httpd`) | Service-QEMU (`qemu-mipsel-static`) | PASS | YES | NO | NO | NO | `RR-0001`–`RR-0003` | 7 | PARTIAL / process started | 0 |
| Huawei HG532e | MIPS32 big-endian | PASS — 16/16 real, 0 fallback | `upnp` (`/bin/upnp`) | Service-QEMU (`qemu-mips-static`) | PASS | YES | NO | NO | NO | `RR-0001`–`RR-0003` | 2 | PARTIAL / process started; IPC blocked | 0 |

The TP-Link static count is from `workspace/tplink-sr20-hardening-bin-01`; its accepted dynamic regression is preserved in `workspace/v0_1-final-dynamic-01`.

## Why prior D-Link and Huawei runs had no runtime observations

The earlier absence of observations was orchestration state, not proof of emulator failure. In both workspaces, `INVESTIGATION` and `DYNAMIC_VALIDATION` were explicitly skipped by `--no-dynamic`. Their prioritization queues also had no validation hypotheses to schedule. The hardening pass therefore began from the existing static service and RootFS evidence and performed a bounded deterministic feasibility assessment; it did not fabricate a validation plan to fill an empty stage.

## Service selection and feasibility

### D-Link DIR-815

Static service evidence identified `upnp` from an init script, `/usr/sbin/dnsmasq`, `/sbin/httpd`, and `/usr/sbin/telnetd`. The generic selector chose `httpd` because it was the strongest discovered web-service candidate with a present executable. This was not selected because of dangerous imports.

Dependency chain:

1. Canonical Linux-semantic RootFS selected through `workspace_relative_path`; the host-safe view was not used.
2. MIPS32 little-endian mapped to `qemu-mipsel-static`.
3. ELF interpreter `/lib/ld-uClibc.so.0` resolved.
4. Required libraries `libcrypt.so.0`, `libgcc_s.so.1`, and `libc.so.0` resolved.
5. `/bin/busybox` loaded and exited normally in the benign smoke test.
6. `/sbin/httpd` remained alive beyond the two-second stability threshold.
7. No vendor startup command or configuration-derived expected port was recovered. DeepDuck therefore sent no request and recorded `protocol_unavailable` instead of inventing a port or claiming reachability.

Whole-system emulation was not justified: service-level execution already established the firmware loader, libraries, and selected process behavior at lower cost.

### Huawei HG532e

Static service evidence identified `/bin/telnetd` and `/bin/upnp`. The generic selector chose `upnp` as the higher-value discovered service candidate with a present executable and recoverable dependency set.

Dependency chain:

1. The authoritative canonical Linux-semantic RootFS was selected; the lossy host-safe view was not used.
2. MIPS32 big-endian mapped to `qemu-mips-static`.
3. ELF interpreter `/lib/ld-uClibc.so.0` resolved.
4. All ten required libraries resolved: `libcfmapi.so`, `libatputil.so`, `libhttpapi.so`, `libmsgapi.so`, `libbhalapi.so`, `libxmlapi.so`, `libcrypto.so`, `librsa.so`, `libgcc_s.so.1`, and `libc.so.0`.
5. `/bin/busybox` loaded and exited normally in the benign smoke test.
6. A bounded `qemu-mips-static -strace` run showed `/bin/upnp` enter real startup syscalls, create a Unix-domain stream socket, and call `connect()`.
7. `connect()` returned `ENOENT`; the required vendor IPC endpoint was absent. The structured blocker is `unix_socket_dependency_missing`.
8. The same failure fingerprint repeated, so the service investigation stopped with `same_failure_fingerprint_repeated`.

No NVRAM content or IPC daemon was fabricated. Whole-system emulation may eventually be needed to supply the vendor process graph, but it was not escalated in this bounded pass because the deepest missing dependency was already verified.

## Runtime architecture verification

The actual `fwagent-round2:latest` worker contains `/usr/bin/qemu-mipsel-static`, `/usr/bin/qemu-mips-static`, `/usr/bin/qemu-arm-static`, `proot`, `readelf`, and `file`. Both MIPS emulators reported QEMU user-mode version 10.0.11. Runtime mapping, endian selection, loader resolution, library-root selection, executable presence, and canonical RootFS provenance are now structured artifacts rather than implicit assumptions.

The bounded worker invocation used `--network none`; all possible protocol endpoints were loopback-only. D-Link and Huawei used 10-second smoke budgets, two-second stability thresholds, and at most one 10-second diagnostic trace.

## RuntimeRepair truthfulness

TP-Link retains the accepted `RR-3501` FastCGI lifecycle reconstruction. Its provenance now states:

- the original gap was the lighttpd-managed firmware child exiting before request handling;
- only the temporary runtime-copy lighttpd configuration changed;
- the source RootFS was not modified;
- FastCGI child lifecycle became externally managed and transport used a loopback-only reconstructed endpoint;
- no environment variables changed;
- vendor-original startup was not confirmed;
- the accepted chain preserves the firmware binaries and routing but is not stock child-supervision parity.

D-Link and Huawei used only `RR-0001`–`RR-0003` to create empty `/dev`, `/proc`, and `/sys` mountpoints in their temporary service RootFS copies after those firmware pseudo-filesystem trees were deliberately excluded from copying. No device contents, kernel state, IPC service, NVRAM values, source firmware, or canonical RootFS content were fabricated or modified. Each repair records that stock pseudo-filesystem contents are not reproduced and dependent services must block or use an explicit safe binding.

## Canonical evidence semantics

Canonical runtime evidence now requires all of the following: an allowed observation type, `execution_mode=real`, `runtime_observation_real=true`, `provider_backed=false`, and exact provenance `real_runtime_observation`. Planning records, backend selection, missing dependencies, blocked attempts, mock results, and pre-start failures remain useful status artifacts but cannot count as real DynamicEvidence.

The model-facing general evidence creator cannot self-assign canonical runtime provenance. Safe protocol probes are routed through `SafeValidationInput`; the generic HTTP service probe is fixed to a validated benign `GET /`. No raw arbitrary payload, Docker, QEMU, shell, or public URL channel was added.

Observation depth reached:

- TP-Link: process/child started → endpoint established → request received → application response observed.
- D-Link: executable smoke → selected service process remained alive.
- Huawei: executable smoke → selected service startup syscalls observed → verified Unix-socket dependency failure.

These results do not claim vulnerability, exploitability, sink execution, or stock boot parity.

## Artifacts

- TP-Link: `workspace/v0_1-final-dynamic-01/dynamic/runtime_summary.json`
- TP-Link integration: `workspace/v0_1-final-dynamic-01/dynamic/application/device_manager/integration_validation.json`
- D-Link: `workspace/dir815-hardening-02/dynamic/runtime_summary.json`
- D-Link feasibility: `workspace/dir815-hardening-02/dynamic/services/httpd/feasibility.json`
- D-Link smoke: `workspace/dir815-hardening-02/dynamic/runtime-smoke/busybox.json`
- Huawei: `workspace/hg532e-hardening-03/dynamic/runtime_summary.json`
- Huawei feasibility: `workspace/hg532e-hardening-03/dynamic/services/upnp/feasibility.json`
- Huawei startup trace: `workspace/hg532e-hardening-03/dynamic/services/upnp/startup_trace.json`
- Huawei smoke: `workspace/hg532e-hardening-03/dynamic/runtime-smoke/busybox.json`

## Verification

- Baseline before changes: 572 tests passed, 8 skipped.
- Targeted hardening module: 18 tests passed.
- Focused runtime and safe-validation regression set: 73 tests passed.
- Explicit TP-Link real-dynamic acceptance: 2 tests passed.
- Full suite on the final code state: 590 tests passed, 8 skipped, in 75.438 seconds.
- Real Docker validation: TP-Link accepted artifacts verified; D-Link MIPS LE and Huawei MIPS BE workers completed successfully with `--network none`.

Safety counters are all zero: public target probes, exploit payloads, blocked attempts promoted as real, and mock/simulated attempts promoted as real. The final secret scan found 0 hits across 36 report/changed files, and no new runtime log is intended for commit. Residual Docker container count is 0. Findings remain zero for all three firmware; runtime reachability was not promoted into a security finding.

## Remaining blockers

- D-Link needs a trustworthy vendor configuration/startup source that identifies the intended HTTP bind or port before a safe request can be sent.
- Huawei needs the vendor IPC server/process graph that owns the missing Unix-domain endpoint; supplying speculative IPC or NVRAM data would reduce fidelity and was not attempted.
- Service-QEMU observations remain service reconstruction, not whole-system stock boot parity.
