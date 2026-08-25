# DeepDuck v0.1 Final Acceptance

Generated: 2026-08-25

## Executive Summary

DeepDuck v0.1 has passed the current real-firmware acceptance gates for extraction, Dockerized Ghidra analysis, isolated dynamic reachability validation, canonical runtime evidence hygiene, and provider-backed bounded investigation. Release-candidate compatibility validation remains partial because a second distinct authorized real firmware image has not yet been exercised.

## Release Gate Summary

| Release Gate | Status |
|---|---|
| Fresh firmware extraction | PASS |
| Canonical RootFS | PASS |
| Real Dockerized Ghidra | PASS |
| Real dynamic runtime observation | PASS |
| Canonical evidence hygiene | PASS |
| Provider-backed execution | PASS |
| Structured output | PASS |
| Controlled tool calling | PASS |
| Safety gates | PASS |
| Full test suite | PASS |
| MIPS architecture fixture | PASS |
| Unsupported-input handling | PASS |
| Second distinct real firmware | PENDING |
| Multi-firmware real acceptance | PARTIAL |

Release Candidate Gate: `HOLD / PARTIAL`

Reason: a second distinct authorized real firmware image has not yet been exercised.

## 1. Release Scope

This acceptance run validates DeepDuck v0.1 on the authorized TP-Link SR20 firmware sample and the local DeepSeek-compatible provider configuration. The run covers real Docker extraction, real Ghidra static analysis, real isolated FastCGI bring-up, canonical runtime evidence hygiene, provider-backed agent control-loop execution, local regression samples, and release safety gates.

Primary firmware:

- `tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin`

Primary task IDs:

- Dynamic runtime task: `workspace/v0_1-final-dynamic-01`
- Provider task: `workspace/v0_1-provider-01`
- Opaque regression task: `workspace/v0_1-regression-opaque-02`

## 2. Environment

- Host: Windows with Docker Desktop
- Dynamic worker: DeepDuck dynamic worker (`fwagent-round3-dynamic:latest`, internal image name)
- Ghidra worker: Dockerized Ghidra, `ghidra_version=12.1.3`, `java_version=21.0.12.1`
- Runtime isolation: Docker `--network none` for the Linux worker bring-up path
- Allowed targets: local artifact paths and loopback/private runtime endpoints only

## 3. Extraction and RootFS

Both primary analysis tasks completed Docker/binwalk extraction successfully after the initial host-side candidate scan reported no local rootfs.

- Selected rootfs: `docker-extract/_tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin.extracted/squashfs-root`
- Rootfs markers: `bin`, `etc`, `usr`, `sbin`, `lib`, `www`
- File count: 2255
- ELF count: 457
- Architecture: ARM, 32-bit little-endian

## 4. Static Backend

Ghidra acceptance completed through the real Dockerized backend for both primary tasks.

- Scheduled binaries: 20
- Processed binaries: 20
- Successful binaries: 20
- Failed binaries: 0
- Timeout count: 0
- Real Ghidra count: 20
- Fallback count: 0

## 5. Dynamic Runtime

The Windows host runtime path correctly reports environment blocking for unsupported runtime primitives such as missing Unix-domain sockets and invalid host `chroot` semantics. The Linux Docker worker successfully reproduced the FastCGI integration path.

- Backend child reached: true
- FastCGI request received: true
- Application response reached: true
- Lighttpd integration reachable: true
- Probe endpoint: `https://127.0.0.1:3000/services/device_manager/`
- Probe result: HTTP 500 SOAP fault, `Unknown SOAP action`
- Vulnerability claim from probe: none

## 6. Runtime Repair

Runtime repair was used only to reproduce lifecycle parity needed for FastCGI reachability.

- Repair ID: `RR-3501`
- Repair type: `external_fastcgi_lifecycle_parity`
- Source rootfs modified: false
- Transport: TCP loopback
- Original startup confirmed: false
- Runtime reconstruction accepted as evidence of reachability, not as proof of stock boot parity

## 7. Canonical Dynamic Evidence

Canonical runtime evidence contains only real observations from the Linux worker bring-up path.

- DynamicEvidence registry records: 88
- Real runtime evidence IDs: `DE-0085`, `DE-0086`, `DE-0087`, `DE-0088`
- Real runtime evidence types: `fastcgi_child_started`, `fastcgi_request_received`, `fastcgi_application_response`, `fastcgi_integration_reachable`
- Blocked evidence marked real: 0
- Mock/simulated evidence marked real: 0

Only evidence records satisfying the canonical real-runtime provenance requirements are treated as runtime-confirmed evidence.

| Evidence class | Count | Canonical real runtime |
|---|---:|---|
| Real Ghidra-derived static evidence (`provenance=real_ghidra`) | 81 | No |
| Real runtime attempts that were blocked or failed (`provenance=real_runtime_attempt`) | 3 | No |
| Real runtime observations (`provenance=real_runtime_observation`) | 4 | Yes |
| Total | 88 | - |

## 8. Graph and Surface

Runtime-confirmed entry points are limited to local or loopback scope.

- Total relationships: 454
- Dynamic relationships: 5
- Runtime-confirmed entries: `EP-HTTPS-lighttpd-device-manager`, `EP-LOOPBACK-FCGI-35635`
- Public entries: 0
- Surface scopes observed: local network, local process, loopback

## 9. Taint and Findings

The analysis found sources and sinks, but no supported taint path and no vulnerability finding.

- Sources: 6 in the dynamic acceptance task
- Sinks: 43
- Candidate taint paths: 0
- High-priority taint paths: 0
- Findings: 0
- Safety rule preserved: source plus sink is not a vulnerability

## 10. Provider Doctor

The configured DeepSeek-compatible provider passed live connectivity after running with required network permissions.

- Provider: DeepSeek
- Model: `deepseek-v4-flash`
- Credentials configured: true
- Connection: pass
- Structured output: pass
- Tool calling: supported
- Status: ready
- API key exposure: not present in generated artifacts or report output

## 11. Provider Agent Smoke

The provider-backed agent smoke ran against `workspace/v0_1-provider-01` without exposing raw execution tools.

The provider-backed control loop was successfully exercised, but this acceptance run terminated at the configured controller step budget (`max_steps`) rather than through an autonomous convergence decision. This validates bounded provider-backed execution, not autonomous convergence.

- Provider-backed: true
- Provider: DeepSeek
- Model: `deepseek-v4-flash`
- Steps: 12
- Tool calls: 12
- Validation requests: 0
- Stop reason: `max_steps`
- Model error: null
- Stored chain-of-thought: none

## 12. Provider Tool Boundary

The provider control loop retained the intended safety boundary.

- Forbidden raw execution tools exposed: 0
- Read-only/status tools available to the model: yes
- Dynamic validation requests require normal DeepDuck mediation
- No shell, Docker, or arbitrary process execution capability is exposed through the provider-facing tool surface

## 13. Regression Samples

The available local sample set does not include a second distinct authorized real firmware image. Regression therefore passes for the exercised fixture and unsupported-input behavior, while multi-firmware real acceptance remains partial.

- Current ARM real firmware: pass
- MIPS firmware fixture integration: pass
- Opaque unsupported sample: pass as graceful partial, no crash
- Distinct second real firmware: unavailable locally
- Multi-firmware acceptance state: `MULTI-FIRMWARE ACCEPTANCE PARTIAL`

## 14. Safety Gates

The final safety gates passed.

- Public target probing: 0
- Docker containers left running: 0
- Secret scan hits in generated artifacts: 0
- Blocked runtime attempts promoted to real evidence: 0
- Mock runtime attempts promoted to real evidence: 0

## 15. Test Gates

The test gates completed successfully.

- Targeted runtime tests: 28 tests, OK
- Full unit/integration discovery: 564 tests, OK, 8 skipped
- Real dynamic/provider acceptance tests: 4 tests, OK
- Real Docker/Ghidra coverage: exercised by fresh primary analysis runs

## 16. Engineering Notes

The final run includes targeted fixes for real backend behavior and evidence hygiene.

- Windows copied symlink/reparse writable paths are materialized into real directories before service rootfs use
- Inaccessible rootfs path checks are guarded against host `OSError`
- Windows `AF_UNIX` and socket-stdin limitations return structured runtime-environment-blocked results
- Linux Docker worker can resolve workspace-relative rootfs paths produced by Windows-host analysis tasks
- Blocked or inconclusive runtime attempts are kept out of canonical real-runtime evidence

## 17. Known Limitations

- The real dynamic acceptance is proven for the selected FastCGI path, not for every service in the firmware
- Runtime repair confirms reconstructed reachability, not original vendor boot sequence parity
- The HTTP 500 SOAP response is expected semantic application behavior for the safe probe and is not a vulnerability
- Multi-firmware real acceptance is partial until a second distinct authorized real firmware is supplied

## 18. Final Status

DeepDuck v0.1 passes real dynamic runtime reachability, real provider-backed execution, canonical evidence hygiene, release safety gates, and full regression tests for the available samples.

Final acceptance state:

`DEEPDUCK V0.1 REAL DYNAMIC + REAL PROVIDER ACCEPTED / MULTI-FIRMWARE ACCEPTANCE PARTIAL`
