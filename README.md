# DeepDuck: Agentic IoT Firmware Analysis Pipeline

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-runtime-blue)](https://www.docker.com/)
[![arXiv](https://img.shields.io/badge/arXiv-TBD-b31b1b.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-active%20research-orange)](#roadmap)
[![Reports](https://img.shields.io/badge/reports-Markdown%20%7C%20HTML%20%7C%20JSON-purple)](#sample-report)

**DeepDuck** stands for **Deep Exploration and Evaluation Platform for Device Understanding, Correlation, and Knowledge**. It is a deterministic-first IoT
firmware analysis framework that turns a firmware image into a reproducible
workspace containing extraction evidence, filesystem inventory, service
discovery, binary triage, dynamic reachability artifacts, and final reports.

The project is designed for agent-assisted security research: scanners produce
structured evidence, the agent reasons over bounded tools, and reports clearly
separate confirmed facts from candidate risks.

## 🎯 Who is DeepDuck for?

| 👥 **User Type** | 🚀 **Use Case** |
|---|---|
| **Firmware Researchers** | Build repeatable first-pass analysis workspaces from router/IoT images |
| **Security Engineers** | Prioritize network services, Web handlers, credentials, and risky binaries |
| **Reverse Engineers** | Select high-value ELF targets for Ghidra and call-graph inspection |
| **Agent Builders** | Connect LLM planning to constrained firmware-analysis tools |
| **Lab Operators** | Run isolated Docker/QEMU/FirmAE validation without touching live targets |

## ✨ Key Features

### For All Users

- **🧭 One-command analysis**: Run `deepduck analyze` and get a task workspace with reports.
- **📦 Safe extraction workspace**: Copy firmware into an isolated task directory before processing.
- **📊 Multi-format reports**: Emit Markdown, HTML, and JSON final reports.
- **🔐 Safety-first posture**: No public target scanning, no exploit execution, and no arbitrary agent shell tools.

### For Firmware Analysts

- **🧬 Firmware fingerprinting**: Hash, size, file type, magic bytes, and format discovery.
- **🗂️ Rootfs inventory**: Count ELF binaries, scripts, configs, certificates, Web assets, and symlinks.
- **🌐 Attack surface discovery**: Identify startup services, Web roots, CGI/FastCGI handlers, and network daemons.
- **🎯 Binary prioritization**: Rank binaries by service exposure, dangerous imports, HTTP strings, shell references, and stripping.

### For Agentic Workflows

- **🧠 Model smoke tests**: Validate provider connectivity, structured output, and tool-calling behavior.
- **🛠️ Bounded tools**: Expose only structured `firmware.*`, `ghidra.*`, `dynamic.*`, `evidence.*`, and `hypothesis.*` tools.
- **🧾 Evidence traceability**: Persist tool traces, hypotheses, validations, findings, and report manifests.
- **🧪 Runtime reachability path**: Prepare dynamic investigation artifacts for Docker/QEMU/FirmAE workflows.

## 🚀 Quick Start

### Installation

**Option 1: Editable local install**

```bash
git clone <your-deepduck-repo-url>
cd DeepDuck
pip install -e .
```

**Option 2: Run from source**

```bash
deepduck doctor
deepduck analyze path/to/firmware.bin
```

**Option 3: Docker runtime**

```bash
docker build -t fwagent-round2:latest .
docker run --rm --network none -v "$PWD:/work" -w /work \
  fwagent-round2:latest deepduck analyze /work/path/to/firmware.bin --workspace /work/workspace
```

### First Run

#### 1. Analyze a firmware image

```bash
deepduck analyze samples/firmware.bin \
  --workspace workspace \
  --task-id demo-firmware \
  --max-iterations 3
```

#### 2. Show task status

```bash
deepduck status demo-firmware --workspace workspace
```

#### 3. Regenerate final reports

```bash
deepduck report demo-firmware \
  --workspace workspace \
  --format md,html,json
```

## 📚 Core Workflow

| Stage | Output | Purpose |
|---|---|---|
| **Identify** | `reports/analysis.json` | Hash and classify the firmware input |
| **Extract** | `extracted/` | Recover root filesystem candidates |
| **Inventory** | `filesystem` section | Count files, scripts, configs, ELF binaries, Web assets |
| **Surface** | `surface/` | Map services, Web routes, entry points, and reachability hints |
| **Investigate** | `evidence/`, `hypotheses/` | Promote interesting observations into bounded hypotheses |
| **Validate** | `dynamic/`, `simulation/` | Record runtime attempts and blocked validations |
| **Report** | `reports/report.*` | Produce human and machine-readable final reports |

## 🛠️ Usage Examples

### Static-only triage

```bash
deepduck analyze firmware.bin \
  --workspace workspace \
  --task-id static-triage \
  --static-only
```

### Agent-assisted investigation

```bash
deepduck investigate static-triage \
  --workspace workspace \
  --binary /usr/sbin/lighttpd \
  --max-steps 10 \
  --max-binary-analyses 1 \
  --max-decompilations-per-binary 5
```

### Model provider smoke test

```bash
deepduck model check
```

Model configuration is read from environment variables or a local `.env` file:

```env
MODEL_PROVIDER=
MODEL_NAME=
MODEL_API_KEY=
MODEL_BASE_URL=
```

`.env` is ignored by Git and Docker builds. Keep provider keys out of reports,
logs, and prompts unless a specific task requires a transient API call.

### Ghidra environment check

```bash
deepduck ghidra check
deepduck doctor
```

### Docker validation

```bash
docker build -t fwagent-round2:latest .
docker run --rm --network none -v "$PWD:/work" -w /work \
  fwagent-round2:latest deepduck analyze /work/firmware.bin \
  --workspace /work/workspace \
  --task-id docker-demo
```

## 📄 Sample Report

The latest local firmware run analyzed:

```text
tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin
```

Generated artifacts:

| Artifact | Path |
|---|---|
| Markdown report | `workspace/deepseek-firmware-02/reports/firmware_analysis_report.md` |
| HTML report | `workspace/deepseek-firmware-02/reports/firmware_analysis_report.html` |
| Evidence JSON | `workspace/deepseek-firmware-02/reports/analysis_docker_rootfs.json` |
| Model triage | `workspace/deepseek-firmware-02/reports/deepseek_triage.md` |

### Executive Summary Preview

- Docker/binwalk recovered a SquashFS root filesystem at offset `0x212FF9`.
- Platform identified as `ARM` `32-bit` little-endian with confidence `1.0`.
- Rootfs inventory found `2165` files, `457` ELF binaries, `531` scripts, `596` Web files, and `481` config files.
- Attack surface discovery identified `8` service candidates, Web root `/www`, CGI entries `/www/cgi-bin/luci` and `/www/cgi-bin/luci-cloud`.
- Candidate security observations include private-key material and empty `guest` password/shadow fields; these remain static candidates pending validation.

### Priority Audit Targets

| Rank | Target | Score | Why it matters |
|---:|---|---:|---|
| 1 | `/usr/sbin/lighttpd` | 81 | Web server, dangerous imports, HTTP strings, `/bin/sh` reference |
| 2 | `/usr/sbin/dnsmasq` | 65 | Network daemon, `popen`, `sprintf`, `strcpy`, `memcpy` |
| 3 | `/usr/sbin/uhttpd` | 55 | Web server, HTTP/CGI surface, authorization strings |
| 4 | `/usr/sbin/miniupnpd` | 51 | UPnP-facing daemon, HTTP strings, possible `system` reference |
| 5 | `/www/services/device_manager/device_manager.fcgi` | 15 | FastCGI endpoint handling authorization and SOAP action metadata |

### Web Runtime Evidence

Manual configuration review found:

- `lighttpd` document root: `/www`
- `lighttpd` port: `3000`
- TLS socket: `:10443`
- FastCGI route: `/services/device_manager/`
- FastCGI binary: `/www/services/device_manager/device_manager.fcgi`
- `uhttpd` HTTP listener: `0.0.0.0:80`
- `uhttpd` HTTPS listener: `0.0.0.0:443`
- CGI prefix: `/cgi-bin`

> Static reachability does not imply exploitability. Every candidate above needs
> reverse engineering, call-graph inspection, or runtime validation before it can
> be promoted to a confirmed vulnerability.

## 🧩 Project Layout

```text
DeepDuck/
  fwagent/
    dynamic/          # QEMU/FirmAE, reachability, service/runtime tooling
    investigation/    # Agent loop and static investigation orchestration
    model/            # Provider config, smoke tests, redaction helpers
    pipeline/         # Product pipeline and workspace orchestration
    reporting/        # JSON, Markdown, HTML report generation
    runtime/          # Command, Ghidra, QEMU, FirmAE adapters
    scanners/         # Config, credential, crypto, and Web scanners
    tools/            # Firmware, filesystem, architecture, binaries, services
  docker/             # Worker images and validation scripts
  scripts/            # Round validation helpers
  tests/              # Unit tests
  workspace/          # Generated task workspaces
```

## 🔒 Safety Model

DeepDuck is built around conservative analysis boundaries:

- Firmware files are copied into task workspaces and are not modified in place.
- Default analysis does not execute firmware binaries or chroot into firmware roots.
- Docker runs should use `--network none` unless a specific local runtime validation needs otherwise.
- Agent-facing APIs expose structured tools only; arbitrary shell, Docker, and QEMU commands are not registered.
- Reports classify unsupported observations as candidates until runtime or reverse-engineering evidence exists.

## 🧪 Tests

Run the unit suite:

```bash
python -m unittest discover -v
```

Recent local validation:

```text
467 passed, 1 skipped
```

## 🗺️ Roadmap

- **Provider-authored reports**: Let DeepSeek/OpenAI generate final narrative reports directly from DeepDuck evidence bundles.
- **Deeper FastCGI reproduction**: Reconstruct service startup and request semantics for selected Web backends.
- **Ghidra-guided promotion**: Promote candidate findings only when call-graph and data-flow evidence supports the claim.
- **Runtime confirmation loop**: Tie Docker/QEMU/FirmAE observations back into evidence chains and final report status.
- **Report UX polish**: Add richer HTML report navigation, evidence filters, and artifact indexing.

## 📜 License

This project is currently configured as MIT in `pyproject.toml`.

