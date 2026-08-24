from __future__ import annotations

from fwagent import __version__


def format_terminal_report(report: dict, report_path: str | None = None) -> str:
    firmware = report.get("firmware", {})
    extraction = report.get("extraction", {})
    platform = report.get("platform", {})
    filesystem = report.get("filesystem", {})
    services = report.get("services", [])
    priority = report.get("priority_binaries", [])
    security = report.get("security_candidates", [])
    web = report.get("web", {})

    lines: list[str] = [f"DeepDuck v{__version__}", ""]
    lines.extend(
        [
            "Target",
            "-" * 40,
            f"File: {firmware.get('filename') or firmware.get('path') or 'unknown'}",
            f"SHA256: {firmware.get('sha256', 'unknown')}",
            f"Formats: {', '.join(firmware.get('formats') or firmware.get('detected_formats') or []) or 'unknown'}",
            "",
            "Extraction",
            "-" * 40,
            f"Status: {'ok' if extraction.get('success') else 'failed or partial'}",
            f"Extractor: {extraction.get('extractor', 'unknown')}",
            f"Files extracted: {extraction.get('files_extracted', 0)}",
            "",
            "Platform",
            "-" * 40,
            f"Architecture: {platform.get('architecture') or platform.get('primary_architecture') or 'unknown'}",
            f"Endianness: {platform.get('endianness') or 'unknown'}",
            f"Bitness: {platform.get('bitness') or 'unknown'}",
            "OS: linux" if platform.get("os") else "OS: unknown",
            "",
            "Filesystem",
            "-" * 40,
            f"Files: {filesystem.get('total_files', 0)}",
            f"ELF binaries: {filesystem.get('elf_files', 0)}",
            f"Scripts: {filesystem.get('scripts', 0)}",
            f"Web files: {filesystem.get('web_files', 0)}",
            "",
            "Services",
            "-" * 40,
        ]
    )
    if services:
        for service in services[:15]:
            confidence = _confidence_label(service.get("confidence", 0))
            lines.append(f"{confidence:<6} {service.get('name')} ({service.get('category')})")
    else:
        lines.append("none discovered")

    lines.extend(["", "Web", "-" * 40])
    lines.append(f"Roots: {', '.join(web.get('roots', [])) or 'none'}")
    lines.append(f"CGI files: {len(web.get('cgi', []))}")

    lines.extend(["", "Interesting Binaries", "-" * 40])
    if priority:
        for index, item in enumerate(priority[:10], start=1):
            lines.append(f"{index}. {item.get('path')}  score: {item.get('score')}")
    else:
        lines.append("none scored")

    lines.extend(["", "Security Candidates", "-" * 40])
    if security:
        for item in security[:15]:
            lines.append(f"[{item.get('severity', 'info').upper()}] {item.get('type')} {item.get('path')}")
    else:
        lines.append("none discovered")

    lines.extend(["", "Report", "-" * 40, report_path or report.get("report_path", "analysis.json")])
    return "\n".join(lines)


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.85:
        return "HIGH"
    if confidence >= 0.65:
        return "MED"
    return "LOW"
