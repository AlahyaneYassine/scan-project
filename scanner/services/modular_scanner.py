"""Independent scan module helpers for selective backend execution.

Each public function in this module runs a single, narrowly scoped scan and
returns a structured result dictionary instead of raising exceptions. This keeps
the caller in control and prevents a failure in one module from stopping other
modules.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import time
import tempfile
from typing import Callable

logger = logging.getLogger(__name__)


ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
HOST_REPORT_PATTERN = re.compile(r"^Nmap scan report for (.+?)(?: \(([^)]+)\))?$", re.IGNORECASE)
PORT_LINE_PATTERN = re.compile(r"^\s*(\d+)/(tcp|udp)\s+open\s*(.*)$", re.IGNORECASE)
CUSTOM_PORT_LINE_PATTERN = re.compile(r"^\s*(\d+)/(tcp|udp)\s+(open|closed|filtered|unfiltered|open\|filtered)\s*(.*)$", re.IGNORECASE)
HTTP_TITLE_PATTERN = re.compile(r"http-title:\s*(.*)$", re.IGNORECASE)
HTTP_SERVER_PATTERN = re.compile(r"http-server-header:\s*(.*)$", re.IGNORECASE)
WHATWEB_TITLE_PATTERN = re.compile(r"Title\[([^\]]+)\]", re.IGNORECASE)
WHATWEB_SERVER_PATTERN = re.compile(r"Server\[([^\]]+)\]", re.IGNORECASE)
WHATWEB_BLOCK_PATTERN = re.compile(r"^--- WhatWeb\s+([^:]+)(?::(\d+))? ---$", re.IGNORECASE)
HOST_UP_PATTERN = re.compile(r"Host is up", re.IGNORECASE)
HOST_DOWN_PATTERN = re.compile(r"Host seems down|down", re.IGNORECASE)

CAMERA_SCAN_PORTS = "80,81,554,8080,8000,8554,8081,8443,37777,34567,5000,5001,9000,10080,8899"
CAMERA_HTTP_PORTS = {80, 81, 443, 8000, 8080, 8081, 8443, 9000, 10080, 8899, 5000, 5001}
CAMERA_HTTPS_PORTS = {443, 8443}
CAMERA_RTSP_PORTS = {554, 8554}
CAMERA_CUSTOM_PORTS = {37777, 34567, 5000, 5001, 9000, 10080, 8899, 8080, 8081, 8000, 8443}
CAMERA_DISCOVERY_ARGS = ["-sn", "--max-retries", "1", "--host-timeout", "20s"]
CAMERA_PORT_ARGS = ["-Pn", "-n", "--open", "--max-retries", "1", "--host-timeout", "20s", "-p", CAMERA_SCAN_PORTS]
CAMERA_VERSION_ARGS = ["-Pn", "-n", "-sV", "--version-light", "--open", "--max-retries", "1", "--host-timeout", "20s"]
CAMERA_ONVIF_PATTERNS = (
    r"\bonvif\b",
    r"ws-discovery",
    r"device service",
    r"media service",
)
CAMERA_VENDOR_PATTERNS = {
    "Hikvision": (
        r"hikvision",
        r"\bds-?\d{3,5}\b",
        r"hi3516",
        r"hi3518",
        r"ezviz",
    ),
    "Dahua": (
        r"dahua",
        r"netsurveillance",
        r"dh-",
        r"imou",
    ),
    "Axis": (
        r"axis",
        r"axis communications",
        r"vapix",
    ),
    "Uniview": (
        r"uniview",
        r"unv",
        r"ezstation",
    ),
    "TP-Link": (
        r"tp-link",
        r"tapo",
        r"vigi",
    ),
    "Reolink": (
        r"reolink",
        r"\brlc-\w+\b",
        r"reo-link",
    ),
}

CAMERA_SERVICE_HINTS = (
    "rtsp",
    "onvif",
    "ip camera",
    "network camera",
    "surveillance",
    "camera",
    "nvr",
    "dvr",
    "webcam",
)

HIGH_RISK_PORTS = {23, 3389, 3306, 5432, 6379, 27017, 1433, 1521}
MEDIUM_RISK_PORTS = {22, 80, 443, 445, 139, 8080, 8443, 631, 515, 9100}


def _strip_ansi_codes(text: str) -> str:
    return ANSI_ESCAPE_PATTERN.sub("", text or "")


def _extract_hostname(host_label: str, ip_address: str | None) -> str:
    label = host_label.strip()
    if ip_address and label == ip_address:
        return ""
    if label.startswith("(") and label.endswith(")"):
        return ""
    return label


def _new_host_entry(host_label: str, ip_address: str | None) -> dict[str, object]:
    return {
        "host_ip": ip_address or host_label,
        "hostname": _extract_hostname(host_label, ip_address),
        "state": "up",
        "open_ports": [],
        "services": [],
        "risk_level": "LOW",
    }


def _normalize_service_name(port: int, protocol: str, state: str, details: str) -> dict[str, object]:
    service_name = details.split()[0] if details.strip() else "unknown"
    return {
        "port": port,
        "protocol": protocol.lower(),
        "state": state.lower(),
        "service": service_name,
        "details": details.strip(),
    }


def _normalize_port_state(state: str) -> str:
    value = state.strip().lower()
    if value.startswith("open|filtered"):
        return "filtered"
    if value.startswith("open"):
        return "open"
    if value.startswith("closed"):
        return "closed"
    if value.startswith("filtered"):
        return "filtered"
    if value.startswith("unfiltered"):
        return "unfiltered"
    return value or "unknown"


def _risk_level_for_services(services: list[dict[str, object]]) -> str:
    if not services:
        return "LOW"

    risk_level = "LOW"
    for service in services:
        port = int(service.get("port") or 0)
        service_name = str(service.get("service") or "").strip().lower()

        if port in HIGH_RISK_PORTS or service_name in {"telnet", "rdp", "mysql", "postgresql", "mongodb", "redis", "mssql", "oracle"}:
            return "HIGH"

        if port in MEDIUM_RISK_PORTS or service_name in {"smb", "microsoft-ds", "netbios-ssn", "ssh", "http", "https", "ftp", "ipp", "printer", "jetdirect"}:
            risk_level = "MEDIUM"

    return risk_level


def _build_camera_url(host_ip: str, port: int) -> str:
    scheme = "https" if port in CAMERA_HTTPS_PORTS else "http"
    return f"{scheme}://{host_ip}:{port}"


def _detect_camera_vendor(text: str) -> str:
    lowered = text.lower()
    for vendor, patterns in CAMERA_VENDOR_PATTERNS.items():
        if any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in patterns):
            return vendor
    return "Unknown"


def _score_camera_confidence(*, vendor: str, services: list[dict[str, object]], titles: list[str], headers: list[str], whatweb_output: str) -> tuple[str, int, list[str], str]:
    evidence: list[str] = []
    score = 0
    detected_service = "Unknown"

    service_text = " ".join(
        [
            " ".join(str(service.get("details") or "") for service in services),
            " ".join(titles),
            " ".join(headers),
            whatweb_output,
        ]
    ).strip()

    if any(int(service.get("port") or 0) in CAMERA_RTSP_PORTS or str(service.get("service") or "").lower() == "rtsp" for service in services):
        score += 30
        evidence.append("RTSP")
        detected_service = "RTSP"

    if any(int(service.get("port") or 0) == 3702 for service in services) or any(re.search(pattern, service_text, flags=re.IGNORECASE) for pattern in CAMERA_ONVIF_PATTERNS):
        score += 25
        evidence.append("ONVIF")
        if detected_service == "Unknown":
            detected_service = "ONVIF"

    if any(int(service.get("port") or 0) in CAMERA_HTTP_PORTS for service in services):
        score += 15
        evidence.append("HTTP")
        if detected_service == "Unknown":
            detected_service = "HTTP / Web UI"

    if any(port in CAMERA_CUSTOM_PORTS for port in (int(service.get("port") or 0) for service in services)):
        score += 20
        evidence.append("CUSTOM_PORT")
        if detected_service == "Unknown":
            detected_service = "Custom Camera Service"

    if any(port in CAMERA_HTTP_PORTS or port in CAMERA_RTSP_PORTS for port in (int(service.get("port") or 0) for service in services)):
        score += 10

    if titles or headers or whatweb_output.strip():
        score += 20
        evidence.append("BANNER")
        if detected_service == "Unknown":
            detected_service = "HTTP / Web UI"

    if vendor != "Unknown":
        score += 30
        evidence.append(vendor)

    if vendor == "Unknown" and score < 30:
        return "LOW", score, evidence, detected_service

    if score >= 70:
        return "HIGH", score, evidence, detected_service
    if score >= 40:
        return "MEDIUM", score, evidence, detected_service
    return "LOW", score, evidence, detected_service


def _unique_ints(values: list[int]) -> list[int]:
    unique: list[int] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return unique


def _unique_strings(values: list[str]) -> list[str]:
    unique: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in unique:
            unique.append(text)
    return unique


def _merge_camera_services(services_a: list[dict[str, object]], services_b: list[dict[str, object]]) -> list[dict[str, object]]:
    merged: dict[tuple[int, str], dict[str, object]] = {}

    for service in [*services_a, *services_b]:
        if not isinstance(service, dict):
            continue

        try:
            port = int(service.get("port") or 0)
        except (TypeError, ValueError):
            continue

        protocol = str(service.get("protocol") or "").lower()
        key = (port, protocol)
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(service)
            continue

        existing_details = str(existing.get("details") or "")
        new_details = str(service.get("details") or "")
        if len(new_details) > len(existing_details):
            merged[key] = dict(service)

    return sorted(merged.values(), key=lambda item: int(item.get("port") or 0))


def _refresh_camera_host_metadata(host: dict[str, object]) -> None:
    services = [service for service in host.get("services", []) if isinstance(service, dict)]
    titles = _unique_strings([str(title) for title in host.get("titles", []) if str(title).strip()])
    headers = _unique_strings([str(header) for header in host.get("headers", []) if str(header).strip()])
    whatweb_output = str(host.get("whatweb_output") or "").strip()

    host["services"] = services
    host["titles"] = titles
    host["headers"] = headers

    banner_text = " ".join(
        [
            " ".join(str(service.get("details") or "") for service in services),
            " ".join(titles),
            " ".join(headers),
            whatweb_output,
        ]
    )
    vendor = _detect_camera_vendor(banner_text)
    confidence_level, confidence_score, evidence, detected_service = _score_camera_confidence(
        vendor=vendor,
        services=services,
        titles=titles,
        headers=headers,
        whatweb_output=whatweb_output,
    )

    if confidence_score > 0 or host.get("open_ports") or whatweb_output:
        host["vendor"] = vendor
        host["confidence_level"] = confidence_level
        host["confidence_score"] = confidence_score
        host["detected_service"] = detected_service
        host["evidence"] = evidence


def _merge_camera_host_entries(base_host: dict[str, object], extra_host: dict[str, object]) -> dict[str, object]:
    merged = dict(base_host)

    merged["open_ports"] = _unique_ints([
        int(port)
        for port in [*base_host.get("open_ports", []), *extra_host.get("open_ports", [])]
        if isinstance(port, int) or str(port).isdigit()
    ])
    merged["http_ports"] = _unique_ints([
        int(port)
        for port in [*base_host.get("http_ports", []), *extra_host.get("http_ports", [])]
        if isinstance(port, int) or str(port).isdigit()
    ])
    merged["services"] = _merge_camera_services(
        [service for service in base_host.get("services", []) if isinstance(service, dict)],
        [service for service in extra_host.get("services", []) if isinstance(service, dict)],
    )
    merged["titles"] = _unique_strings([
        *[str(title) for title in base_host.get("titles", []) if str(title).strip()],
        *[str(title) for title in extra_host.get("titles", []) if str(title).strip()],
    ])
    merged["headers"] = _unique_strings([
        *[str(header) for header in base_host.get("headers", []) if str(header).strip()],
        *[str(header) for header in extra_host.get("headers", []) if str(header).strip()],
    ])

    extra_whatweb = str(extra_host.get("whatweb_output") or "").strip()
    if extra_whatweb:
        current_whatweb = str(merged.get("whatweb_output") or "").strip()
        merged["whatweb_output"] = "\n".join([value for value in [current_whatweb, extra_whatweb] if value]).strip()

    _refresh_camera_host_metadata(merged)
    return merged


def _build_camera_section(title: str, command: str, result: dict[str, object]) -> str:
    output = str(result.get("output") or "").strip()
    error = str(result.get("error") or "").strip()
    parts = [f"=== {title} ===", f"Command: {command}"]
    if output:
        parts.append(output)
    if error:
        parts.append(f"[stderr]\n{error}")
    return "\n".join(parts).strip()


def _collect_discovery_hosts(output: str, target: str | None = None) -> list[dict[str, object]]:
    """Parse Nmap discovery output to extract IP, hostname, and status only."""
    cleaned_output = _strip_ansi_codes(output)
    hosts: list[dict[str, object]] = []
    current_host: dict[str, object] | None = None

    def flush_current_host() -> None:
        nonlocal current_host
        if current_host is None:
            return

        host_ip = str(current_host.get("host_ip") or "").strip()
        if host_ip and not _is_network_address(host_ip, target):
            hosts.append(current_host)

        current_host = None

    for raw_line in cleaned_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        host_match = HOST_REPORT_PATTERN.match(line)
        if host_match:
            flush_current_host()

            host_label = host_match.group(1).strip()
            ip_address = host_match.group(2).strip() if host_match.group(2) else None
            current_host = {
                "host_ip": ip_address or host_label,
                "hostname": _extract_hostname(host_label, ip_address),
                "state": "down",
            }
            continue

        if current_host is None:
            continue

        if HOST_UP_PATTERN.search(line):
            current_host["state"] = "up"
            continue

        if HOST_DOWN_PATTERN.search(line):
            current_host["state"] = "down"
            continue

    flush_current_host()
    return hosts


def _extract_whatweb_blocks(output: str) -> dict[str, str]:
    blocks: dict[str, list[str]] = {}
    current_host_ip = ""

    for raw_line in _strip_ansi_codes(output).splitlines():
        line = raw_line.strip()
        if not line:
            continue

        block_match = WHATWEB_BLOCK_PATTERN.match(line)
        if block_match:
            current_host_ip = block_match.group(1).strip()
            blocks.setdefault(current_host_ip, [])
            continue

        if current_host_ip:
            blocks.setdefault(current_host_ip, []).append(line)

    return {host_ip: "\n".join(lines).strip() for host_ip, lines in blocks.items() if lines}


def _collect_camera_hosts(output: str, target: str | None = None, auxiliary_output: str = "") -> list[dict[str, object]]:
    cleaned_output = _strip_ansi_codes(output)
    whatweb_blocks = _extract_whatweb_blocks(auxiliary_output)
    hosts: list[dict[str, object]] = []
    current_host: dict[str, object] | None = None

    def flush_current_host() -> None:
        nonlocal current_host
        if current_host is None:
            return

        open_ports = [port for port in current_host.get("open_ports", []) if isinstance(port, int)]
        services = [service for service in current_host.get("services", []) if isinstance(service, dict)]
        if not open_ports or _is_network_address(str(current_host.get("host_ip") or ""), target):
            current_host = None
            return

        current_host["open_ports"] = list(dict.fromkeys(open_ports))
        current_host["services"] = services
        host_ip = str(current_host.get("host_ip") or "").strip()
        current_host["http_ports"] = [port for port in current_host.get("http_ports", []) if isinstance(port, int)]
        current_host["titles"] = list(dict.fromkeys([str(title).strip() for title in current_host.get("titles", []) if str(title).strip()]))
        current_host["headers"] = list(dict.fromkeys([str(header).strip() for header in current_host.get("headers", []) if str(header).strip()]))
        current_host["whatweb_output"] = whatweb_blocks.get(host_ip, "")

        banner_text = " ".join(
            [
                " ".join(str(service.get("details") or "") for service in services),
                " ".join(current_host["titles"]),
                " ".join(current_host["headers"]),
                str(current_host.get("whatweb_output") or ""),
            ]
        )
        vendor = _detect_camera_vendor(banner_text)
        confidence_level, confidence_score, evidence, detected_service = _score_camera_confidence(
            vendor=vendor,
            services=services,
            titles=current_host["titles"],
            headers=current_host["headers"],
            whatweb_output=str(current_host.get("whatweb_output") or ""),
        )

        if confidence_score <= 0 and not current_host["http_ports"] and not any(
            int(service.get("port") or 0) in CAMERA_RTSP_PORTS for service in services
        ):
            current_host = None
            return

        current_host["vendor"] = vendor
        current_host["confidence_level"] = confidence_level
        current_host["confidence_score"] = confidence_score
        current_host["detected_service"] = detected_service
        current_host["evidence"] = evidence
        hosts.append(current_host)
        current_host = None

    for raw_line in cleaned_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        host_match = HOST_REPORT_PATTERN.match(line)
        if host_match:
            flush_current_host()

            host_label = host_match.group(1).strip()
            ip_address = host_match.group(2).strip() if host_match.group(2) else None
            current_host = _new_host_entry(host_label, ip_address)
            current_host["http_ports"] = []
            current_host["titles"] = []
            current_host["headers"] = []
            current_host["whatweb_output"] = ""
            continue

        if current_host is None:
            continue

        port_match = PORT_LINE_PATTERN.match(line)
        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2).lower()
            details = (port_match.group(3) or "").strip()
            service_name = details.split()[0] if details else "unknown"

            current_host["open_ports"].append(port)
            current_host["services"].append(_normalize_service_name(port, protocol, "open", details))
            if port in CAMERA_HTTP_PORTS or service_name.lower() in {"http", "https", "ssl/http", "ssl/https"}:
                current_host["http_ports"].append(port)
            continue

        title_match = HTTP_TITLE_PATTERN.search(line)
        if title_match:
            current_host["titles"].append(title_match.group(1).strip())
            continue

        server_match = HTTP_SERVER_PATTERN.search(line)
        if server_match:
            current_host["headers"].append(server_match.group(1).strip())
            continue

        lower_line = line.lower()
        if any(pattern in lower_line for pattern in CAMERA_SERVICE_HINTS):
            current_host.setdefault("titles", []).append(line)

    flush_current_host()
    return hosts


def _extract_whatweb_signals(output: str) -> tuple[list[str], list[str]]:
    titles: list[str] = []
    headers: list[str] = []
    cleaned_output = _strip_ansi_codes(output)
    for raw_line in cleaned_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        title_match = WHATWEB_TITLE_PATTERN.search(line)
        if title_match:
            titles.append(title_match.group(1).strip())
        server_match = WHATWEB_SERVER_PATTERN.search(line)
        if server_match:
            headers.append(server_match.group(1).strip())
    return titles, headers


def _is_network_address(host_ip: str, target: str | None) -> bool:
    if not target or "/" not in target:
        return False

    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
        return ipaddress.ip_address(host_ip) == network.network_address
    except ValueError:
        return False


def parse_modular_nmap_output(module_name: str, output: str, target: str | None = None, auxiliary_output: str = "") -> list[dict[str, object]]:
    """Parse Nmap output into normalized per-host module findings."""
    module_name = module_name.strip().lower()
    if module_name == "host_discovery":
        return _collect_discovery_hosts(output, target)

    if module_name == "camera_scan":
        return _collect_camera_hosts(output, target, auxiliary_output)

    if module_name == "custom_ports":
        cleaned_output = _strip_ansi_codes(output)
        hosts: list[dict[str, object]] = []
        current_host: dict[str, object] | None = None

        def flush_current_host() -> None:
            nonlocal current_host
            if current_host is None:
                return

            ports = [port for port in current_host.get("ports", []) if isinstance(port, dict)]
            if ports:
                open_ports = [int(port.get("port") or 0) for port in ports if str(port.get("state") or "").lower() == "open"]
                services = [
                    _normalize_service_name(
                        int(port.get("port") or 0),
                        str(port.get("protocol") or "tcp"),
                        str(port.get("state") or "open"),
                        str(port.get("details") or ""),
                    )
                    for port in ports
                    if str(port.get("state") or "").lower() == "open"
                ]
                current_host["ports"] = ports
                current_host["open_ports"] = list(dict.fromkeys(port for port in open_ports if port > 0))
                current_host["services"] = services
                current_host["risk_level"] = _risk_level_for_services(services)
                hosts.append(current_host)

            current_host = None

        for raw_line in cleaned_output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            host_match = HOST_REPORT_PATTERN.match(line)
            if host_match:
                flush_current_host()

                host_label = host_match.group(1).strip()
                ip_address = host_match.group(2).strip() if host_match.group(2) else None

                current_host = _new_host_entry(host_label, ip_address)
                current_host["ports"] = []
                continue

            if current_host is None:
                continue

            port_match = CUSTOM_PORT_LINE_PATTERN.match(line)
            if port_match:
                port = int(port_match.group(1))
                protocol = port_match.group(2).lower()
                state = _normalize_port_state(port_match.group(3))
                details = (port_match.group(4) or "").strip()
                service_name = details.split()[0] if details else "unknown"

                current_host["ports"].append(
                    {
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "details": details,
                    }
                )

        flush_current_host()
        return hosts

    cleaned_output = _strip_ansi_codes(output)

    hosts: list[dict[str, object]] = []
    current_host: dict[str, object] | None = None

    def flush_current_host() -> None:
        nonlocal current_host
        if current_host is None:
            return

        open_ports = [port for port in current_host.get("open_ports", []) if isinstance(port, int)]
        services = [service for service in current_host.get("services", []) if isinstance(service, dict)]

        if open_ports and not _is_network_address(str(current_host.get("host_ip") or ""), target):
            current_host["open_ports"] = list(dict.fromkeys(open_ports))
            current_host["services"] = services
            current_host["risk_level"] = _risk_level_for_services(services)
            hosts.append(current_host)

        current_host = None

    for raw_line in cleaned_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        host_match = HOST_REPORT_PATTERN.match(line)
        if host_match:
            flush_current_host()

            host_label = host_match.group(1).strip()
            ip_address = host_match.group(2).strip() if host_match.group(2) else None

            current_host = _new_host_entry(host_label, ip_address)
            continue

        if current_host is None:
            continue

        port_match = PORT_LINE_PATTERN.match(line)
        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2).lower()
            details = (port_match.group(3) or "").strip()

            current_host["open_ports"].append(port)
            current_host["services"].append(_normalize_service_name(port, protocol, "open", details))
            continue

    flush_current_host()

    return hosts


def _normalize_target(target: str) -> str:
    value = str(target or "").strip()
    if not value:
        raise ValueError("Target cannot be empty.")
    return value


def _normalize_ip_target(target: str) -> str:
    value = _normalize_target(target)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _build_result(
    *,
    status: str,
    command: str,
    output: str = "",
    error: str = "",
    duration: float = 0.0,
) -> dict[str, object]:
    return {
        "status": status,
        "command": command,
        "output": _strip_ansi_codes(output),
        "error": _strip_ansi_codes(error),
        "duration": round(duration, 3),
    }


def _run_command(command: list[str], timeout: int) -> dict[str, object]:
    start_time = time.monotonic()
    command_display = " ".join(command)

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except FileNotFoundError as exc:
        logger.exception("Executable not found for command: %s", command_display)
        return _build_result(
            status="error",
            command=command_display,
            error=f"Executable not found: {exc.filename or command[0]}",
            duration=time.monotonic() - start_time,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("Command timeout (%ss): %s", timeout, command_display)
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return _build_result(
            status="timeout",
            command=command_display,
            output=str(stdout),
            error=str(stderr) or f"Command exceeded timeout of {timeout}s.",
            duration=time.monotonic() - start_time,
        )
    except Exception as exc:
        logger.exception("Error running command: %s", command_display)
        return _build_result(
            status="error",
            command=command_display,
            error=str(exc),
            duration=time.monotonic() - start_time,
        )

    duration = time.monotonic() - start_time
    stdout = process.stdout or ""
    stderr = process.stderr or ""

    stderr_lower = stderr.lower()
    if process.returncode == 0 or ("rttvar" in stderr_lower and stdout.strip()):
        return _build_result(
            status="success",
            command=command_display,
            output=stdout,
            error=stderr,
            duration=duration,
        )

    return _build_result(
        status="error",
        command=command_display,
        output=stdout,
        error=stderr or f"Command exited with code {process.returncode}.",
        duration=duration,
    )


def _run_nmap_scan(target: str, args: list[str], timeout: int) -> dict[str, object]:
    command = ["nmap", *args, target]
    return _run_command(command, timeout)


def _with_module_guard(
    runner: Callable[[], dict[str, object]],
    module_name: str,
    timeout: int,
) -> dict[str, object]:
    try:
        result = runner()
        if not isinstance(result, dict):
            return _build_result(
                status="error",
                command=module_name,
                error="Module runner returned an invalid result.",
                duration=0.0,
            )
        result.setdefault("status", "error")
        result.setdefault("command", module_name)
        result.setdefault("output", "")
        result.setdefault("error", "")
        result.setdefault("duration", 0.0)
        return result
    except subprocess.TimeoutExpired as exc:
        logger.warning("Module %s timed out after %ss", module_name, timeout)
        return _build_result(
            status="timeout",
            command=module_name,
            error=str(exc) or f"{module_name} exceeded timeout of {timeout}s.",
            duration=0.0,
        )
    except Exception as exc:
        logger.exception("Unexpected error in module %s: %s", module_name, exc)
        return _build_result(
            status="error",
            command=module_name,
            error=str(exc),
            duration=0.0,
        )


def run_host_discovery(target: str) -> dict[str, object]:
    timeout = 120

    def runner() -> dict[str, object]:
        normalized = _normalize_target(target)
        return _run_nmap_scan(
            normalized,
            ["-sn", "--max-retries", "1", "--host-timeout", "10s"],
            timeout,
        )

    return _with_module_guard(runner, "run_host_discovery", timeout)


def run_camera_scan(target: str) -> dict[str, object]:
    timeout = 240

    def runner() -> dict[str, object]:
        normalized = _normalize_target(target)
        discovery_command = ["nmap", *CAMERA_DISCOVERY_ARGS, normalized]
        discovery_result = _run_command(discovery_command, timeout)
        discovery_output = str(discovery_result.get("output", "") or "")
        discovered_hosts = _collect_discovery_hosts(discovery_output, normalized)
        active_hosts = [host for host in discovered_hosts if str(host.get("state") or "").lower() == "up"]

        phase_sections = [
            _build_camera_section("Phase 1 - Host discovery", " ".join(discovery_command), discovery_result),
        ]

        probable_cameras: list[dict[str, object]] = []
        whatweb_outputs: list[str] = []
        whatweb_commands: list[str] = []
        scanned_hosts = 0

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", newline="\n") as active_hosts_file:
            for host in active_hosts:
                host_ip = str(host.get("host_ip") or "").strip()
                if host_ip:
                    active_hosts_file.write(f"{host_ip}\n")
            active_hosts_file_path = active_hosts_file.name

        try:
            if active_hosts:
                scanned_hosts = len(active_hosts)
                port_scan_command = ["nmap", *CAMERA_PORT_ARGS, "-iL", active_hosts_file_path]
                port_scan_result = _run_command(port_scan_command, timeout)
                port_scan_output = str(port_scan_result.get("output", "") or "")
                phase_sections.append(_build_camera_section("Phase 2 - Camera port scan", " ".join(port_scan_command), port_scan_result))

                for host_entry in _collect_camera_hosts(port_scan_output, normalized):
                    host_ip = str(host_entry.get("host_ip") or "").strip()
                    if not host_ip:
                        continue

                    open_ports = [int(port) for port in host_entry.get("open_ports", []) if isinstance(port, int)]
                    camera_ports = [port for port in open_ports if port in CAMERA_HTTP_PORTS or port in CAMERA_RTSP_PORTS or port in CAMERA_CUSTOM_PORTS]
                    if not camera_ports:
                        continue

                    camera_probe_command = [
                        "nmap",
                        *CAMERA_VERSION_ARGS,
                        "-p",
                        ",".join(str(port) for port in camera_ports),
                        host_ip,
                    ]
                    camera_probe_result = _run_command(camera_probe_command, timeout)
                    camera_probe_output = str(camera_probe_result.get("output", "") or "")
                    if camera_probe_output:
                        phase_sections.append(_build_camera_section(f"Phase 3 - Lightweight service detection ({host_ip})", " ".join(camera_probe_command), camera_probe_result))

                    enriched_host = host_entry
                    if camera_probe_output:
                        probe_hosts = _collect_camera_hosts(camera_probe_output, host_ip, "")
                        if probe_hosts:
                            enriched_host = _merge_camera_host_entries(host_entry, probe_hosts[0])

                    http_ports = [port for port in camera_ports if port in CAMERA_HTTP_PORTS or port in CAMERA_HTTPS_PORTS]
                    if http_ports:
                        chosen_port = 443 if 443 in http_ports else 8443 if 8443 in http_ports else http_ports[0]
                        url = _build_camera_url(host_ip, chosen_port)
                        whatweb_command = ["whatweb", "--no-errors", "--color=never", url]
                        whatweb_result = _run_command(whatweb_command, 45)
                        whatweb_commands.append(" ".join(whatweb_command))
                        whatweb_output = str(whatweb_result.get("output", "") or "").strip()
                        if whatweb_output:
                            whatweb_outputs.append(f"--- WhatWeb {host_ip}:{chosen_port} ---\n{whatweb_output}")
                            enriched_host["whatweb_output"] = whatweb_output

                    _refresh_camera_host_metadata(enriched_host)
                    probable_cameras.append(enriched_host)
        finally:
            try:
                import os

                os.unlink(active_hosts_file_path)
            except OSError:
                pass

        combined_raw_output = "\n\n".join(section for section in [*phase_sections, *whatweb_outputs] if section).strip()
        combined_whatweb_output = "\n".join(whatweb_outputs).strip()
        camera_port_command_summary = "nmap " + " ".join(CAMERA_PORT_ARGS) + " -iL <active-hosts>"

        result = dict(discovery_result)
        result["command"] = " ; ".join([
            " ".join(discovery_command),
            camera_port_command_summary,
            "optional nmap -sV --version-light on camera ports",
        ])
        result["output"] = combined_raw_output or discovery_output
        result["raw_output"] = result["output"]
        result["discovery_output"] = discovery_output
        result["discovery_total_hosts"] = len(active_hosts)
        result["camera_hosts_scanned"] = scanned_hosts
        result["probable_cameras_detected"] = len(probable_cameras)
        result["whatweb_output"] = combined_whatweb_output
        result["whatweb_commands"] = whatweb_commands
        result["parsed_results"] = probable_cameras

        return result

    return _with_module_guard(runner, "run_camera_scan", timeout)


def run_smb_audit(target: str) -> dict[str, object]:
    timeout = 150

    def runner() -> dict[str, object]:
        normalized = _normalize_ip_target(target)
        return _run_nmap_scan(
            normalized,
            ["-p", "445,139", "--script", "smb-os-discovery", "--open", "--max-retries", "1", "--host-timeout", "10s"],
            timeout,
        )

    return _with_module_guard(runner, "run_smb_audit", timeout)


def run_rdp_scan(target: str) -> dict[str, object]:
    timeout = 120

    def runner() -> dict[str, object]:
        normalized = _normalize_ip_target(target)
        return _run_nmap_scan(
            normalized,
            ["-p", "3389", "--open", "--max-retries", "1", "--host-timeout", "10s"],
            timeout,
        )

    return _with_module_guard(runner, "run_rdp_scan", timeout)


def run_database_scan(target: str) -> dict[str, object]:
    timeout = 120

    def runner() -> dict[str, object]:
        normalized = _normalize_ip_target(target)
        return _run_nmap_scan(
            normalized,
            ["-p", "3306,5432,6379,27017", "--open", "--max-retries", "1", "--host-timeout", "10s"],
            timeout,
        )

    return _with_module_guard(runner, "run_database_scan", timeout)


def run_web_server_scan(target: str) -> dict[str, object]:
    timeout = 120

    def runner() -> dict[str, object]:
        normalized = _normalize_target(target)
        return _run_nmap_scan(
            normalized,
            ["-p", "80,443,8080,8443", "--open", "--max-retries", "1", "--host-timeout", "10s"],
            timeout,
        )

    return _with_module_guard(runner, "run_web_server_scan", timeout)


def run_printer_scan(target: str) -> dict[str, object]:
    timeout = 120

    def runner() -> dict[str, object]:
        normalized = _normalize_ip_target(target)
        return _run_nmap_scan(
            normalized,
            ["-p", "9100,515,631", "--open", "--max-retries", "1", "--host-timeout", "10s"],
            timeout,
        )

    return _with_module_guard(runner, "run_printer_scan", timeout)


def run_ssh_scan(target: str) -> dict[str, object]:
    timeout = 120

    def runner() -> dict[str, object]:
        normalized = _normalize_ip_target(target)
        return _run_nmap_scan(
            normalized,
            ["-p", "22", "--open", "--max-retries", "1", "--host-timeout", "10s"],
            timeout,
        )

    return _with_module_guard(runner, "run_ssh_scan", timeout)


def run_telnet_scan(target: str) -> dict[str, object]:
    timeout = 120

    def runner() -> dict[str, object]:
        normalized = _normalize_ip_target(target)
        return _run_nmap_scan(
            normalized,
            ["-p", "23", "--open", "--max-retries", "1", "--host-timeout", "10s"],
            timeout,
        )

    return _with_module_guard(runner, "run_telnet_scan", timeout)