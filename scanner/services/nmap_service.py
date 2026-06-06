import ipaddress
import re
import subprocess


class NmapServiceError(Exception):
    """Base exception for Nmap service errors."""


class NmapNotInstalledError(NmapServiceError):
    """Raised when nmap is not available in PATH."""


class BashUnavailableError(NmapServiceError):
    """Raised when bash cannot be started on the host machine."""


class NmapScanTimeoutError(NmapServiceError):
    """Raised when nmap scan exceeds timeout."""


class NmapScanExecutionError(NmapServiceError):
    """Raised when nmap returns an execution error."""


HOST_REPORT_PATTERN = re.compile(r"^Nmap scan report for (.+?)(?: \(([^)]+)\))?$", flags=re.IGNORECASE)
PORT_LINE_PATTERN = re.compile(r"^\s*(\d+)/(tcp|udp)\s+open\s*(.*)$", flags=re.IGNORECASE)
VULNERABLE_MARKER_PATTERN = re.compile(r"\bvulnerable\b", flags=re.IGNORECASE)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", flags=re.IGNORECASE)
RISK_FACTOR_PATTERN = re.compile(r"risk factor:\s*([^\n]+)", flags=re.IGNORECASE)
STATE_PATTERN = re.compile(r"state:\s*([^\n]+)", flags=re.IGNORECASE)
HIGH_RISK_PORTS = {23, 3389, 3306, 5432, 6379, 27017, 1433, 1521}
MEDIUM_RISK_PORTS = {22, 80, 443, 445, 139, 8080, 8443, 631, 515, 9100}
RISK_POINTS = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def _build_nmap_command(ip: str, scan_type: str) -> list[str]:
    scan_commands = {
        "quick": ["nmap", "-F", ip],
        "service": ["nmap", "-sV", ip],
        "vuln": ["nmap", "-sV", "--script", "vuln", ip],
        "os": ["nmap", "-O", ip],
    }

    try:
        return scan_commands[scan_type]
    except KeyError as exc:
        raise NmapScanExecutionError("Type de scan invalide.") from exc


def _risk_for_port(port: int, service_name: str) -> str:
    normalized_service = service_name.strip().lower()

    # Specific mappings: port 445 (SMB) treated as HIGH risk per policy.
    if port == 445:
        return "HIGH"

    if port in HIGH_RISK_PORTS or normalized_service in {"telnet", "rdp", "mysql", "postgresql", "mongodb", "redis", "mssql", "oracle"}:
        return "HIGH"

    if port in MEDIUM_RISK_PORTS or normalized_service in {"smb", "microsoft-ds", "netbios-ssn", "ssh", "http", "https", "ftp", "ipp", "printer", "jetdirect"}:
        return "MEDIUM"

    return "LOW"


def parse_nmap_output(output: str) -> list[dict[str, object]]:
    """Parse Nmap textual output into structured open-port findings only."""
    findings: list[dict[str, object]] = []
    current_host_label = ""
    current_host_ip = ""

    def update_host(match: re.Match[str]) -> None:
        nonlocal current_host_label, current_host_ip
        current_host_label = match.group(1).strip()
        current_host_ip = match.group(2).strip() if match.group(2) else current_host_label

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        host_match = HOST_REPORT_PATTERN.match(line)
        if host_match:
            update_host(host_match)
            continue

        match = PORT_LINE_PATTERN.match(line)
        if not match:
            continue

        port = int(match.group(1))
        protocol = match.group(2).lower()
        details = (match.group(3) or "").strip()
        service = details.split()[0] if details else "unknown"

        findings.append(
            {
                "host_ip": current_host_ip,
                "hostname": "" if current_host_ip == current_host_label else current_host_label,
                "port": port,
                "protocol": protocol,
                "state": "open",
                "service": service,
                "risk": _risk_for_port(port, service),
                "description": f"{port}/{protocol} open {details}".strip(),
            }
        )

    return findings


def parse_vulnerability_findings(output: str) -> list[dict[str, object]]:
    """Extract Nmap vuln script findings with CVEs, risk and affected service."""
    findings: list[dict[str, object]] = []
    current_service: dict[str, object] | None = None
    current_finding: dict[str, object] | None = None

    def flush_current_finding() -> None:
        nonlocal current_finding
        if not current_finding:
            return

        cves = list(dict.fromkeys(current_finding.get("cves", [])))
        raw_lines = current_finding.get("raw_lines", [])
        description = str(current_finding.get("description") or "").strip()
        if not description and raw_lines:
            description = next((line for line in raw_lines if line), "").strip()

        finding = {
            "port": current_finding.get("port"),
            "protocol": current_finding.get("protocol"),
            "state": current_finding.get("state"),
            "service": current_finding.get("service"),
            "title": current_finding.get("title") or description or "Vulnérabilité détectée",
            "risk": current_finding.get("risk") or "MEDIUM",
            "description": description,
            "cves": cves,
            "raw_output": "\n".join(str(line) for line in raw_lines if line).strip(),
        }

        if finding["title"] or finding["description"] or finding["cves"]:
            findings.append(finding)

        current_finding = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        normalized = stripped.lstrip("|_").strip()

        if not stripped:
            if current_finding is not None:
                current_finding.setdefault("raw_lines", []).append("")
            continue

        service_match = PORT_LINE_PATTERN.match(normalized)
        if service_match:
            flush_current_finding()
            current_service = {
                "port": int(service_match.group(1)),
                "protocol": service_match.group(2).lower(),
                "state": "open",
                "service": ((service_match.group(3) or "").strip().split() or ["unknown"])[0],
            }
            continue

        lower_line = normalized.lower()
        is_vulnerable_marker = normalized.upper().startswith("VULNERABLE:") or lower_line.startswith("vulnerable:")
        if is_vulnerable_marker:
            if current_service is None:
                current_service = {
                    "port": None,
                    "protocol": None,
                    "state": None,
                    "service": "unknown",
                }

            flush_current_finding()
            current_finding = {
                **current_service,
                "title": "",
                "description": "",
                "risk": "MEDIUM",
                "cves": [],
                "raw_lines": [],
            }

            title_line = normalized
            if title_line.upper() == "VULNERABLE:" or title_line.lower().startswith("vulnerable:"):
                title_line = ""
            if title_line:
                current_finding["title"] = title_line
                current_finding["description"] = title_line
            current_finding["raw_lines"].append(normalized)
            continue

        if current_finding is None:
            continue

        current_finding.setdefault("raw_lines", []).append(normalized)

        cves = CVE_PATTERN.findall(normalized)
        if cves:
            current_finding.setdefault("cves", []).extend(cves)

        risk_match = RISK_FACTOR_PATTERN.search(normalized)
        if risk_match:
            risk_value = risk_match.group(1).strip().upper()
            if risk_value.startswith("CRITICAL") or risk_value.startswith("HIGH"):
                current_finding["risk"] = "HIGH"
            elif risk_value.startswith("MEDIUM"):
                current_finding["risk"] = "MEDIUM"
            elif risk_value.startswith("LOW"):
                current_finding["risk"] = "LOW"

        state_match = STATE_PATTERN.search(normalized)
        if state_match:
            state_value = state_match.group(1).strip()
            current_finding["state"] = state_value
            state_upper = state_value.upper()
            if "VULNERABLE" in state_upper or "LIKELY" in state_upper:
                current_finding["risk"] = "HIGH"

        if not current_finding.get("title"):
            metadata_prefixes = (
                "ids:",
                "risk factor:",
                "state:",
                "references:",
                "disclosure date:",
                "extra information:",
            )
            if not lower_line.startswith(metadata_prefixes) and not lower_line.startswith("http"):
                current_finding["title"] = normalized
                if not current_finding.get("description"):
                    current_finding["description"] = normalized

    flush_current_finding()
    return findings


def calculate_risk_score(findings: list[dict[str, object]]) -> dict[str, object]:
    """Return weighted score and global risk level for parsed findings."""
    total_score = 0
    risk_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in findings:
        risk = str(finding.get("risk") or "LOW").upper()
        if risk not in RISK_POINTS:
            risk = "LOW"
        risk_count[risk] += 1
        total_score += RISK_POINTS[risk]

    if total_score >= 8:
        global_level = "HIGH"
    elif total_score >= 4:
        global_level = "MEDIUM"
    else:
        global_level = "LOW"

    return {
        "score_total": total_score,
        "global_level": global_level,
        "risk_count": risk_count,
    }


def detect_os_from_output(output: str) -> str:
    """Return a simple OS label from Nmap output."""
    lowered = output.lower()

    windows_markers = (
        "microsoft windows",
        "windows",
        "microsoft-ds",
        "netbios",
        "smb",
        "rdp",
    )
    linux_markers = (
        "linux",
        "ubuntu",
        "debian",
        "centos",
        "red hat",
        "fedora",
        "unix",
    )

    if any(marker in lowered for marker in windows_markers):
        return "Windows"
    if any(marker in lowered for marker in linux_markers):
        return "Linux"
    return "Unknown"


def run_nmap_scan(ip: str, scan_type: str = "service") -> tuple[str, str]:
    """Run an Nmap scan and return stdout along with the command used."""
    try:
        safe_ip = str(ipaddress.IPv4Address(ip.strip()))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise NmapScanExecutionError("Adresse IP invalide pour le scan.") from exc

    command = _build_nmap_command(safe_ip, scan_type)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise NmapNotInstalledError("nmap n'est pas installe ou introuvable dans le PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise NmapScanTimeoutError("Le scan a depasse le delai autorise (120s).") from exc
    except PermissionError as exc:
        raise NmapScanExecutionError("Permissions insuffisantes pour executer Nmap.") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        details = "\n".join(part for part in [stdout, stderr] if part) or "Aucun detail disponible."
        raise NmapScanExecutionError(f"Erreur lors de l'execution de Nmap: {details}") from exc

    return result.stdout, " ".join(command)
