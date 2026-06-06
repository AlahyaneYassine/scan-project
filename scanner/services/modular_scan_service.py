"""
Modular scan service providing independent scan modules for security testing.
Each module handles a specific scan type with consistent error handling and output formatting.
"""

import ipaddress
import re
import subprocess
import time
from typing import Optional

from .scan_validation_service import WEB_COMMON_PORTS, parse_web_target


class ModularScanError(Exception):
    """Base exception for modular scan errors."""


class ScanTimeoutError(ModularScanError):
    """Raised when a scan exceeds timeout."""


class ScanExecutionError(ModularScanError):
    """Raised when a scan returns an execution error."""


class ToolNotFoundError(ModularScanError):
    """Raised when a required tool is not available in PATH."""


class InvalidInputError(ModularScanError):
    """Raised when input validation fails."""


# ANSI escape code pattern
ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*m')


def _strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return ANSI_ESCAPE_PATTERN.sub('', text)


def _validate_ip(ip: str) -> str:
    """Validate and normalize a single IP address."""
    try:
        return str(ipaddress.IPv4Address(ip.strip()))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise InvalidInputError(f"Invalid IP address: {ip}") from exc


def _validate_cidr(cidr: str) -> str:
    """Validate and normalize a CIDR notation."""
    try:
        network = ipaddress.IPv4Network(cidr.strip(), strict=False)
        return str(network)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise InvalidInputError(f"Invalid CIDR notation: {cidr}") from exc


def _validate_ports(ports: str) -> str:
    """Validate port specification."""
    ports = ports.strip()
    if not ports:
        raise InvalidInputError("Port specification cannot be empty")
    
    # Allow comma-separated ports, ranges like 80-443, and keywords
    valid_chars = set('0123456789,-')
    if not all(c in valid_chars for c in ports):
        raise InvalidInputError(f"Invalid port specification: {ports}")
    
    return ports


def _execute_command(
    command: list[str],
    timeout: int,
    tool_name: str = "Tool"
) -> tuple[str, str, int, float]:
    """
    Execute a command and return stdout, stderr, exit status, and duration.
    
    Args:
        command: Command as list of strings (for shell=False)
        timeout: Timeout in seconds
        tool_name: Name of tool for error messages
        
    Returns:
        Tuple of (stdout, stderr, status, duration)
    """
    start_time = time.time()
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        duration = time.time() - start_time
        
        stdout = _strip_ansi_codes(result.stdout)
        stderr = _strip_ansi_codes(result.stderr)
        
        return stdout, stderr, result.returncode, duration
        
    except FileNotFoundError as exc:
        duration = time.time() - start_time
        raise ToolNotFoundError(
            f"{tool_name} is not installed or not found in PATH"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        duration = time.time() - start_time
        raise ScanTimeoutError(
            f"{tool_name} scan exceeded timeout ({timeout}s)"
        ) from exc
    except PermissionError as exc:
        duration = time.time() - start_time
        raise ScanExecutionError(
            f"Insufficient permissions to execute {tool_name}"
        ) from exc


def _build_web_url(host: str, port: int, path: str = "") -> str:
    scheme = "https" if port in {443, 8443} else "http"
    normalized_path = path if path.startswith("/") or not path else f"/{path}"
    return f"{scheme}://{host}:{port}{normalized_path}"


def _extract_open_ports(output: str, allowed_ports: set[int]) -> list[int]:
    detected_ports: list[int] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+", line, re.IGNORECASE)
        if not match:
            continue

        port = int(match.group(1))
        protocol = match.group(2).lower()
        if protocol == "tcp" and port in allowed_ports and port not in detected_ports:
            detected_ports.append(port)

    return detected_ports


def _run_web_tool_scan(url: str, timeout: int) -> dict[str, object]:
    scan_result = {
        "stdout": "",
        "stderr": "",
        "status": 0,
        "duration": 0.0,
        "command": "",
        "tools_used": [],
        "whatweb": {},
        "nuclei": {},
    }

    try:
        whatweb_command = ["whatweb", url]
        stdout, stderr, status, duration = _execute_command(whatweb_command, timeout, "whatweb")
        scan_result["whatweb"] = {
            "stdout": stdout,
            "stderr": stderr,
            "status": status,
            "duration": duration,
            "command": " ".join(whatweb_command),
        }
        scan_result["tools_used"].append("whatweb")
        scan_result["stdout"] += f"\n--- WhatWeb Output ---\n{stdout}"
        if stderr:
            scan_result["stderr"] += f"\n--- WhatWeb Errors ---\n{stderr}"
    except ToolNotFoundError:
        scan_result["whatweb"]["error"] = "whatweb not installed"
    except Exception as exc:
        scan_result["whatweb"]["error"] = str(exc)

    try:
        nuclei_command = ["nuclei", "-u", url, "-silent"]
        stdout, stderr, status, duration = _execute_command(nuclei_command, timeout, "nuclei")
        scan_result["nuclei"] = {
            "stdout": stdout,
            "stderr": stderr,
            "status": status,
            "duration": duration,
            "command": " ".join(nuclei_command),
        }
        scan_result["tools_used"].append("nuclei")
        scan_result["stdout"] += f"\n--- Nuclei Output ---\n{stdout}"
        if stderr:
            scan_result["stderr"] += f"\n--- Nuclei Errors ---\n{stderr}"
    except ToolNotFoundError:
        scan_result["nuclei"]["error"] = "nuclei not installed"
    except Exception as exc:
        scan_result["nuclei"]["error"] = str(exc)

    return scan_result

def host_discovery(cidr: str, timeout: int = 300) -> dict:
    """
    Discover live hosts on a network using ping scan.
    
    Args:
        cidr: Network in CIDR notation (e.g., 192.168.1.0/24)
        timeout: Timeout in seconds (default: 300)
        
    Returns:
        Dictionary with keys: stdout, stderr, status, duration, command
    """
    cidr = _validate_cidr(cidr)
    command = ["nmap", "-sn", cidr]
    
    stdout, stderr, status, duration = _execute_command(command, timeout, "nmap")
    
    return {
        "stdout": stdout,
        "stderr": stderr,
        "status": status,
        "duration": duration,
        "command": " ".join(command),
    }


def network_audit(cidr: str, timeout: int = 600) -> dict:
    """
    Perform network audit scanning top ports on a network.
    
    Args:
        cidr: Network in CIDR notation (e.g., 192.168.1.0/24)
        timeout: Timeout in seconds (default: 600)
        
    Returns:
        Dictionary with keys: stdout, stderr, status, duration, command
    """
    cidr = _validate_cidr(cidr)
    command = ["nmap", "-T4", "--top-ports", "100", "--open", cidr]
    
    stdout, stderr, status, duration = _execute_command(command, timeout, "nmap")
    
    return {
        "stdout": stdout,
        "stderr": stderr,
        "status": status,
        "duration": duration,
        "command": " ".join(command),
    }


def fast_scan(ip: str, timeout: int = 120) -> dict:
    """
    Perform a fast scan on a single IP using only top 100 ports.
    
    Args:
        ip: Target IP address
        timeout: Timeout in seconds (default: 120)
        
    Returns:
        Dictionary with keys: stdout, stderr, status, duration, command
    """
    ip = _validate_ip(ip)
    command = ["nmap", "-F", ip]
    
    stdout, stderr, status, duration = _execute_command(command, timeout, "nmap")
    
    return {
        "stdout": stdout,
        "stderr": stderr,
        "status": status,
        "duration": duration,
        "command": " ".join(command),
    }


def service_detection(ip: str, timeout: int = 300) -> dict:
    """
    Detect services and versions running on open ports.
    
    Args:
        ip: Target IP address
        timeout: Timeout in seconds (default: 300)
        
    Returns:
        Dictionary with keys: stdout, stderr, status, duration, command
    """
    ip = _validate_ip(ip)
    command = ["nmap", "-sV", ip]
    
    stdout, stderr, status, duration = _execute_command(command, timeout, "nmap")
    
    return {
        "stdout": stdout,
        "stderr": stderr,
        "status": status,
        "duration": duration,
        "command": " ".join(command),
    }


def vulnerability_scan(ip: str, timeout: int = 600) -> dict:
    """
    Scan for vulnerabilities using NSE vulnerability scripts.
    
    Args:
        ip: Target IP address
        timeout: Timeout in seconds (default: 600)
        
    Returns:
        Dictionary with keys: stdout, stderr, status, duration, command
    """
    ip = _validate_ip(ip)
    command = ["nmap", "-sV", "--script", "vuln", "--script-timeout", "120s", ip]
    
    stdout, stderr, status, duration = _execute_command(command, timeout, "nmap")
    
    return {
        "stdout": stdout,
        "stderr": stderr,
        "status": status,
        "duration": duration,
        "command": " ".join(command),
    }


def web_scan(url: str, timeout: int = 300) -> dict:
    """
    Perform web application scanning using whatweb and nuclei.
    
    Args:
        url: Target URL (e.g., http://example.com)
        timeout: Timeout in seconds (default: 300)
        
    Returns:
        Dictionary with keys: stdout, stderr, status, duration, command, tools_used
    """
    target_info = parse_web_target(url)
    normalized_url = str(target_info["normalized_url"])
    host = str(target_info["host"])
    path = str(target_info["path"] or "")
    is_ip = bool(target_info["is_ip"])
    explicit_port = target_info["port"]

    if not normalized_url:
        raise InvalidInputError("URL cannot be empty")

    results = {
        "stdout": "",
        "stderr": "",
        "status": 0,
        "duration": 0.0,
        "command": "",
        "tools_used": [],
        "whatweb": {},
        "nuclei": {},
        "web_ports": [],
        "detected_web_ports": [],
        "message": "",
    }
    
    start_time = time.time()

    target_urls = [normalized_url]
    detection_output = ""
    if is_ip and explicit_port is None and not path:
        detection_command = [
            "nmap",
            "-Pn",
            "-n",
            "-sV",
            "--open",
            "--max-retries",
            "1",
            "--host-timeout",
            "20s",
            "-p",
            ",".join(str(port) for port in WEB_COMMON_PORTS),
            host,
        ]
        stdout, stderr, status, duration = _execute_command(detection_command, timeout, "nmap")
        results["tools_used"].append("nmap")
        results["command"] = " ".join(detection_command)
        results["web_ports"] = _extract_open_ports(stdout, set(WEB_COMMON_PORTS))
        results["detected_web_ports"] = list(results["web_ports"])
        detection_output = stdout
        if stderr:
            results["stderr"] = stderr

        if not results["web_ports"]:
            results["duration"] = time.time() - start_time
            message = "No HTTP service detected on common web ports."
            results["message"] = message
            results["stdout"] = message
            results["status"] = "warning"
            return results

        target_urls = [_build_web_url(host, port) for port in results["web_ports"]]
        results["stdout"] = detection_output

    for web_url in target_urls:
        tool_result = _run_web_tool_scan(web_url, timeout)
        for tool_name in ("whatweb", "nuclei"):
            tool_details = tool_result.get(tool_name, {})
            if tool_details:
                results[tool_name] = tool_details
        if tool_result.get("stdout"):
            results["stdout"] = "\n".join(part for part in [results["stdout"], tool_result["stdout"]] if part).strip()
        if tool_result.get("stderr"):
            results["stderr"] = "\n".join(part for part in [results["stderr"], tool_result["stderr"]] if part).strip()
        results["tools_used"].extend([tool for tool in tool_result.get("tools_used", []) if tool not in results["tools_used"]])
        if not results["command"]:
            results["command"] = f"whatweb {web_url} && nuclei -u {web_url} -silent"
        else:
            results["command"] += f" ; whatweb {web_url} && nuclei -u {web_url} -silent"

    results["duration"] = time.time() - start_time

    if not results["tools_used"]:
        raise ToolNotFoundError("Neither whatweb nor nuclei is installed")

    return results


def custom_ports(ip: str, ports: str, timeout: int = 300) -> dict:
    """
    Scan specific ports with service detection.
    
    Args:
        ip: Target IP address
        ports: Port specification (e.g., "22,80,443" or "1-1000")
        timeout: Timeout in seconds (default: 300)
        
    Returns:
        Dictionary with keys: stdout, stderr, status, duration, command
    """
    ip = _validate_ip(ip)
    ports = _validate_ports(ports)
    command = ["nmap", "-sV", "-p", ports, ip]
    
    stdout, stderr, status, duration = _execute_command(command, timeout, "nmap")
    
    return {
        "stdout": stdout,
        "stderr": stderr,
        "status": status,
        "duration": duration,
        "command": " ".join(command),
    }
