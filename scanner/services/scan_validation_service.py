"""
Strict validation service for modular scan operations.
Determines target type, enforces scan type restrictions, and validates input formats.
"""

import ipaddress
import re
from urllib.parse import urlparse, urlunparse
from enum import Enum


class TargetType(Enum):
    """Enumeration of target types."""
    SINGLE_IP = "single_ip"
    CIDR = "cidr"


class ValidationError(Exception):
    """Base exception for validation errors."""
    
    def __init__(self, message: str, error_code: str = "VALIDATION_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)
    
    def to_json(self) -> dict:
        """Convert error to JSON response format."""
        return {
            "success": False,
            "error_code": self.error_code,
            "message": self.message,
        }


class InvalidTargetError(ValidationError):
    """Raised when target format is invalid."""
    
    def __init__(self, message: str):
        super().__init__(message, "INVALID_TARGET")


class InvalidScanTypeError(ValidationError):
    """Raised when scan type is not allowed for target."""
    
    def __init__(self, message: str):
        super().__init__(message, "INVALID_SCAN_TYPE")


class InvalidPortsError(ValidationError):
    """Raised when port specification is invalid."""
    
    def __init__(self, message: str):
        super().__init__(message, "INVALID_PORTS")


class InvalidURLError(ValidationError):
    """Raised when URL format is invalid."""
    
    def __init__(self, message: str):
        super().__init__(message, "INVALID_URL")


# Allowed scan types per target type
NETWORK_MODULES = {
    "host_discovery",
    "network_audit",
    "camera_scan",
    "smb_audit",
    "rdp_scan",
    "database_scan",
    "web_server_scan",
    "printer_scan",
    "ssh_scan",
    "telnet_scan",
}

SINGLE_HOST_MODULES = {
    "vulnerability_scan",
    "web_scan",
    "fast_scan",
    "service_detection",
    "custom_ports",
}

SCAN_TYPE_MAPPING = {
    TargetType.CIDR: NETWORK_MODULES,
    TargetType.SINGLE_IP: SINGLE_HOST_MODULES,
}

# Port format pattern: comma-separated numbers/ranges
PORT_PATTERN = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$')

# URL pattern: basic validation
URL_PATTERN = re.compile(r'^(https?://)?[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+(:\d+)?(/.*)?$')
WEB_COMMON_PORTS = (80, 443, 8080, 8000, 8443)


def _is_network_address(ip: str) -> bool:
    """Return True when the address looks like a network boundary host."""
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        return str(addr).endswith(".0") or str(addr).endswith(".255")
    except (ipaddress.AddressValueError, ValueError):
        return False


def _validate_cidr_target(target: str, allow_public: bool = False) -> str:
    target = target.strip()

    if "/" not in target:
        raise InvalidTargetError("Veuillez saisir un réseau CIDR valide, exemple: 192.168.18.0/24")

    try:
        network = ipaddress.IPv4Network(target, strict=False)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise InvalidTargetError("Veuillez saisir un réseau CIDR valide, exemple: 192.168.18.0/24") from exc

    if network.network_address == network.broadcast_address:
        raise InvalidTargetError("Veuillez saisir un réseau CIDR valide, exemple: 192.168.18.0/24")

    if network.network_address == ipaddress.IPv4Address(target.split("/")[0]) and _is_network_address(str(network.network_address)):
        # Keep the explicit CIDR form but reject bare network-like hosts elsewhere.
        pass

    if network.is_global and not allow_public:
        raise InvalidTargetError("Ce module est réservé aux réseaux privés. Activez allow_public=true pour autoriser un réseau public.")

    return str(network)


def _validate_single_host_target(target: str) -> str:
    target = target.strip()

    if "/" in target:
        raise InvalidTargetError("Ce module nécessite une adresse IP unique.")

    try:
        ip = ipaddress.IPv4Address(target)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise InvalidTargetError("Ce module nécessite une adresse IP unique.") from exc

    if _is_network_address(str(ip)):
        raise InvalidTargetError("Ce module nécessite une adresse IP unique.")

    return str(ip)


def detect_target_type(target: str) -> TargetType:
    """
    Detect if target is a single IP or CIDR notation.
    
    Args:
        target: Target string (IP or CIDR)
        
    Returns:
        TargetType.SINGLE_IP or TargetType.CIDR
        
    Raises:
        InvalidTargetError: If target format is invalid
    """
    target = target.strip()
    
    if not target:
        raise InvalidTargetError("Veuillez saisir une cible valide.")
    
    # Check if it's CIDR notation
    if '/' in target:
        try:
            network = ipaddress.IPv4Network(target, strict=False)
            if network.network_address == network.broadcast_address:
                raise InvalidTargetError("Veuillez saisir un réseau CIDR valide, exemple: 192.168.18.0/24")
            return TargetType.CIDR
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise InvalidTargetError("Veuillez saisir un réseau CIDR valide, exemple: 192.168.18.0/24") from exc
    
    # Try to parse as single IP
    try:
        ip = ipaddress.IPv4Address(target)
        ip_str = str(ip)
        
        # Reject network addresses used as single host targets
        if _is_network_address(ip_str):
            raise InvalidTargetError(
                "Veuillez saisir un réseau CIDR valide, exemple: 192.168.18.0/24"
            )
        
        return TargetType.SINGLE_IP
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise InvalidTargetError("Veuillez saisir une cible valide.") from exc


def validate_scan_type(target: str, scan_type: str) -> tuple[TargetType, str]:
    """
    Validate that scan type is allowed for the target type.
    
    Args:
        target: Target string (IP or CIDR)
        scan_type: Scan type name
        
    Returns:
        Tuple of (target_type, scan_type)
        
    Raises:
        InvalidTargetError: If target is invalid
        InvalidScanTypeError: If scan type is not allowed for target
    """
    scan_type = scan_type.strip().lower()
    
    target_type = detect_target_type(target)
    
    # Check if scan type is allowed for this target type
    allowed_types = SCAN_TYPE_MAPPING[target_type]
    
    if scan_type not in allowed_types:
        if target_type == TargetType.CIDR:
            raise InvalidScanTypeError("Ce module est réservé aux réseaux CIDR.")
        raise InvalidScanTypeError("Ce module nécessite une adresse IP unique.")
    
    return target_type, scan_type


def validate_ports(ports: str) -> str:
    """
    Validate port specification format.
    Accepts only comma-separated single ports such as 80,443,8080.
    
    Args:
        ports: Port specification string
        
    Returns:
        Normalized port string
        
    Raises:
        InvalidPortsError: If format is invalid
    """
    ports = ports.strip()
    
    if not ports:
        raise InvalidPortsError("Veuillez saisir une liste de ports valide.")
    
    # Check basic format: only digits and commas are allowed.
    if not re.fullmatch(r"\d+(,\d+)*", ports):
        raise InvalidPortsError(
            "Format de ports invalide. Utilisez une liste séparée par des virgules, par exemple: 80,443,8080."
        )
    
    # Validate individual port numbers.
    for part in ports.split(','):
        try:
            port_num = int(part)
        except ValueError as exc:
            raise InvalidPortsError("Format de ports invalide. Utilisez une liste séparée par des virgules, par exemple: 80,443,8080.") from exc

        if port_num < 1 or port_num > 65535:
            raise InvalidPortsError("Chaque port doit être compris entre 1 et 65535.")
    
    return ports


def validate_url(url: str) -> str:
    """
    Validate and normalize URL format.
    
    Args:
        url: URL string
        
    Returns:
        Normalized URL
        
    Raises:
        InvalidURLError: If URL format is invalid
    """
    url = url.strip()
    
    if not url:
        raise InvalidURLError("Veuillez saisir une URL valide.")
    
    # Add http:// if no scheme provided
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Basic URL validation
    if not URL_PATTERN.match(url):
        raise InvalidURLError("Veuillez saisir une URL valide.")
    
    return url


def _normalize_web_target(target: str) -> str:
    raw_target = target.strip()

    if not raw_target:
        raise InvalidURLError("Veuillez saisir une URL ou une adresse IP valide.")

    if "//" not in raw_target and "/" in raw_target:
        host_part, remainder = raw_target.split("/", 1)
        try:
            ipaddress.IPv4Address(host_part)
        except (ipaddress.AddressValueError, ValueError):
            pass
        else:
            if remainder.isdigit():
                raise InvalidURLError("Veuillez saisir une URL ou une adresse IP valide.")

    candidate = raw_target if raw_target.startswith(("http://", "https://")) else f"http://{raw_target}"
    parsed = urlparse(candidate)

    hostname = parsed.hostname
    if not hostname:
        raise InvalidURLError("Veuillez saisir une URL ou une adresse IP valide.")

    if " " in parsed.netloc or " " in parsed.path:
        raise InvalidURLError("Veuillez saisir une URL ou une adresse IP valide.")

    try:
        normalized_host = str(ipaddress.IPv4Address(hostname))
    except (ipaddress.AddressValueError, ValueError):
        normalized_host = hostname.lower()

    netloc = normalized_host
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    scheme = parsed.scheme.lower() if parsed.scheme.lower() in {"http", "https"} else "http"
    normalized = urlunparse((scheme, netloc, parsed.path or "", "", parsed.query or "", parsed.fragment or ""))
    return normalized


def parse_web_target(target: str) -> dict[str, object]:
    """Parse a web target into normalized URL and host metadata."""
    normalized_url = _normalize_web_target(target)
    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    try:
        normalized_ip = str(ipaddress.IPv4Address(hostname))
        is_ip = True
    except (ipaddress.AddressValueError, ValueError):
        normalized_ip = hostname
        is_ip = False

    return {
        "normalized_url": normalized_url,
        "host": normalized_ip,
        "hostname": hostname,
        "port": parsed.port,
        "scheme": parsed.scheme,
        "path": parsed.path or "",
        "is_ip": is_ip,
        "raw_target": target.strip(),
    }


def validate_cidr_for_scan(target: str, scan_type: str) -> tuple[str, str]:
    """
    Validate CIDR target and scan type combination.
    
    Args:
        target: CIDR notation string
        scan_type: Scan type name
        
    Returns:
        Tuple of (normalized_cidr, normalized_scan_type)
        
    Raises:
        ValidationError subclasses
    """
    target_type, validated_scan_type = validate_scan_type(target, scan_type)
    
    if target_type != TargetType.CIDR:
        raise InvalidTargetError("Ce module est réservé aux réseaux CIDR.")

    return _validate_cidr_target(target), validated_scan_type


def validate_single_ip_for_scan(target: str, scan_type: str) -> tuple[str, str]:
    """
    Validate single IP target and scan type combination.
    
    Args:
        target: Single IP address string
        scan_type: Scan type name
        
    Returns:
        Tuple of (normalized_ip, normalized_scan_type)
        
    Raises:
        ValidationError subclasses
    """
    target_type, validated_scan_type = validate_scan_type(target, scan_type)
    
    if target_type != TargetType.SINGLE_IP:
        raise InvalidTargetError("Ce module nécessite une adresse IP unique.")

    return _validate_single_host_target(target), validated_scan_type


def validate_custom_ports_scan(target: str, ports: str) -> tuple[str, str]:
    """
    Validate custom_ports scan with IP and port specification.
    
    Args:
        target: Single IP address string
        ports: Port specification string
        
    Returns:
        Tuple of (normalized_ip, normalized_ports)
        
    Raises:
        ValidationError subclasses
    """
    normalized_ip = _validate_single_host_target(target)
    normalized_ports = validate_ports(ports)
    
    return normalized_ip, normalized_ports


def validate_web_scan(target: str) -> str:
    """
    Validate web_scan with URL.
    
    Args:
        target: URL string
        
    Returns:
        Normalized URL
        
    Raises:
        ValidationError subclasses
    """
    return _normalize_web_target(target)


def validate_module_target(target: str, module_name: str, allow_public: bool = False) -> str:
    """Validate a target for a specific selective module and return its normalized value."""
    module_name = module_name.strip().lower()

    if module_name in NETWORK_MODULES:
        target_type = detect_target_type(target)
        if target_type == TargetType.CIDR:
            return _validate_cidr_target(target, allow_public=allow_public)
        return _validate_single_host_target(target)

    if module_name == "web_scan":
        return validate_web_scan(target)

    if module_name in SINGLE_HOST_MODULES:
        target_type = detect_target_type(target)
        if target_type != TargetType.SINGLE_IP:
            raise InvalidScanTypeError("Ce module nécessite une adresse IP unique.")
        return _validate_single_host_target(target)

    raise InvalidScanTypeError("Ce module n'est pas pris en charge.")
