"""
Scan orchestrator service for managing modular scan execution.
Handles validation, execution, result aggregation, and database persistence.
"""

import json
import time
from datetime import datetime
from typing import Optional

from scanner.services.modular_scan_service import (
    host_discovery,
    network_audit,
    fast_scan,
    service_detection,
    vulnerability_scan,
    web_scan,
    custom_ports,
    ModularScanError,
)
from scanner.services.modular_scanner import (
    run_host_discovery,
    run_camera_scan,
    run_smb_audit,
    run_rdp_scan,
    run_database_scan,
    run_web_server_scan,
    run_printer_scan,
    run_ssh_scan,
    run_telnet_scan,
    parse_modular_nmap_output,
)
from scanner.services.scan_validation_service import (
    TargetType,
    validate_custom_ports_scan,
    validate_module_target,
    validate_web_scan,
    ValidationError,
)
import logging

logger = logging.getLogger(__name__)


# Map module names to functions
MODULE_FUNCTIONS = {
    "host_discovery": host_discovery,
    "network_audit": network_audit,
    "fast_scan": fast_scan,
    "service_detection": service_detection,
    "vulnerability_scan": vulnerability_scan,
    "web_scan": web_scan,
    "custom_ports": custom_ports,
    "camera_scan": run_camera_scan,
    "smb_audit": run_smb_audit,
    "rdp_scan": run_rdp_scan,
    "database_scan": run_database_scan,
    "web_server_scan": run_web_server_scan,
    "printer_scan": run_printer_scan,
    "ssh_scan": run_ssh_scan,
    "telnet_scan": run_telnet_scan,
    "run_host_discovery": run_host_discovery,
}


class ScanOrchestrator:
    """Orchestrates modular scan execution with error recovery."""

    def __init__(self, target: str, modules: list[str], ports: Optional[str] = None, allow_public: bool = False):
        """
        Initialize orchestrator.

        Args:
            target: Target IP or CIDR
            modules: List of module names to execute
            ports: Port specification for custom_ports module
        """
        self.target = target.strip()
        self.modules = [m.strip().lower() for m in modules]
        self.ports = (ports or "").strip()
        self.allow_public = allow_public
        self.target_type: Optional[TargetType] = None
        self.results = {
            "target": self.target,
            "target_type": None,
            "modules": {},
            "debug": {},
            "warnings": [],
            "errors": [],
        }
        self.start_time = time.time()

    def _target_type_label(self) -> str:
        if self.target_type == TargetType.CIDR:
            return "cidr"
        if self.target_type == TargetType.SINGLE_IP:
            return "ip"
        return "unknown"

    def _module_allowed_for_target(self, module_name: str) -> bool:
        try:
            validate_module_target(self.target, module_name)
            return True
        except ValidationError as exc:
            self.results["errors"].append(f"{module_name}: {exc.message}")
            return False

    def _validate_and_prepare(self) -> bool:
        """
        Validate target and modules, prepare for execution.

        Returns:
            True if validation successful, False otherwise
        """
        # Preserve the requested order while removing duplicates.
        self.modules = list(dict.fromkeys(m.lower() for m in self.modules))

        if not self.modules:
            self.results["errors"].append("No modules specified")
            return False

        try:
            invalid_modules = [m for m in self.modules if m not in MODULE_FUNCTIONS]
        except Exception:
            invalid_modules = list(self.modules)

        if invalid_modules:
            self.results["errors"].append(
                f"Invalid modules: {', '.join(invalid_modules)}"
            )
            return False

        allowed_modules: list[str] = []
        target_labels: list[str] = []
        for module in self.modules:
            try:
                normalized_target = validate_module_target(self.target, module)
                if normalized_target.startswith("http://") or normalized_target.startswith("https://"):
                    target_labels.append("url")
                elif module in {"camera_scan", "smb_audit", "rdp_scan", "database_scan", "web_server_scan", "printer_scan", "ssh_scan", "telnet_scan", "host_discovery"}:
                    target_labels.append("cidr")
                else:
                    target_labels.append("ip")
                allowed_modules.append(module)
            except ValidationError as exc:
                self.results["errors"].append(f"{module}: {exc.message}")

        self.modules = allowed_modules

        if not self.modules:
            self.results["errors"].append("No valid modules for this target")
            self.results["target_type"] = self._target_type_label()
            return False

        if "url" in target_labels and len(set(target_labels)) == 1:
            self.results["target_type"] = "url"
        elif "cidr" in target_labels and len(set(target_labels)) == 1:
            self.results["target_type"] = "cidr"
        elif "ip" in target_labels and len(set(target_labels)) == 1:
            self.results["target_type"] = "ip"
        else:
            self.results["target_type"] = self._target_type_label()

        return True

    def _execute_module(self, module_name: str) -> dict:
        """
        Execute a single module safely.

        Args:
            module_name: Name of module to execute

        Returns:
            Module result dictionary
        """
        module_func = MODULE_FUNCTIONS[module_name]
        module_start = time.time()

        try:
            # Handle modules with special parameters
            if module_name == "custom_ports":
                if not self.ports:
                    return {
                        "status": "failed",
                        "error": "Veuillez saisir une liste de ports valide.",
                        "output": "",
                        "duration": 0.0,
                        "command": "",
                    }
                normalized_ip, normalized_ports = validate_custom_ports_scan(self.target, self.ports)
                result = module_func(normalized_ip, normalized_ports)
            elif module_name == "web_scan":
                normalized_url = validate_web_scan(self.target)
                result = module_func(normalized_url)
            else:
                # Standard nmap-based modules
                result = module_func(self.target)

            # result should be a dict from module runner
            raw_output = (result.get("output") or result.get("stdout") or "") if isinstance(result, dict) else ""
            raw_error = (result.get("error") or result.get("stderr") or "") if isinstance(result, dict) else ""
            command_used = str(result.get("command", "")) if isinstance(result, dict) else ""
            auxiliary_output = str(result.get("whatweb_output", "") or "") if isinstance(result, dict) else ""

            status_in = (result.get("status") if isinstance(result, dict) else None) or "error"

            # Map module runner statuses to orchestrator status
            if status_in == "success":
                status = "success"
            elif status_in == "timeout":
                status = "warning"
                raw_error = raw_error or f"Module {module_name} exceeded time limit."
                logger.warning("Module %s timed out; target=%s", module_name, self.target)
            else:
                # any error or other statuses become warnings but record sanitized message
                status = "warning"
                if raw_error:
                    logger.warning("Module %s produced error: %s", module_name, raw_error)

            parsed_results = (result.get("parsed_results") if isinstance(result, dict) else None) or []
            try:
                if not parsed_results and raw_output:
                    parsed_results = parse_modular_nmap_output(module_name, raw_output, self.target, auxiliary_output=auxiliary_output)
            except Exception as e:
                logger.exception("Failed to parse module output for %s: %s", module_name, e)

            # sanitize error message for frontend - do not expose internal traces
            safe_error = raw_error if raw_error and len(raw_error) < 240 else (raw_error.splitlines()[0] if raw_error else "")

            standard_module_keys = {
                "status",
                "executed_on",
                "command_used",
                "raw_output",
                "whatweb_output",
                "parsed_results",
                "output",
                "stderr",
                "duration",
                "command",
                "error",
            }

            extra_fields = {
                key: value
                for key, value in (result.items() if isinstance(result, dict) else [])
                if key not in standard_module_keys
            }

            module_response = {
                "status": status,
                "executed_on": "Kali VM",
                "command_used": command_used,
                "raw_output": raw_output,
                "whatweb_output": auxiliary_output,
                "parsed_results": parsed_results,
                "output": raw_output,
                "stderr": safe_error,
                "duration": float(result.get("duration", 0.0) if isinstance(result, dict) else 0.0),
                "command": command_used,
            }

            module_response.update(extra_fields)
            return module_response
        except ModularScanError as e:
            logger.exception("ModularScanError in module %s: %s", module_name, e)
            return {
                "status": "failed",
                "executed_on": "Kali VM",
                "command_used": "",
                "error": "Module execution error.",
                "output": "",
                "whatweb_output": "",
                "duration": time.time() - module_start,
                "command": "",
            }
        except Exception as e:
            logger.exception("Unexpected exception executing module %s: %s", module_name, e)
            return {
                "status": "failed",
                "executed_on": "Kali VM",
                "command_used": "",
                "error": "Unexpected module error.",
                "output": "",
                "whatweb_output": "",
                "duration": time.time() - module_start,
                "command": "",
            }

    def execute(self) -> dict:
        """
        Execute all modules with error recovery.

        Returns:
            Structured result dictionary
        """
        # Validate and prepare
        if not self._validate_and_prepare():
            self.results["target_type"] = self.results["target_type"] or "unknown"
            total_duration = time.time() - self.start_time
            self.results["total_duration"] = total_duration
            return self.results

        # Execute each module independently
        for module in self.modules:
            module_result = self._execute_module(module)
            standard_module_keys = {
                "status",
                "executed_on",
                "command_used",
                "raw_output",
                "whatweb_output",
                "parsed_results",
                "output",
                "stderr",
                "duration",
                "command",
                "error",
            }

            # Always add result, even if failed (partial results)
            self.results["modules"][module] = {
                "status": module_result["status"],
                "executed_on": module_result.get("executed_on", "Kali VM"),
                "command_used": module_result.get("command_used", module_result.get("command", "")),
                "raw_output": module_result.get("raw_output", module_result.get("output", "")),
                "whatweb_output": module_result.get("whatweb_output", ""),
                "parsed_results": module_result.get("parsed_results", []),
                "output": module_result.get("output", ""),
                "stderr": module_result.get("stderr", ""),
                "duration": module_result.get("duration", 0.0),
                "command": module_result.get("command", ""),
            }

            for extra_key, extra_value in module_result.items():
                if extra_key not in standard_module_keys:
                    self.results["modules"][module][extra_key] = extra_value

            self.results["debug"][module] = {
                "executed_on": module_result.get("executed_on", "Kali VM"),
                "command_used": module_result.get("command_used", module_result.get("command", "")),
                "raw_output": module_result.get("raw_output", module_result.get("output", "")),
                "whatweb_output": module_result.get("whatweb_output", ""),
                "parsed_results": module_result.get("parsed_results", []),
            }

            for extra_key, extra_value in module_result.items():
                if extra_key not in standard_module_keys:
                    self.results["debug"][module][extra_key] = extra_value

            # Track failures as warnings
            if module_result["status"] == "failed":
                error_msg = module_result.get("error", f"{module} failed")
                self.results["warnings"].append(
                    f"Module {module} failed: {error_msg}"
                )
                self.results["modules"][module]["error"] = error_msg

        total_duration = time.time() - self.start_time
        self.results["total_duration"] = total_duration
        self.results["timestamp"] = datetime.now().isoformat()

        return self.results

    def save_to_database(self, scan_result_model) -> Optional[int]:
        """
        Save aggregated results to database.

        Args:
            scan_result_model: ScanResult model class

        Returns:
            ScanResult ID if successful, None otherwise
        """
        if not self.results.get("modules"):
            return None

        try:
            # Determine IP for storage
            ip = self.target.split("/")[0] if "/" in self.target else self.target

            # Create ScanResult record
            scan_result = scan_result_model.objects.create(
                ip=ip,
                result=json.dumps(self.results, ensure_ascii=True, indent=2),
            )

            return scan_result.id
        except Exception as e:
            print(f"Error saving to database: {str(e)}")
            return None

def execute_modular_scan(
    target: str,
    modules: list[str],
    ports: Optional[str] = None,
    allow_public: bool = False,
    save_to_db: bool = True,
) -> dict:
    """
    Execute a modular scan with database persistence.

    Args:
        target: Target IP or CIDR
        modules: List of module names
        ports: Optional port specification
        save_to_db: Whether to save results to database

    Returns:
        Scan result dictionary
    """
    orchestrator = ScanOrchestrator(target, modules, ports, allow_public=allow_public)
    results = orchestrator.execute()

    # Save to database if requested
    if save_to_db and results.get("modules"):
        from scanner.models import ScanResult
        scan_id = orchestrator.save_to_database(ScanResult)
        results["scan_id"] = scan_id

    return results
