import ipaddress
import queue
import subprocess
import threading
import time
from pathlib import Path

from django.db import close_old_connections
from django.utils import timezone

from ..models import ScanAlert, ScanJob, ScanResult
from .nmap_service import calculate_risk_score, detect_os_from_output, parse_nmap_output

SCAN_TIMEOUTS = {
    "fast": 120,
    "vuln": 300,
    "web": 600,
    "full": 600,
}

ALLOWED_MODULES = ("fast", "full", "vuln", "web")
LEGACY_SCAN_TYPES = {
    "quick": ["fast"],
    "service": ["fast"],
    "vuln": ["vuln"],
    "os": ["fast"],
    "fast": ["fast"],
    "full": ["full"],
    "web": ["web"],
}


def sanitize_ip(ip: str) -> str:
    try:
        return str(ipaddress.IPv4Address(ip.strip()))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError("Adresse IP invalide pour le scan.") from exc


def sanitize_ports(ports: str | None) -> str | None:
    if ports is None:
        return None

    normalized = ports.strip().replace(" ", "")
    if not normalized:
        return None

    values = []
    for raw_port in normalized.split(","):
        if not raw_port.isdigit():
            raise ValueError("Format de ports invalide. Exemple attendu: 80,443,8080")
        port = int(raw_port)
        if port < 1 or port > 65535:
            raise ValueError("Chaque port doit etre entre 1 et 65535.")
        values.append(str(port))

    return ",".join(values)


def resolve_selected_modules(validated_data: dict[str, object]) -> list[str]:
    selected_modules: list[str] = []
    for module_name in ("fast", "full", "vuln", "web"):
        if validated_data.get(module_name):
            selected_modules.append(module_name)

    if "full" in selected_modules:
        return ["full"]

    if selected_modules:
        return selected_modules

    legacy_scan_type = str(validated_data.get("scan_type") or "fast")
    return LEGACY_SCAN_TYPES.get(legacy_scan_type, ["fast"])


def get_timeout_for_modules(selected_modules: list[str]) -> int:
    timeout_seconds = 120
    for module_name in selected_modules:
        timeout_seconds = max(timeout_seconds, SCAN_TIMEOUTS.get(module_name, 120))
    return timeout_seconds


def start_scan_job(job_id: int) -> threading.Thread:
    thread = threading.Thread(target=_run_scan_job, args=(job_id,), daemon=True)
    thread.start()
    return thread


def _append_output(job: ScanJob, chunk: str) -> None:
    if not chunk:
        return

    job.output = (job.output or "") + chunk
    job.save(update_fields=["output", "updated_at"])


def _build_command(job: ScanJob) -> tuple[list[str], str]:
    script_path = Path(__file__).resolve().parent / "scan.sh"
    if not script_path.exists():
        raise FileNotFoundError(f"Script introuvable: {script_path}")

    command = ["bash", str(script_path), job.ip]
    for module_name in job.selected_modules:
        command.append(f"--{module_name}")

    if job.ports:
        command.extend(["--ports", job.ports])

    return command, " ".join(command)


def _stream_process_output(process: subprocess.Popen, timeout_seconds: int, job: ScanJob) -> bool:
    output_queue: queue.Queue[str | None] = queue.Queue()

    def reader() -> None:
        assert process.stdout is not None
        try:
            for line in iter(process.stdout.readline, ""):
                output_queue.put(line)
        finally:
            output_queue.put(None)

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()

    buffer: list[str] = []
    start_time = time.monotonic()
    last_flush = start_time
    stream_closed = False
    timed_out = False

    while True:
        try:
            item = output_queue.get(timeout=0.5)
            if item is None:
                stream_closed = True
            else:
                buffer.append(item)
        except queue.Empty:
            pass

        now = time.monotonic()
        if buffer and (len(buffer) >= 10 or now - last_flush >= 1.0):
            _append_output(job, "".join(buffer))
            buffer.clear()
            last_flush = now

        if now - start_time >= timeout_seconds and process.poll() is None:
            timed_out = True
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            break

        if stream_closed and process.poll() is not None and output_queue.empty():
            break

    if buffer:
        _append_output(job, "".join(buffer))

    reader_thread.join(timeout=2)
    return timed_out


def _finalize_job(job: ScanJob, status: str, error_message: str = "") -> None:
    job.status = status
    job.error_message = error_message
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "error_message", "finished_at", "updated_at"])


def _emit_scan_result(job: ScanJob) -> ScanResult:
    result_text = (job.output or "").strip()
    if job.error_message and job.error_message not in result_text:
        result_text = "\n\n".join(part for part in [result_text, f"[ERROR] {job.error_message}"] if part).strip()
    if not result_text:
        result_text = job.error_message or "Scan termine sans sortie."

    scan_result = ScanResult.objects.create(ip=job.ip, result=result_text)
    job.scan_result = scan_result
    job.save(update_fields=["scan_result", "updated_at"])

    parsed_results = parse_nmap_output(result_text)
    risk_summary = calculate_risk_score(parsed_results)
    if risk_summary["global_level"] == "HIGH":
        ScanAlert.objects.create(
            scan_result=scan_result,
            level=ScanAlert.LEVEL_HIGH,
            message="⚠️ Vulnérabilité critique détectée",
        )

    return scan_result


def _run_scan_job(job_id: int) -> None:
    close_old_connections()

    try:
        job = ScanJob.objects.get(pk=job_id)
    except ScanJob.DoesNotExist:
        return

    job.status = ScanJob.STATUS_RUNNING
    job.progress_message = "Scan en cours..."
    job.started_at = timezone.now()
    job.save(update_fields=["status", "progress_message", "started_at", "updated_at"])

    try:
        command, command_display = _build_command(job)
        job.command = command_display
        job.save(update_fields=["command", "updated_at"])
    except FileNotFoundError as exc:
        _append_output(job, f"{exc}\n")
        _finalize_job(job, ScanJob.STATUS_ERROR, str(exc))
        _emit_scan_result(job)
        return

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False,
        )
    except FileNotFoundError:
        error_message = "Bash est introuvable sur ce serveur."
        _append_output(job, f"{error_message}\n")
        _finalize_job(job, ScanJob.STATUS_ERROR, error_message)
        _emit_scan_result(job)
        return
    except PermissionError:
        error_message = "Permissions insuffisantes pour executer Bash."
        _append_output(job, f"{error_message}\n")
        _finalize_job(job, ScanJob.STATUS_ERROR, error_message)
        _emit_scan_result(job)
        return

    timed_out = _stream_process_output(process, job.timeout_seconds, job)
    return_code = process.poll()

    if timed_out:
        error_message = f"Le scan a depasse le delai autorise ({job.timeout_seconds}s)."
        _append_output(job, f"\n[ERROR] {error_message}\n")
        _finalize_job(job, ScanJob.STATUS_TIMEOUT, error_message)
    elif return_code not in (0, None):
        error_message = f"Le script de scan a echoue (code {return_code})."
        _append_output(job, f"\n[ERROR] {error_message}\n")
        _finalize_job(job, ScanJob.STATUS_ERROR, error_message)
    else:
        _finalize_job(job, ScanJob.STATUS_SUCCESS, "")

    _emit_scan_result(job)
