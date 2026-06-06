import json
import ipaddress
from collections import Counter

from django.db import OperationalError
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_date
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from rest_framework.permissions import IsAuthenticated
from rest_framework import pagination, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import IntrusionAlert, Profile, ScanAlert, ScanJob, ScanResult, get_effective_role
from .serializers import ScanResultSerializer, ScanSerializer, DiscoverySerializer
from .services import nmap_service
from .services import pentest_service
from .services import scan_job_service
from .services.scan_validation_service import (
    ValidationError,
    validate_custom_ports_scan,
    validate_module_target,
    validate_web_scan,
)
import subprocess
import re
import logging

logger = logging.getLogger(__name__)


def _coerce_payload(data):
    if hasattr(data, "copy"):
        return data.copy()
    return dict(data)


def _log_scan_request(prefix: str, payload: dict[str, object]) -> None:
    print(f"[{prefix}] received payload: {payload}")
    print(f"[{prefix}] selected modules: {payload.get('modules')}")
    print(f"[{prefix}] parsed target: {payload.get('target') or payload.get('ip')}")


def _validation_error_response(exc: ValidationError) -> Response:
    return Response(
        {
            "success": False,
            "error": exc.message,
            "error_code": exc.error_code,
            "details": {
                "non_field_errors": [exc.message],
            },
        },
        status=status.HTTP_400_BAD_REQUEST,
    )


def _resolve_selected_modules(validated_data: dict[str, object]) -> list[str]:
    selected_modules: list[str] = []
    for module_name in ("fast", "full", "vuln", "web"):
        if validated_data.get(module_name):
            selected_modules.append(module_name)

    if "full" in selected_modules:
        return ["full"]

    if selected_modules:
        return selected_modules

    legacy_scan_type = str(validated_data.get("scan_type") or "fast")
    return scan_job_service.LEGACY_SCAN_TYPES.get(legacy_scan_type, ["fast"])


def _validate_modular_scan_request(
    target: str,
    modules: list[str],
    ports: str | None = None,
    allow_public: bool = False,
) -> None:
    normalized_target = target.strip()
    for module_name in modules:
        normalized_target = validate_module_target(normalized_target, module_name, allow_public=allow_public)

    if "custom_ports" in modules:
        validate_custom_ports_scan(normalized_target, ports or "")

    if "web_scan" in modules:
        validate_web_scan(normalized_target)


class HomeView(LoginRequiredMixin, TemplateView):
    template_name = "index.html"
    login_url = "/login/"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        role = get_effective_role(self.request.user)
        context["user_role"] = role
        context["can_launch_scan"] = role in {Profile.ROLE_ADMIN, Profile.ROLE_ANALYST}
        context["is_admin"] = role == Profile.ROLE_ADMIN
        return context


class ScanResultPagination(pagination.PageNumberPagination):
    page_size = 10


class ScanAlertPagination(pagination.PageNumberPagination):
    page_size = 10


class AuthenticatedAPIView(APIView):
    permission_classes = [IsAuthenticated]


class StatsView(AuthenticatedAPIView):
    def get(self, request, *args, **kwargs):
        queryset = ScanResult.objects.all().only("result", "date")

        total_scans = queryset.count()
        machines_up_ips: set[str] = set()
        port_counter: Counter[int] = Counter()
        vulnerability_counter: Counter[str] = Counter({"HIGH": 0, "MEDIUM": 0, "LOW": 0})
        scans_per_day_counter: Counter[str] = Counter()

        for scan in queryset:
            scans_per_day_counter[scan.date.date().isoformat()] += 1
            findings = nmap_service.parse_nmap_output(scan.result or "")
            has_open_port = False

            for finding in findings:
                risk = str(finding.get("risk") or "LOW").upper()
                if risk not in {"HIGH", "MEDIUM", "LOW"}:
                    risk = "LOW"
                vulnerability_counter[risk] += 1

                port = finding.get("port")
                state = str(finding.get("state") or "").lower()
                if isinstance(port, int) and state == "open":
                    port_counter[port] += 1
                    has_open_port = True

            if has_open_port:
                machines_up_ips.add(str(scan.ip))

        total_vulns = sum(vulnerability_counter.values())
        machines_up = len(machines_up_ips)

        ports = [
            {"port": str(port), "count": count}
            for port, count in sorted(port_counter.items(), key=lambda item: (-item[1], item[0]))[:10]
        ]

        scans_per_day = [
            {"date": day, "count": scans_per_day_counter[day]}
            for day in sorted(scans_per_day_counter.keys())
        ]

        return Response(
            {
                "totalScans": total_scans,
                "totalVulns": total_vulns,
                "machinesUp": machines_up,
                "total_scans": total_scans,
                "total_vulns": total_vulns,
                "machines_up": machines_up,
                "ports": ports,
                "vulnerabilities": {
                    "HIGH": vulnerability_counter["HIGH"],
                    "MEDIUM": vulnerability_counter["MEDIUM"],
                    "LOW": vulnerability_counter["LOW"],
                },
                "scans_per_day": scans_per_day,
            },
            status=status.HTTP_200_OK,
        )


class ScanHistoryView(AuthenticatedAPIView):
    def get(self, request, *args, **kwargs):
        queryset = ScanResult.objects.all().order_by("-date")

        ip_filter = request.query_params.get("ip")
        search = request.query_params.get("search")
        date_filter = request.query_params.get("date")

        if ip_filter:
            try:
                ip_filter = str(ipaddress.IPv4Address(ip_filter.strip()))
            except (ipaddress.AddressValueError, ValueError):
                return Response(
                    {"error": "Filtre IP invalide."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            queryset = queryset.filter(ip=ip_filter)

        if search:
            search_term = search.strip()
            queryset = queryset.filter(result__icontains=search_term)

        if date_filter:
            parsed_date = parse_date(date_filter.strip())
            if parsed_date is None:
                return Response(
                    {"error": "Filtre date invalide. Format attendu: YYYY-MM-DD."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            queryset = queryset.filter(date__date=parsed_date)

        if not queryset.exists():
            return Response(
                {"error": "Aucun resultat de scan trouve."},
                status=status.HTTP_404_NOT_FOUND,
            )

        paginator = ScanResultPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        serializer = ScanResultSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class ScanReportView(AuthenticatedAPIView):
    def get(self, request, scan_id: int, *args, **kwargs):
        scan_result = get_object_or_404(ScanResult, id=scan_id)
        from .services.report_service import build_scan_report_pdf

        pdf_content = build_scan_report_pdf(scan_result)

        response = HttpResponse(pdf_content, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="scan_report_{scan_result.id}.pdf"'
        return response


class ScanHtmlReportView(AuthenticatedAPIView):
    def get(self, request, scan_id: int, *args, **kwargs):
        scan_result = get_object_or_404(ScanResult, id=scan_id)
        # Use stored results: if the saved `result` is modular JSON, render the
        # modular network HTML. Otherwise render the single-host audit HTML.
        from .services.report_service import build_scan_audit_report_html, build_modular_network_report_html
        import json

        html_content = ""
        try:
            parsed = json.loads(scan_result.result or "{}")
        except Exception:
            parsed = {}

        if isinstance(parsed, dict) and parsed.get("modules"):
            html_content = build_modular_network_report_html(scan_result)
        else:
            html_content = build_scan_audit_report_html(
                str(scan_result.ip),
                scan_result.result or "",
                scan_result.date.strftime("%Y-%m-%d %H:%M:%S"),
            )
        return HttpResponse(html_content, content_type="text/html; charset=utf-8")


class NetworkReportView(AuthenticatedAPIView):
    def get(self, request, scan_id: int, *args, **kwargs):
        # Role restriction: only Admin and Analyst may download network reports
        user_role = get_effective_role(request.user)
        if user_role not in {Profile.ROLE_ADMIN, Profile.ROLE_ANALYST}:
            return Response(
                {"error": "Accès refusé : vous n'avez pas les droits pour télécharger ce rapport."},
                status=status.HTTP_403_FORBIDDEN,
            )

        scan_result = get_object_or_404(ScanResult, id=scan_id)
        from .services.report_service import build_modular_network_report_pdf

        pdf_content = build_modular_network_report_pdf(scan_result)

        response = HttpResponse(pdf_content, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="network_report_{scan_result.id}.pdf"'
        return response


class ScanAuditReportView(AuthenticatedAPIView):
    def get(self, request, scan_id: int, *args, **kwargs):
        scan_result = get_object_or_404(ScanResult, id=scan_id)
        from .services.report_service import build_scan_audit_report

        report_text = build_scan_audit_report(str(scan_result.ip), scan_result.result or "")
        return Response(
            {
                "scan_id": scan_result.id,
                "ip": scan_result.ip,
                "audit_report": report_text,
            },
            status=status.HTTP_200_OK,
        )


class AlertHistoryView(AuthenticatedAPIView):
    def get(self, request, *args, **kwargs):
        try:
            scan_alerts = [
                {
                    "id": alert.id,
                    "source": "SCAN",
                    "level": alert.level,
                    "ip": alert.scan_result.ip,
                    "endpoint": f"/scan/{alert.scan_result.id}",
                    "message": alert.message,
                    "date": alert.created_at.isoformat(),
                    "alert_type": "CRITICAL_VULNERABILITY",
                }
                for alert in ScanAlert.objects.select_related("scan_result").all()
            ]
        except OperationalError:
            scan_alerts = []

        try:
            ids_alerts = [
                {
                    "id": alert.id,
                    "source": "IDS",
                    "level": "HIGH",
                    "ip": alert.ip,
                    "endpoint": alert.endpoint,
                    "message": alert.message,
                    "date": alert.date.isoformat(),
                    "alert_type": alert.alert_type,
                }
                for alert in IntrusionAlert.objects.all()
            ]
        except OperationalError:
            ids_alerts = []

        combined_alerts = sorted(
            [*scan_alerts, *ids_alerts],
            key=lambda item: item["date"],
            reverse=True,
        )

        paginator = ScanAlertPagination()
        page_number = request.query_params.get("page", 1)
        paginator.page_size = 10

        try:
            page_number = int(page_number)
        except (TypeError, ValueError):
            page_number = 1

        start = (page_number - 1) * paginator.page_size
        end = start + paginator.page_size
        page_items = combined_alerts[start:end]

        next_page = None if end >= len(combined_alerts) else request.build_absolute_uri(f"{request.path}?page={page_number + 1}")
        previous_page = None if page_number <= 1 else request.build_absolute_uri(f"{request.path}?page={page_number - 1}")

        return Response(
            {
                "count": len(combined_alerts),
                "next": next_page,
                "previous": previous_page,
                "results": page_items,
            },
            status=status.HTTP_200_OK,
        )


class ScanView(AuthenticatedAPIView):
    def post(self, request, *args, **kwargs):
        user_role = get_effective_role(request.user)
        if user_role not in {Profile.ROLE_ADMIN, Profile.ROLE_ANALYST}:
            return Response(
                {"error": "Accès refusé : vous n'avez pas les droits pour lancer un scan."},
                status=status.HTTP_403_FORBIDDEN,
            )

        from .serializers import ModularScanSerializer
        from .services.scan_orchestrator_service import execute_modular_scan

        payload = _coerce_payload(request.data)
        if not payload.get("target") and payload.get("ip"):
            payload["target"] = payload.get("ip")
        if not payload.get("modules"):
            selected_modules = _resolve_selected_modules(payload)
            module_mapping = {
                "fast": ["fast_scan"],
                "full": ["host_discovery", "network_audit", "fast_scan", "service_detection", "vulnerability_scan", "web_scan", "custom_ports"],
                "vuln": ["vulnerability_scan"],
                "web": ["web_scan"],
                "quick": ["fast_scan"],
                "service": ["service_detection"],
                "os": ["service_detection"],
            }
            payload["modules"] = module_mapping.get(payload.get("scan_type", "fast"), selected_modules)

        _log_scan_request("ScanView", payload)

        serializer = ModularScanSerializer(data=payload)
        if not serializer.is_valid():
            return Response(
                {
                    "success": False,
                    "error": "Paramètres de scan invalides.",
                    "error_code": "VALIDATION_ERROR",
                    "details": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        target = serializer.validated_data["target"]
        modules = serializer.validated_data["modules"]
        ports = serializer.validated_data.get("ports") or None
        allow_public = bool(serializer.validated_data.get("allow_public", False))

        try:
            _validate_modular_scan_request(target, modules, ports, allow_public=allow_public)
        except ValidationError as exc:
            return _validation_error_response(exc)

        try:
            result = execute_modular_scan(
                target=target,
                modules=modules,
                ports=ports,
                allow_public=allow_public,
                save_to_db=True,
            )
        except Exception as exc:
            logger.exception("Internal error running modular scan: %s", exc)
            return Response(
                {
                    "success": False,
                    "error": "Erreur interne pendant le scan.",
                    "error_code": "INTERNAL_ERROR",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        has_errors = bool(result.get("errors"))
        has_warnings = bool(result.get("warnings"))
        response_status = status.HTTP_200_OK if not (has_errors or has_warnings) else status.HTTP_207_MULTI_STATUS

        return Response(
            {
                "success": not has_errors,
                "target": result.get("target"),
                "target_type": result.get("target_type"),
                "modules": result.get("modules", {}),
                "debug": result.get("debug", {}),
                "warnings": result.get("warnings", []),
                "errors": result.get("errors", []),
                "scan_id": result.get("scan_id"),
                "total_duration": result.get("total_duration"),
                "timestamp": result.get("timestamp"),
            },
            status=response_status,
        )


class ModularScanView(AuthenticatedAPIView):
    def post(self, request, *args, **kwargs):
        user_role = get_effective_role(request.user)
        if user_role not in {Profile.ROLE_ADMIN, Profile.ROLE_ANALYST}:
            return Response(
                {"error": "Accès refusé : vous n'avez pas les droits pour lancer un scan."},
                status=status.HTTP_403_FORBIDDEN,
            )

        from .serializers import ModularScanSerializer
        from .services.scan_orchestrator_service import execute_modular_scan

        payload = _coerce_payload(request.data)
        _log_scan_request("ModularScanView", payload)

        serializer = ModularScanSerializer(data=payload)
        if not serializer.is_valid():
            return Response(
                {
                    "success": False,
                    "error": "Paramètres de scan invalides.",
                    "error_code": "VALIDATION_ERROR",
                    "details": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        target = serializer.validated_data["target"]
        modules = serializer.validated_data["modules"]
        ports = serializer.validated_data.get("ports") or None
        allow_public = bool(serializer.validated_data.get("allow_public", False))

        try:
            _validate_modular_scan_request(target, modules, ports, allow_public=allow_public)
        except ValidationError as exc:
            return _validation_error_response(exc)

        try:
            result = execute_modular_scan(
                target=target,
                modules=modules,
                ports=ports,
                allow_public=allow_public,
                save_to_db=True,
            )
        except Exception as exc:
            logger.exception("Internal error running modular scan (modular view): %s", exc)
            return Response(
                {
                    "success": False,
                    "error": "Erreur interne pendant le scan.",
                    "error_code": "INTERNAL_ERROR",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        has_errors = bool(result.get("errors"))
        has_warnings = bool(result.get("warnings"))
        response_status = status.HTTP_200_OK if not (has_errors or has_warnings) else status.HTTP_207_MULTI_STATUS

        return Response(
            {
                "target": result.get("target"),
                "target_type": result.get("target_type"),
                "results": result.get("modules", {}),
                "debug": result.get("debug", {}),
                "warnings": result.get("warnings", []),
                "errors": result.get("errors", []),
                "scan_id": result.get("scan_id"),
                "total_duration": result.get("total_duration"),
                "timestamp": result.get("timestamp"),
                "success": not has_errors,
            },
            status=response_status,
        )


def _parse_nmap_discovery_output(output_text: str) -> list[dict[str, object]]:
    """Parse nmap -sn output to extract discovered hosts."""
    hosts: list[dict[str, object]] = []
    host_entry = None
    host_re = re.compile(r"^Nmap scan report for (.+?)(?: \(([0-9\.]+)\))?$")

    for raw in output_text.splitlines():
        line = raw.strip()
        if not line:
            continue

        m = host_re.match(line)
        if m:
            # flush previous
            if host_entry is not None:
                hosts.append(host_entry)

            name = m.group(1) or ""
            ip = m.group(2) or ""

            # if name is an IP, treat as ip
            try:
                _ip.IPv4Address(name)
                ip = name
                name = ""
            except Exception:
                pass

            host_entry = {"ip": ip, "hostname": name, "status": "DOWN"}
            continue

        if host_entry is not None and "host is up" in line.lower():
            host_entry["status"] = "UP"

    if host_entry is not None:
        hosts.append(host_entry)

    return hosts


def _exclude_network_address(hosts: list[dict[str, object]], network_cidr: str) -> list[dict[str, object]]:
    """Exclude the network address itself from the discovered hosts."""
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
        network_addr = str(net.network_address)
        return [h for h in hosts if h.get("ip") != network_addr]
    except Exception:
        return hosts


class DiscoveryView(AuthenticatedAPIView):
    def post(self, request, *args, **kwargs):
        user_role = get_effective_role(request.user)
        if user_role not in {Profile.ROLE_ADMIN, Profile.ROLE_ANALYST}:
            return Response(
                {"error": "Accès refusé : vous n'avez pas les droits pour lancer une découverte réseau."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = DiscoverySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {
                    "error": "Réseau invalide.",
                    "details": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        network = serializer.validated_data["network"]

        # Lightweight nmap discovery: ping scan only, no retries, short timeout per host
        command = ["nmap", "-sn", "--max-retries", "1", "--host-timeout", "5s", network]

        output_text = ""
        is_partial = False

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                shell=False,
            )
            output_text = result.stdout or ""
        except FileNotFoundError:
            return Response({"error": "nmap n'est pas installe ou introuvable."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except subprocess.TimeoutExpired as exc:
            # Timeout: return partial results from whatever output was captured
            is_partial = True
            stdout_data = exc.stdout or b""
            output_text = stdout_data.decode('utf-8', errors='ignore') if isinstance(stdout_data, bytes) else (stdout_data or "")
        except subprocess.CalledProcessError as exc:
            out_data = exc.stdout or b""
            err_data = exc.stderr or b""
            out = (out_data.decode('utf-8', errors='ignore') if isinstance(out_data, bytes) else out_data).strip()
            err = (err_data.decode('utf-8', errors='ignore') if isinstance(err_data, bytes) else err_data).strip()
            details = out or err or "Erreur d'execution de nmap"
            return Response({"error": "Erreur pendant l'execution de nmap.", "details": details}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as exc:
            return Response({"error": f"Erreur inattendue: {str(exc)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Parse discovered hosts
        hosts = _parse_nmap_discovery_output(output_text)
        
        # Exclude network address from results
        hosts = _exclude_network_address(hosts, network)

        response_data = {
            "network": network,
            "hosts": hosts,
            "partial": is_partial,
        }
        
        if is_partial:
            response_data["warning"] = "Découverte terminée avec avertissement"

        return Response(response_data, status=status.HTTP_200_OK)


class ScanJobStatusView(AuthenticatedAPIView):
    def get(self, request, job_id: int, *args, **kwargs):
        if get_effective_role(request.user) not in {Profile.ROLE_ADMIN, Profile.ROLE_ANALYST}:
            return Response(
                {"error": "Accès refusé : vous n'avez pas les droits pour consulter ce scan."},
                status=status.HTTP_403_FORBIDDEN,
            )

        job = get_object_or_404(ScanJob, id=job_id)
        result_output = job.output or ""
        structured_modules = {}
        if job.scan_result_id and job.scan_result and job.scan_result.result:
            try:
                saved_result = json.loads(job.scan_result.result)
                if isinstance(saved_result, dict):
                    modules = saved_result.get("modules")
                    if isinstance(modules, dict):
                        structured_modules = modules
            except (TypeError, ValueError, json.JSONDecodeError):
                structured_modules = {}

        parsed_results = nmap_service.parse_nmap_output(result_output)
        vulnerability_details = nmap_service.parse_vulnerability_findings(result_output)
        risk_summary = nmap_service.calculate_risk_score(parsed_results)
        os_detected = nmap_service.detect_os_from_output(result_output)
        vulnerability_message = (
            "Aucune vulnérabilité détectée par les scripts Nmap."
            if not vulnerability_details
            else ""
        )

        return Response(
            {
                "job_id": job.id,
                "ip": job.ip,
                "scan_type": job.scan_type,
                "selected_modules": job.selected_modules,
                "ports": job.ports or None,
                "status": job.status,
                "progress_message": job.progress_message,
                "output": result_output,
                "modules": structured_modules,
                "error_message": job.error_message,
                "timeout_seconds": job.timeout_seconds,
                "command": job.command,
                "scan_result_id": job.scan_result.id if job.scan_result_id else None,
                "parsed_results": parsed_results,
                "vulnerability_details": vulnerability_details,
                "vulnerability_message": vulnerability_message,
                "risk_score_total": risk_summary["score_total"],
                "global_risk_level": risk_summary["global_level"],
                "os_detected": os_detected,
                "date": job.scan_result.date.isoformat() if job.scan_result_id else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "updated_at": job.updated_at.isoformat() if job.updated_at else None,
            },
            status=status.HTTP_200_OK,
        )
