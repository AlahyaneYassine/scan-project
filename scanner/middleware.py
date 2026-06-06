from __future__ import annotations

from datetime import timedelta

from django.db import OperationalError
from django.utils import timezone

from .models import IntrusionAlert, LogRequest


class RequestLoggingMiddleware:
    INTERNAL_DETECTION_PREFIXES = (
        "/api/stats/",
        "/api/scans/",
        "/api/alerts/",
        "/api/report/",
    )
    INTERNAL_DETECTION_EXACT = {
        "/favicon.ico",
    }
    WINDOW = timedelta(minutes=1)
    ALERT_COOLDOWN = timedelta(minutes=5)

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            response = self.get_response(request)
        finally:
            self._log_and_detect(request)
        return response

    def _get_client_ip(self, request) -> str:
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded_for:
            first_ip = forwarded_for.split(",")[0].strip()
            if first_ip:
                return first_ip
        return (request.META.get("REMOTE_ADDR") or "127.0.0.1").strip()

    def _is_internal_detection_path(self, endpoint: str) -> bool:
        if endpoint in self.INTERNAL_DETECTION_EXACT:
            return True
        return any(endpoint.startswith(prefix) for prefix in self.INTERNAL_DETECTION_PREFIXES)

    def _log_and_detect(self, request) -> None:
        endpoint = request.path or "/"
        ip = self._get_client_ip(request)

        try:
            LogRequest.objects.create(ip=ip, endpoint=endpoint)
        except OperationalError:
            return

        if self._is_internal_detection_path(endpoint):
            return

        try:
            self._detect_and_alert(ip)
        except OperationalError:
            return

    def _recent_alert_exists(self, ip: str, alert_type: str) -> bool:
        cutoff = timezone.now() - self.ALERT_COOLDOWN
        return IntrusionAlert.objects.filter(ip=ip, alert_type=alert_type, date__gte=cutoff).exists()

    def _create_alert(self, ip: str, endpoint: str, alert_type: str, message: str) -> None:
        if self._recent_alert_exists(ip, alert_type):
            return
        IntrusionAlert.objects.create(ip=ip, endpoint=endpoint, alert_type=alert_type, message=message)

    def _detect_and_alert(self, ip: str) -> None:
        cutoff = timezone.now() - self.WINDOW
        recent_logs = LogRequest.objects.filter(ip=ip, date__gte=cutoff)

        meaningful_logs = recent_logs.exclude(endpoint__in=self.INTERNAL_DETECTION_EXACT)
        for prefix in self.INTERNAL_DETECTION_PREFIXES:
            meaningful_logs = meaningful_logs.exclude(endpoint__startswith=prefix)

        total_requests = meaningful_logs.count()
        distinct_endpoints = meaningful_logs.values("endpoint").distinct().count()
        login_hits = meaningful_logs.filter(endpoint__startswith="/login/").count()

        if total_requests > 10:
            self._create_alert(
                ip=ip,
                endpoint="*",
                alert_type=IntrusionAlert.ALERT_TRAFFIC_SPIKE,
                message=f"⚠️ Activité suspecte détectée depuis {ip} (trop de requêtes: {total_requests}/min)",
            )

        if distinct_endpoints >= 8:
            self._create_alert(
                ip=ip,
                endpoint="*",
                alert_type=IntrusionAlert.ALERT_PORT_SCAN,
                message=f"⚠️ Activité suspecte détectée depuis {ip} (scan d'endpoints: {distinct_endpoints} chemins différents)",
            )

        if login_hits > 5:
            self._create_alert(
                ip=ip,
                endpoint="/login/",
                alert_type=IntrusionAlert.ALERT_BRUTE_FORCE,
                message=f"⚠️ Activité suspecte détectée depuis {ip} (brute force possible sur /login/)",
            )