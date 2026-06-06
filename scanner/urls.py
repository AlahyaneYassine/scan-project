from django.urls import path

from .views import AlertHistoryView, DiscoveryView, ModularScanView, NetworkReportView, ScanAuditReportView, ScanHistoryView, ScanHtmlReportView, ScanJobStatusView, ScanReportView, ScanView, StatsView

urlpatterns = [
    path("scan/", ScanView.as_view(), name="scan"),
    path("scan/modular/", ScanView.as_view(), name="modular-scan"),
    path("modular-scan/", ModularScanView.as_view(), name="modular-scan-api"),
    path("scan-jobs/<int:job_id>/", ScanJobStatusView.as_view(), name="scan-job-status"),
    path("scans/", ScanHistoryView.as_view(), name="scan-history"),
    path("alerts/", AlertHistoryView.as_view(), name="alert-history"),
    path("stats/", StatsView.as_view(), name="stats"),
    path("discovery/", DiscoveryView.as_view(), name="discovery"),
    path("report/<int:scan_id>/", ScanReportView.as_view(), name="scan-report"),
    path("report-html/<int:scan_id>/", ScanHtmlReportView.as_view(), name="scan-html-report"),
    path("audit-report/<int:scan_id>/", ScanAuditReportView.as_view(), name="scan-audit-report"),
    path("network-report/<int:scan_id>/", NetworkReportView.as_view(), name="network-report"),
]
