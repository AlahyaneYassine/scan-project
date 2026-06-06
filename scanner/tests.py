import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APITestCase

from .models import Profile, ScanJob, ScanResult
from .services.modular_scan_service import _strip_ansi_codes, web_scan
from .services.report_service import build_modular_network_report_html
from .services import scan_orchestrator_service
from .services.scan_validation_service import validate_web_scan


class ScanApiTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="analyst", password="secret123")
        self.user.profile.role = Profile.ROLE_ANALYST
        self.user.profile.save(update_fields=["role"])
        self.client.force_authenticate(user=self.user)

    def test_reject_invalid_ip(self):
        response = self.client.post("/api/scan/", {"ip": "999.999.999.999"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_reject_command_injection_payload(self):
        response = self.client.post("/api/scan/", {"ip": "127.0.0.1; whoami"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_enqueue_scan_job_and_return_accepted_response(self):
        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {
                "fast_scan": lambda ip: {
                    "stdout": "fast scan output",
                    "stderr": "",
                    "status": 0,
                    "duration": 1.0,
                    "command": f"nmap -F {ip}",
                },
            },
            clear=False,
        ):
            response = self.client.post("/api/scan/", {"ip": "127.0.0.1", "fast": True}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        self.assertIn("fast_scan", response.data["modules"])

    def test_send_selected_modules_and_ports_to_service(self):
        payload = {
            "target": "127.0.0.1",
            "modules": ["fast_scan", "vulnerability_scan"],
            "ports": "80,443",
        }
        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {
                "fast_scan": lambda ip: {
                    "stdout": "fast scan output",
                    "stderr": "",
                    "status": 0,
                    "duration": 1.0,
                    "command": f"nmap -F {ip}",
                },
                "vulnerability_scan": lambda ip: {
                    "stdout": "vuln scan output",
                    "stderr": "",
                    "status": 0,
                    "duration": 2.0,
                    "command": f"nmap -sV --script vuln {ip}",
                },
            },
            clear=False,
        ):
            response = self.client.post("/api/scan/", payload, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertIn("fast_scan", response.data["modules"])
        self.assertIn("vulnerability_scan", response.data["modules"])

    def test_web_scan_module_accepts_ip_targets_and_normalizes_url(self):
        observed_targets = []

        def fake_web_scan(target):
            observed_targets.append(target)
            return {
                "stdout": "web scan output",
                "stderr": "",
                "status": "success",
                "duration": 1.0,
                "command": f"whatweb {target}",
            }

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"web_scan": fake_web_scan},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.10", "modules": ["web_scan"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(observed_targets)
        self.assertEqual(observed_targets[0], "http://192.168.1.10")
        self.assertIn("web_scan", response.data["modules"])

    def test_validate_web_scan_accepts_domain_and_url_targets(self):
        self.assertEqual(validate_web_scan("example.com"), "http://example.com")
        self.assertEqual(validate_web_scan("https://example.com/path"), "https://example.com/path")

    def test_web_scan_returns_message_when_no_http_service_detected(self):
        def fake_execute(command, timeout, tool_name):
            self.assertEqual(command[0], "nmap")
            return (
                "Nmap scan report for 192.168.1.10\nAll 5 scanned ports on 192.168.1.10 are closed\n",
                "",
                0,
                1.0,
            )

        with patch("scanner.services.modular_scan_service._execute_command", side_effect=fake_execute):
            result = web_scan("192.168.1.10")

        self.assertEqual(result["message"], "No HTTP service detected on common web ports.")
        self.assertEqual(result["stdout"], "No HTTP service detected on common web ports.")
        self.assertEqual(result["web_ports"], [])

    def test_cidr_allows_only_discovery_and_network_audit(self):
        response = self.client.post(
            "/api/scan/",
            {"target": "192.168.1.0/24", "modules": ["fast_scan"]},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("details", response.data)

    def test_single_ip_allows_host_scan_modules(self):
        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {
                "fast_scan": lambda ip: {
                    "stdout": "fast scan output",
                    "stderr": "",
                    "status": 0,
                    "duration": 1.0,
                    "command": f"nmap -F {ip}",
                },
                "service_detection": lambda ip: {
                    "stdout": "service scan output",
                    "stderr": "",
                    "status": 0,
                    "duration": 2.0,
                    "command": f"nmap -sV {ip}",
                },
            },
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.10", "modules": ["fast_scan", "service_detection"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        self.assertIn("modules", response.data)
        self.assertIn("fast_scan", response.data["modules"])
        self.assertIn("service_detection", response.data["modules"])

    def test_invalid_ip_returns_400(self):
        response = self.client.post(
            "/api/scan/",
            {"target": "999.999.999.999", "modules": ["fast_scan"]},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "INVALID_TARGET")

    def test_invalid_custom_ports_returns_400(self):
        response = self.client.post(
            "/api/scan/",
            {"target": "192.168.1.10", "modules": ["custom_ports"], "ports": "80,abc"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_code"], "VALIDATION_ERROR")

    def test_one_failed_module_does_not_fail_the_whole_scan(self):
        def raise_port_error(_ip):
            raise Exception("Port error")

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {
                "fast_scan": lambda ip: {
                    "stdout": "fast ok",
                    "stderr": "",
                    "status": 0,
                    "duration": 1.0,
                    "command": f"nmap -F {ip}",
                },
                "service_detection": raise_port_error,
            },
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.10", "modules": ["fast_scan", "service_detection"]},
                format="json",
            )

        self.assertEqual(response.status_code, 207)
        self.assertTrue(response.data["success"])
        self.assertIn("modules", response.data)
        self.assertEqual(response.data["modules"]["service_detection"]["status"], "failed")

    def test_ansi_codes_are_removed(self):
        raw = "\x1b[31mERROR\x1b[0m line\n\x1b[32mok\x1b[0m"
        cleaned = _strip_ansi_codes(raw)

        self.assertEqual(cleaned, "ERROR line\nok")

    def test_get_scan_job_status_returns_progress(self):
        job = ScanJob.objects.create(
            ip="127.0.0.1",
            scan_type="fast",
            selected_modules=["fast"],
            timeout_seconds=120,
            status=ScanJob.STATUS_RUNNING,
            progress_message="Scan en cours...",
            output="Starting scan...\n",
        )

        response = self.client.get(f"/api/scan-jobs/{job.id}/", format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "running")
        self.assertIn("Starting scan", response.data["output"])

    def test_get_scan_job_status_returns_vulnerability_details(self):
        job = ScanJob.objects.create(
            ip="127.0.0.1",
            scan_type="vuln",
            selected_modules=["vuln"],
            timeout_seconds=600,
            status=ScanJob.STATUS_SUCCESS,
            progress_message="Scan termine",
            output=(
                "21/tcp open ftp vsftpd 2.3.4\n"
                "| ftp-vsftpd-backdoor:\n"
                "|   VULNERABLE:\n"
                "|   Backdoor in vsftpd 2.3.4\n"
                "|     State: VULNERABLE\n"
                "|     IDs:  CVE:CVE-2011-2523\n"
                "|     Risk factor: High\n"
                "|_    Remote backdoor access is possible.\n"
            ),
        )

        response = self.client.get(f"/api/scan-jobs/{job.id}/", format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["vulnerability_message"], "")
        self.assertEqual(len(response.data["vulnerability_details"]), 1)
        finding = response.data["vulnerability_details"][0]
        self.assertEqual(finding["risk"], "HIGH")
        self.assertEqual(finding["port"], 21)
        self.assertEqual(finding["service"], "ftp")
        self.assertIn("CVE-2011-2523", finding["cves"])
        self.assertIn("Backdoor", finding["title"])

    def test_get_scan_job_status_returns_no_vulnerability_message(self):
        job = ScanJob.objects.create(
            ip="127.0.0.1",
            scan_type="vuln",
            selected_modules=["vuln"],
            timeout_seconds=600,
            status=ScanJob.STATUS_SUCCESS,
            progress_message="Scan termine",
            output="Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds\n",
        )

        response = self.client.get(f"/api/scan-jobs/{job.id}/", format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["vulnerability_message"],
            "Aucune vulnérabilité détectée par les scripts Nmap.",
        )
        self.assertEqual(response.data["vulnerability_details"], [])

    def test_get_scan_history_returns_404_when_empty(self):
        response = self.client.get("/api/scans/", format="json")
        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.data)

    def test_get_scan_history_returns_paginated_results_sorted_desc(self):
        for i in range(12):
            ScanResult.objects.create(ip="127.0.0.1", result=f"result-{i}")

        response = self.client.get("/api/scans/", format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 12)
        self.assertEqual(len(response.data["results"]), 10)
        self.assertIsNotNone(response.data["next"])

    def test_get_scan_history_filter_by_ip(self):
        ScanResult.objects.create(ip="127.0.0.1", result="open ports")
        ScanResult.objects.create(ip="192.168.1.10", result="closed ports")

        response = self.client.get("/api/scans/?ip=127.0.0.1", format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["ip"], "127.0.0.1")

    def test_get_scan_history_filter_by_invalid_ip_returns_400(self):
        response = self.client.get("/api/scans/?ip=999.999.999.999", format="json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.data)

    def test_get_scan_history_search_in_result(self):
        ScanResult.objects.create(ip="127.0.0.1", result="apache http service")
        ScanResult.objects.create(ip="127.0.0.1", result="ssh service")

        response = self.client.get("/api/scans/?search=apache", format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertIn("apache", response.data["results"][0]["result"])

    def test_modular_report_uses_real_custom_ports_findings(self):
        payload = {
            "target": "192.168.1.77",
            "modules": {
                "custom_ports": {
                    "status": "success",
                    "command_used": "nmap -sV -p 135,139,445 192.168.1.77",
                    "parsed_results": [
                        {
                            "host_ip": "192.168.1.77",
                            "hostname": "",
                            "ports": [
                                {"port": 135, "protocol": "tcp", "state": "open", "service": "msrpc", "details": "msrpc Microsoft Windows RPC"},
                                {"port": 139, "protocol": "tcp", "state": "open", "service": "netbios-ssn", "details": "netbios-ssn"},
                                {"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds", "details": "microsoft-ds"},
                            ],
                        }
                    ],
                    "raw_output": (
                        "Nmap scan report for 192.168.1.77\n"
                        "135/tcp open msrpc Microsoft Windows RPC\n"
                        "139/tcp open netbios-ssn\n"
                        "445/tcp open microsoft-ds\n"
                    ),
                }
            },
        }

        scan_result = ScanResult.objects.create(ip="192.168.1.77", result=json.dumps(payload))
        html = build_modular_network_report_html(scan_result)

        self.assertIn("Custom Ports Scan", html)
        self.assertIn("Windows RPC exposure detected", html)
        self.assertIn("NetBIOS exposure detected", html)
        self.assertIn("SMB exposure detected", html)
        self.assertIn("Windows Host", html)
        self.assertNotIn("unknown", html.lower())

    def test_modular_report_web_scan_no_http_message(self):
        payload = {
            "target": "192.168.1.10",
            "modules": {
                "web_scan": {
                    "status": "warning",
                    "command_used": "nmap -Pn -n -sV --open -p 80,443,8080,8443 192.168.1.10",
                    "message": "No HTTP service detected on common web ports.",
                    "parsed_results": [],
                    "raw_output": "No HTTP service detected on common web ports.",
                }
            },
        }

        scan_result = ScanResult.objects.create(ip="192.168.1.10", result=json.dumps(payload))
        html = build_modular_network_report_html(scan_result)

        self.assertIn("No HTTP service detected on common web ports.", html)
        self.assertIn("Web Scan", html)
        self.assertNotIn("No Shadow IT findings", html)
