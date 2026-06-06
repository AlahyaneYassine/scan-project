from unittest.mock import patch

from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APITestCase

from .models import Profile
from .services import scan_orchestrator_service


class ModularEnterpriseTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="analyst2", password="secret123")
        self.user.profile.role = Profile.ROLE_ANALYST
        self.user.profile.save(update_fields=["role"])
        self.client.force_authenticate(user=self.user)

    def test_cidr_target_allowed_for_network_modules(self):
        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {
                "host_discovery": lambda tgt: {
                    "stdout": "Nmap scan report for host (192.168.18.1)\n",
                    "stderr": "",
                    "status": "success",
                    "duration": 0.5,
                    "command": "nmap -sn",
                }
            },
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.18.0/24", "modules": ["host_discovery"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.get("target_type"), "cidr")

    def test_reject_plain_network_without_prefix(self):
        response = self.client.post(
            "/api/scan/",
            {"target": "192.168.18.0", "modules": ["host_discovery"]},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get("error_code"), "INVALID_TARGET")

    def test_selected_modules_only_run_selected_commands(self):
        calls = []

        def fast_scan(ip):
            calls.append("fast_scan")
            return {
                "stdout": "Nmap scan report for host (127.0.0.1)\n",
                "stderr": "",
                "status": "success",
                "duration": 0.1,
                "command": "nmap -F",
            }

        def vulnerability_scan(ip):
            raise AssertionError("vulnerability_scan should not be called for this test")

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"fast_scan": fast_scan, "vulnerability_scan": vulnerability_scan},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "127.0.0.1", "modules": ["fast_scan"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("fast_scan", calls)

    def test_heavy_scans_not_allowed_on_cidr(self):
        # vulnerability_scan is a single-host (heavy) module and should be rejected for CIDR targets
        response = self.client.post(
            "/api/scan/",
            {"target": "192.168.18.0/24", "modules": ["vulnerability_scan"]},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.get("error_code"), "INVALID_SCAN_TYPE")

    def test_ansi_codes_stripped_and_parsed_results_contain_expected_fields(self):
        raw = "\x1b[31mNmap scan report for host (192.168.1.55)\x1b[0m\n\x1b[32m22/tcp open ssh OpenSSH\x1b[0m\n80/tcp open http Apache\n"

        def ssh_scan(ip):
            return {
                "stdout": raw,
                "stderr": "",
                "status": "success",
                "duration": 0.2,
                "command": "nmap -p22,80",
            }

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"ssh_scan": ssh_scan},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.55", "modules": ["ssh_scan"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)

        mod = response.data["modules"].get("ssh_scan")
        self.assertIsNotNone(mod)
        parsed = mod.get("parsed_results")
        self.assertIsInstance(parsed, list)
        self.assertGreaterEqual(len(parsed), 1)

        host = parsed[0]
        self.assertEqual(host.get("host_ip"), "192.168.1.55")
        self.assertEqual(host.get("open_ports"), [22, 80])
        self.assertIsInstance(host.get("services"), list)
        self.assertIn("risk_level", host)

    def test_cidr_network_address_is_not_returned_as_asset(self):
        raw = (
            "Nmap scan report for 192.168.18.0\n"
            "22/tcp open ssh OpenSSH\n"
            "Nmap scan report for 192.168.18.5\n"
            "22/tcp open ssh OpenSSH\n"
        )

        def network_audit(target):
            return {
                "stdout": raw,
                "stderr": "",
                "status": "success",
                "duration": 0.2,
                "command": f"nmap --top-ports 100 --open {target}",
            }

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"network_audit": network_audit},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.18.0/24", "modules": ["network_audit"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        parsed = response.data["modules"]["network_audit"]["parsed_results"]
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["host_ip"], "192.168.18.5")

    def test_no_open_ports_returns_empty_results_and_debug(self):
        raw = "Nmap scan report for 192.168.1.55\nAll 1000 scanned ports on 192.168.1.55 are closed\n"

        def service_detection(ip):
            return {
                "stdout": raw,
                "stderr": "",
                "status": "success",
                "duration": 0.2,
                "command": f"nmap -sV {ip}",
            }

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"service_detection": service_detection},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.55", "modules": ["service_detection"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        module = response.data["modules"]["service_detection"]
        self.assertEqual(module["parsed_results"], [])
        self.assertEqual(module["command_used"], "nmap -sV 192.168.1.55")
        self.assertEqual(module["executed_on"], "Kali VM")
        self.assertIn("debug", response.data)
        self.assertEqual(response.data["debug"]["service_detection"]["executed_on"], "Kali VM")
        self.assertEqual(response.data["debug"]["service_detection"]["parsed_results"], [])

    def test_custom_ports_scan_keeps_open_closed_and_filtered_ports(self):
        raw = (
            "Nmap scan report for 192.168.1.77\n"
            "80/tcp open http Apache\n"
            "443/tcp closed https\n"
            "8080/tcp filtered http-proxy\n"
        )

        def custom_ports(target, ports):
            return {
                "stdout": raw,
                "stderr": "",
                "status": "success",
                "duration": 0.4,
                "command": f"nmap -sV -p {ports} {target}",
            }

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"custom_ports": custom_ports},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.77", "modules": ["custom_ports"], "ports": "80,443,8080"},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        module = response.data["modules"]["custom_ports"]
        parsed = module["parsed_results"]
        self.assertEqual(len(parsed), 1)
        ports = parsed[0]["ports"]
        states = {str(port["port"]): port["state"] for port in ports}
        self.assertEqual(states["80"], "open")
        self.assertEqual(states["443"], "closed")
        self.assertEqual(states["8080"], "filtered")
        self.assertIn("ports", parsed[0])

    def test_camera_scan_detects_vendor_confidence_and_whatweb_output(self):
        raw = (
            "Nmap scan report for 192.168.1.88\n"
            "Host is up (0.012s latency).\n"
            "554/tcp open  rtsp  Live555 streaming media\n"
            "80/tcp open  http  Boa webserver\n"
            "| http-title: Hikvision IP Camera\n"
            "| http-server-header: Boa/0.94\n"
        )
        whatweb_output = "--- WhatWeb 192.168.1.88:80 ---\nhttp://192.168.1.88 [200 OK] Title[Hikvision IP Camera] Server[Boa/0.94]\n"

        def camera_scan(target):
            return {
                "stdout": raw,
                "whatweb_output": whatweb_output,
                "stderr": "",
                "status": "success",
                "duration": 1.2,
                "command": f"nmap -sV -Pn -p 80,554 {target}",
            }

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"camera_scan": camera_scan},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.0/24", "modules": ["camera_scan"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        module = response.data["modules"]["camera_scan"]
        parsed = module["parsed_results"]
        self.assertEqual(len(parsed), 1)
        camera = parsed[0]
        self.assertEqual(camera["host_ip"], "192.168.1.88")
        self.assertEqual(camera["vendor"], "Hikvision")
        self.assertEqual(camera["detected_service"], "RTSP")
        self.assertEqual(camera["confidence_level"], "HIGH")
        self.assertIn(554, camera["open_ports"])
        self.assertIn(80, camera["open_ports"])
        self.assertIn("whatweb_output", module)
        self.assertIn("Hikvision", module["whatweb_output"])

    def test_camera_scan_ignores_non_camera_hosts(self):
        raw = (
            "Nmap scan report for 192.168.1.55\n"
            "Host is up (0.01s latency).\n"
            "22/tcp open  ssh  OpenSSH 9.6\n"
        )

        def camera_scan(target):
            return {
                "stdout": raw,
                "whatweb_output": "",
                "stderr": "",
                "status": "success",
                "duration": 0.8,
                "command": f"nmap -sV -Pn -p 80,554 {target}",
            }

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"camera_scan": camera_scan},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.0/24", "modules": ["camera_scan"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["modules"]["camera_scan"]["parsed_results"], [])

    def test_camera_scan_preserves_summary_fields(self):
        def camera_scan(target):
            return {
                "stdout": "Nmap scan report for 192.168.1.88\n554/tcp open rtsp Live555\n",
                "whatweb_output": "",
                "stderr": "",
                "status": "success",
                "duration": 1.0,
                "command": "nmap camera pipeline",
                "discovery_total_hosts": 14,
                "camera_hosts_scanned": 5,
                "probable_cameras_detected": 1,
            }

        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {"camera_scan": camera_scan},
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "192.168.1.0/24", "modules": ["camera_scan"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        module = response.data["modules"]["camera_scan"]
        self.assertEqual(module["discovery_total_hosts"], 14)
        self.assertEqual(module["camera_hosts_scanned"], 5)
        self.assertEqual(module["probable_cameras_detected"], 1)
        self.assertEqual(response.data["debug"]["camera_scan"]["discovery_total_hosts"], 14)

    def test_api_returns_structured_json_keys(self):
        with patch.dict(
            scan_orchestrator_service.MODULE_FUNCTIONS,
            {
                "fast_scan": lambda tgt: {
                    "stdout": "Nmap scan report for host (127.0.0.1)\n",
                    "stderr": "",
                    "status": "success",
                    "duration": 0.1,
                    "command": "nmap -F",
                }
            },
            clear=False,
        ):
            response = self.client.post(
                "/api/scan/",
                {"target": "127.0.0.1", "modules": ["fast_scan"]},
                format="json",
            )

        self.assertEqual(response.status_code, 200)
        for key in ("target", "target_type", "modules", "debug", "warnings", "errors", "scan_id", "total_duration", "timestamp", "success"):
            self.assertIn(key, response.data)
