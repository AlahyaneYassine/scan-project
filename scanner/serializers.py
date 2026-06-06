from rest_framework import serializers

from .models import ScanAlert, ScanResult
from .services.scan_validation_service import NETWORK_MODULES, SINGLE_HOST_MODULES


class ModularScanSerializer(serializers.Serializer):
    """Serializer for modular scan API requests."""

    target = serializers.CharField(
        max_length=255,
        help_text="Target IP or CIDR (e.g., 192.168.1.100 or 192.168.1.0/24)"
    )
    modules = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of modules to execute"
    )
    allow_public = serializers.BooleanField(required=False, default=False)
    ports = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=128,
        help_text="Port specification for custom_ports module (e.g., 80,443,8080)"
    )

    def validate_target(self, value: str) -> str:
        """Validate and normalize target."""
        return value.strip()

    def validate_modules(self, value: list[str]) -> list[str]:
        """Validate module names."""
        if not value:
            raise serializers.ValidationError("Veuillez sélectionner au moins un module.")

        valid_modules = sorted({*NETWORK_MODULES, *SINGLE_HOST_MODULES})
        normalized = [m.strip().lower() for m in value]
        invalid = [m for m in normalized if m not in valid_modules]

        if invalid:
            raise serializers.ValidationError(
                f"Modules invalides: {', '.join(invalid)}. "
                f"Modules autorisés: {', '.join(valid_modules)}"
            )

        return normalized

    def validate_ports(self, value: str) -> str:
        """Validate port specification format."""
        if not value:
            return ""

        normalized = value.strip().replace(" ", "")

        import re
        port_pattern = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$')

        if not port_pattern.match(normalized):
            raise serializers.ValidationError(
                "Format de ports invalide. Utilisez par exemple: 80,443,8080"
            )

        return normalized


class ScanSerializer(serializers.Serializer):
    ip = serializers.IPAddressField(
        protocol="IPv4",
        error_messages={"invalid": "Adresse IPv4 invalide."},
    )
    scan_type = serializers.ChoiceField(
        choices=["fast", "full", "vuln", "web", "quick", "service", "os"],
        default="fast",
        required=False,
    )
    fast = serializers.BooleanField(required=False, default=False)
    full = serializers.BooleanField(required=False, default=False)
    vuln = serializers.BooleanField(required=False, default=False)
    web = serializers.BooleanField(required=False, default=False)
    ports = serializers.CharField(required=False, allow_blank=True, max_length=128)

    def validate_ip(self, value: str) -> str:
        return value.strip()

    def validate_ports(self, value: str) -> str:
        normalized = (value or "").strip().replace(" ", "")
        if not normalized:
            return ""

        chunks = normalized.split(",")
        for chunk in chunks:
            if not chunk.isdigit():
                raise serializers.ValidationError("Le format des ports est invalide. Exemple: 80,443,8080")
            port = int(chunk)
            if port < 1 or port > 65535:
                raise serializers.ValidationError("Chaque port doit etre entre 1 et 65535.")

        return ",".join(str(int(chunk)) for chunk in chunks)


class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = ["id", "ip", "result", "date"]


class DiscoverySerializer(serializers.Serializer):
    network = serializers.CharField()

    def validate_network(self, value: str) -> str:
        import ipaddress

        try:
            # allow both networks and single IPs (treated as /32)
            net = ipaddress.ip_network(value.strip(), strict=False)
        except (ValueError, Exception) as exc:
            raise serializers.ValidationError("Réseau CIDR invalide. Exemple attendu: 192.168.1.0/24") from exc

        return str(net)


class ScanAlertSerializer(serializers.ModelSerializer):
    scan_id = serializers.IntegerField(source="scan_result.id", read_only=True)
    ip = serializers.CharField(source="scan_result.ip", read_only=True)

    class Meta:
        model = ScanAlert
        fields = ["id", "scan_id", "ip", "level", "message", "created_at"]
