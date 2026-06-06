from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class Profile(models.Model):
    ROLE_ADMIN = "admin"
    ROLE_ANALYST = "analyst"
    ROLE_USER = "user"

    ROLE_CHOICES = [
        (ROLE_ADMIN, "Admin"),
        (ROLE_ANALYST, "Analyst"),
        (ROLE_USER, "User"),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_USER)

    def __str__(self) -> str:
        return f"{self.user.username} - {self.role}"


def get_effective_role(user) -> str:
    if not user.is_authenticated:
        return Profile.ROLE_USER
    if user.is_superuser or user.is_staff:
        return Profile.ROLE_ADMIN

    profile = getattr(user, "profile", None)
    if profile is not None:
        return profile.role
    return Profile.ROLE_USER


@receiver(post_save, sender=get_user_model())
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


class ScanResult(models.Model):
    ip = models.GenericIPAddressField(protocol="IPv4")
    result = models.TextField()
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-date"]

    def __str__(self) -> str:
        return f"{self.ip} - {self.date.isoformat()}"


class ScanJob(models.Model):
    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_TIMEOUT = "timeout"
    STATUS_ERROR = "error"

    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_TIMEOUT, "Timeout"),
        (STATUS_ERROR, "Error"),
    ]

    ip = models.GenericIPAddressField(protocol="IPv4")
    scan_type = models.CharField(max_length=16, default="fast")
    selected_modules = models.JSONField(default=list)
    ports = models.CharField(max_length=128, blank=True)
    timeout_seconds = models.PositiveIntegerField(default=300)
    command = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED)
    progress_message = models.CharField(max_length=255, blank=True)
    output = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    scan_result = models.OneToOneField(
        ScanResult,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="job",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.ip} - {self.scan_type} - {self.status}"


class LogRequest(models.Model):
    ip = models.GenericIPAddressField(protocol="IPv4")
    endpoint = models.CharField(max_length=255)
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-date"]

    def __str__(self) -> str:
        return f"{self.ip} - {self.endpoint} - {self.date.isoformat()}"


class IntrusionAlert(models.Model):
    ALERT_TRAFFIC_SPIKE = "TRAFFIC_SPIKE"
    ALERT_PORT_SCAN = "PORT_SCAN"
    ALERT_BRUTE_FORCE = "BRUTE_FORCE"

    ALERT_CHOICES = [
        (ALERT_TRAFFIC_SPIKE, "Traffic spike"),
        (ALERT_PORT_SCAN, "Port scan"),
        (ALERT_BRUTE_FORCE, "Brute force"),
    ]

    ip = models.GenericIPAddressField(protocol="IPv4")
    endpoint = models.CharField(max_length=255)
    alert_type = models.CharField(max_length=32, choices=ALERT_CHOICES)
    message = models.CharField(max_length=255)
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-date"]

    def __str__(self) -> str:
        return f"{self.alert_type} - {self.ip} - {self.date.isoformat()}"


class ScanAlert(models.Model):
    LEVEL_HIGH = "HIGH"
    LEVEL_MEDIUM = "MEDIUM"
    LEVEL_LOW = "LOW"

    LEVEL_CHOICES = [
        (LEVEL_HIGH, "High"),
        (LEVEL_MEDIUM, "Medium"),
        (LEVEL_LOW, "Low"),
    ]

    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name="alerts")
    level = models.CharField(max_length=16, choices=LEVEL_CHOICES, default=LEVEL_HIGH)
    message = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.level} - {self.scan_result.ip} - {self.created_at.isoformat()}"
