from django.contrib import admin

from .models import IntrusionAlert, LogRequest, Profile, ScanAlert, ScanResult


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role")
    list_select_related = ("user",)
    search_fields = ("user__username", "user__email", "role")
    list_filter = ("role",)


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ("ip", "date")
    search_fields = ("ip",)
    ordering = ("-date",)


@admin.register(ScanAlert)
class ScanAlertAdmin(admin.ModelAdmin):
    list_display = ("level", "scan_result", "created_at")
    list_select_related = ("scan_result",)
    search_fields = ("scan_result__ip", "message", "level")
    list_filter = ("level", "created_at")
    ordering = ("-created_at",)


@admin.register(LogRequest)
class LogRequestAdmin(admin.ModelAdmin):
    list_display = ("ip", "endpoint", "date")
    search_fields = ("ip", "endpoint")
    list_filter = ("date",)
    ordering = ("-date",)


@admin.register(IntrusionAlert)
class IntrusionAlertAdmin(admin.ModelAdmin):
    list_display = ("alert_type", "ip", "endpoint", "date")
    search_fields = ("ip", "endpoint", "message", "alert_type")
    list_filter = ("alert_type", "date")
    ordering = ("-date",)
