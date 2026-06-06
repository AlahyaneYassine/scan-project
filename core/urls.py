from django.contrib import admin
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect, render
from django.urls import include, path
from scanner.models import get_effective_role, Profile
from scanner.views import HomeView


def logout_view(request):
    logout(request)
    return redirect("login")


class AdminProtectionMiddleware:
    """
    Middleware that protects the /admin/ path by checking user role.
    Only users with ROLE_ADMIN can access the Django admin panel.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/admin/"):
            if not request.user.is_authenticated:
                return redirect("login")
            
            role = get_effective_role(request.user)
            if role != Profile.ROLE_ADMIN:
                return render(request, "403.html", status=403)
        
        return self.get_response(request)


urlpatterns = [
    path("admin/", admin.site.urls),
    path("", HomeView.as_view(), name="home"),
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="login.html"),
        name="login",
    ),
    path(
        "logout/",
        logout_view,
        name="logout",
    ),
    path("api/", include("scanner.urls")),
]
