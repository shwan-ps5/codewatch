from django.shortcuts import redirect
from django.urls import reverse


class ForcePasswordChangeMiddleware:
    """Keeps the seeded admin/admin account locked to the password-change page until the password is changed."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if user.is_authenticated and getattr(getattr(user, "profile", None), "must_change_password", False):
            allowed = {reverse("password_change"), reverse("logout")}
            if request.path not in allowed and not request.path.startswith("/api/"):
                return redirect("password_change")
        return self.get_response(request)
