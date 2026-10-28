from django.contrib.auth import views as auth_views
from django.urls import path

from core import api, views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", auth_views.LoginView.as_view(template_name="core/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("account/", views.account, name="account"),
    path("account/password/", views.ChangePasswordView.as_view(), name="password_change"),
    path("users/", views.users, name="users"),
    path("users/<int:pk>/", views.user_edit, name="user_edit"),
    path("projects/new/", views.new_project, name="new_project"),
    path("p/<slug:key>/", views.project_detail, name="project"),
    path("p/<slug:key>/scan/", views.start_scan, name="scan"),
    path("p/<slug:key>/settings/", views.project_settings, name="settings"),
    path("p/<slug:key>/members/", views.project_members, name="members"),
    path("p/<slug:key>/delete/", views.delete_project, name="delete_project"),
    path("p/<slug:key>/resolve/", views.resolve_issue, name="resolve"),
    path("p/<slug:key>/a/<int:pk>/", views.analysis_detail, name="analysis"),
    path("p/<slug:key>/a/<int:pk>/issues/", views.issue_list, name="issues"),
    path("p/<slug:key>/a/<int:pk>/source/", views.source_view, name="source"),
    path("api/projects/", api.projects),
    path("api/projects/<slug:key>/", api.project),
    path("api/projects/<slug:key>/config/", api.project_config),
    path("api/projects/<slug:key>/status/", api.status),
    path("api/projects/<slug:key>/issues/", api.issues),
    path("api/projects/<slug:key>/analyses/", api.upload),
    path("api/projects/<slug:key>/scan/", api.server_scan),
    path("api/analyses/<int:pk>/", api.analysis),
    path("api/issues/<int:pk>/", api.issue_detail),
    path("api/issues/<int:pk>/resolve/", api.resolve),
]
