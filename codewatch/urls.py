from django.urls import path

from core import views

urlpatterns = [
    path("", views.index, name="index"),
    path("p/<slug:key>/", views.project_detail, name="project"),
    path("p/<slug:key>/scan/", views.start_scan, name="scan"),
    path("p/<slug:key>/settings/", views.project_settings, name="settings"),
    path("p/<slug:key>/resolve/", views.resolve_issue, name="resolve"),
    path("p/<slug:key>/a/<int:pk>/", views.analysis_detail, name="analysis"),
    path("p/<slug:key>/a/<int:pk>/issues/", views.issue_list, name="issues"),
    path("p/<slug:key>/a/<int:pk>/source/", views.source_view, name="source"),
]
