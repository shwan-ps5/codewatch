import pytest
from django.contrib.auth.models import User
from django.test import Client

from core.models import Project, ProjectMember


@pytest.mark.django_db
def test_pages_require_login():
    resp = Client().get("/")
    assert resp.status_code == 302 and resp.url.startswith("/login/")


@pytest.mark.django_db
def test_default_admin_must_change_password():
    c = Client()
    assert c.post("/login/", {"username": "admin", "password": "admin"}).status_code == 302
    assert c.get("/").url == "/account/password/"
    resp = c.post("/account/password/", {
        "old_password": "admin", "new_password1": "a-much-better-pass-42", "new_password2": "a-much-better-pass-42",
    })
    assert resp.status_code == 302
    assert c.get("/").status_code == 200


def logged_in(user):
    c = Client()
    c.force_login(user)
    return c


@pytest.mark.django_db
def test_projects_visible_to_owner_members_and_admins(alice, bob):
    p = Project.objects.create(key="mine", name="mine", owner=alice)
    admin = User.objects.get(username="admin")
    admin.profile.must_change_password = False
    admin.profile.save()
    assert logged_in(alice).get("/p/mine/").status_code == 200
    assert logged_in(bob).get("/p/mine/").status_code == 404
    assert logged_in(admin).get("/p/mine/").status_code == 200
    ProjectMember.objects.create(project=p, user=bob, role=ProjectMember.VIEWER)
    assert logged_in(bob).get("/p/mine/").status_code == 200
    assert logged_in(bob).get("/p/mine/settings/").status_code == 403


@pytest.mark.django_db
def test_owner_adds_member(alice, bob):
    Project.objects.create(key="mine", name="mine", owner=alice)
    logged_in(alice).post("/p/mine/members/", {"username": "bob", "role": "contributor"})
    assert Project.objects.get(key="mine").role_of(bob) == "contributor"


@pytest.mark.django_db
def test_user_admin_is_superuser_only(alice):
    assert logged_in(alice).get("/users/").status_code == 403


@pytest.mark.django_db
def test_non_admin_cannot_register_local_path(alice, tmp_path):
    resp = logged_in(alice).post("/projects/new/", {"key": "x", "name": "x", "repo_url": str(tmp_path)})
    assert resp.status_code == 200 and not Project.objects.filter(key="x").exists()
    assert b"must be an https://" in resp.content


@pytest.mark.django_db
def test_token_shown_once_and_stored_hashed(alice):
    resp = logged_in(alice).post("/account/", {"name": "Claude", "scope": "read"})
    raw = resp.context["new_token"]
    token = alice.api_tokens.get()
    assert raw.startswith("cw_") and raw not in (token.key_hash, token.prefix + "x")
    assert raw.encode() not in logged_in(alice).get("/account/").content
