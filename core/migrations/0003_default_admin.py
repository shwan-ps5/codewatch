import os
import secrets

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db import migrations


def initial_password():
    """CODEWATCH_ADMIN_PASSWORD, else a random one in a file only this account can read. A well-known default
    (admin/admin) let anyone in until someone changed it."""
    password = os.environ.get("CODEWATCH_ADMIN_PASSWORD")
    if password:
        return password
    password = secrets.token_urlsafe(16)
    path = settings.CODEWATCH_CACHE / "admin-password.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as out:
        out.write(password + "\n")
    print(f"\n  Created the administrator account 'admin'; its first password is in {path}")
    return password


def create_admin(apps, schema_editor):
    User = apps.get_model("auth", "User")
    Profile = apps.get_model("core", "Profile")
    Project = apps.get_model("core", "Project")
    if User.objects.filter(is_superuser=True).exists():
        return
    admin = User.objects.create(
        username="admin", password=make_password(initial_password()), is_superuser=True, is_staff=True, is_active=True
    )
    Profile.objects.create(user=admin, must_change_password=True)
    Project.objects.filter(owner__isnull=True).update(owner=admin)


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0002_auth_tokens_a11y"),
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [migrations.RunPython(create_admin, migrations.RunPython.noop)]
