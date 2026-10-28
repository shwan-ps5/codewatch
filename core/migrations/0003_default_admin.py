from django.contrib.auth.hashers import make_password
from django.db import migrations


def create_admin(apps, schema_editor):
    User = apps.get_model("auth", "User")
    Profile = apps.get_model("core", "Profile")
    Project = apps.get_model("core", "Project")
    if User.objects.filter(is_superuser=True).exists():
        return
    admin = User.objects.create(
        username="admin", password=make_password("admin"), is_superuser=True, is_staff=True, is_active=True
    )
    Profile.objects.create(user=admin, must_change_password=True)
    Project.objects.filter(owner__isnull=True).update(owner=admin)


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0002_auth_tokens_a11y"),
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [migrations.RunPython(create_admin, migrations.RunPython.noop)]
