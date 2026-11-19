from django.db import migrations

# A copy of models.OVERALL_GATE as it was when this migration was written: migrations don't import live code.
OVERALL_GATE = [("reliability_rating", "gt", 3), ("security_rating", "gt", 3), ("security_review_rating", "gt", 3),
                ("maintainability_rating", "gt", 3)]


def add_overall_conditions(apps, schema_editor):
    """Existing projects get the overall conditions too, unless they already have one on that metric."""
    project_model = apps.get_model("core", "Project")
    condition_model = apps.get_model("core", "GateCondition")
    for project in project_model.objects.all():
        have = set(condition_model.objects.filter(project=project).values_list("metric", flat=True))
        condition_model.objects.bulk_create(
            condition_model(project=project, metric=m, op=op, threshold=t) for m, op, t in OVERALL_GATE if m not in have)


class Migration(migrations.Migration):
    dependencies = [("core", "0010_analysis_progress")]
    operations = [migrations.RunPython(add_overall_conditions, migrations.RunPython.noop)]
