from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def create_missing_profiles(apps, schema_editor):
    User = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    Profile = apps.get_model("scanner", "Profile")

    for user in User.objects.all():
        Profile.objects.get_or_create(user_id=user.id)


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Profile",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "role",
                    models.CharField(
                        choices=[("admin", "Admin"), ("analyst", "Analyst"), ("user", "User")],
                        default="user",
                        max_length=16,
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="profile",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.RunPython(create_missing_profiles, migrations.RunPython.noop),
    ]
