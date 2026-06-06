from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanner", "0003_scanalert"),
    ]

    operations = [
        migrations.CreateModel(
            name="LogRequest",
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
                ("ip", models.GenericIPAddressField(protocol="IPv4")),
                ("endpoint", models.CharField(max_length=255)),
                ("date", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ["-date"],
            },
        ),
        migrations.CreateModel(
            name="IntrusionAlert",
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
                    "ip",
                    models.GenericIPAddressField(protocol="IPv4"),
                ),
                ("endpoint", models.CharField(max_length=255)),
                (
                    "alert_type",
                    models.CharField(
                        choices=[
                            ("TRAFFIC_SPIKE", "Traffic spike"),
                            ("PORT_SCAN", "Port scan"),
                            ("BRUTE_FORCE", "Brute force"),
                        ],
                        max_length=32,
                    ),
                ),
                ("message", models.CharField(max_length=255)),
                ("date", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ["-date"],
            },
        ),
    ]
