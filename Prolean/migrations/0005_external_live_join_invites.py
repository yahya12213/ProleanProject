from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("Prolean", "0004_externallivestudentstat_hand_raised_seconds_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ExternalLiveJoinInvite",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("session_id", models.CharField(db_index=True, max_length=64)),
                ("student_cin", models.CharField(blank=True, db_index=True, default="", max_length=50)),
                ("student_name", models.CharField(blank=True, default="", max_length=120)),
                ("student_email", models.EmailField(blank=True, default="", max_length=254)),
                ("student_phone", models.CharField(blank=True, default="", max_length=50)),
                ("token_hash", models.CharField(max_length=128, unique=True)),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("revoked_at", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("used_at", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("used_user_agent", models.TextField(blank=True, default="")),
                ("used_device_label", models.CharField(blank=True, default="", max_length=120)),
                ("used_sec_ch_ua", models.TextField(blank=True, default="")),
                ("used_sec_ch_platform", models.CharField(blank=True, default="", max_length=60)),
                ("used_sec_ch_mobile", models.CharField(blank=True, default="", max_length=20)),
                ("used_ip", models.CharField(blank=True, default="", max_length=64)),
                ("used_location", models.CharField(blank=True, default="", max_length=160)),
                ("used_browser", models.CharField(blank=True, default="", max_length=60)),
                ("used_os", models.CharField(blank=True, default="", max_length=60)),
                ("used_device_type", models.CharField(blank=True, default="", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="external_live_join_invites_created",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="external_live_join_invites",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="ExternalLiveJoinAttempt",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("session_id", models.CharField(blank=True, db_index=True, default="", max_length=64)),
                ("student_cin", models.CharField(blank=True, db_index=True, default="", max_length=50)),
                ("token_hash", models.CharField(blank=True, db_index=True, default="", max_length=128)),
                ("ip_address", models.CharField(blank=True, default="", max_length=64)),
                ("location", models.CharField(blank=True, default="", max_length=160)),
                ("user_agent", models.TextField(blank=True, default="")),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("success", "Success"),
                            ("invalid", "Invalid"),
                            ("expired", "Expired"),
                            ("revoked", "Revoked"),
                            ("used", "Already used"),
                            ("rate_limited", "Rate limited"),
                            ("preview_bot", "Preview bot"),
                            ("error", "Error"),
                        ],
                        db_index=True,
                        max_length=30,
                    ),
                ),
                ("detail", models.CharField(blank=True, default="", max_length=220)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "invite",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="attempts",
                        to="Prolean.externallivejoininvite",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="external_live_join_attempts",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="externallivejoininvite",
            index=models.Index(fields=["session_id", "created_at"], name="Prolean_ext_session_created_idx"),
        ),
        migrations.AddIndex(
            model_name="externallivejoininvite",
            index=models.Index(fields=["session_id", "student_cin"], name="Prolean_ext_session_cin_idx"),
        ),
        migrations.AddIndex(
            model_name="externallivejoininvite",
            index=models.Index(fields=["session_id", "used_at"], name="Prolean_ext_session_used_idx"),
        ),
        migrations.AddIndex(
            model_name="externallivejoinattempt",
            index=models.Index(fields=["session_id", "created_at"], name="Prolean_attempt_session_created_idx"),
        ),
        migrations.AddIndex(
            model_name="externallivejoinattempt",
            index=models.Index(fields=["ip_address", "created_at"], name="Prolean_attempt_ip_created_idx"),
        ),
        migrations.AddIndex(
            model_name="externallivejoinattempt",
            index=models.Index(fields=["token_hash", "created_at"], name="Prolean_attempt_token_created_idx"),
        ),
        migrations.AddIndex(
            model_name="externallivejoinattempt",
            index=models.Index(fields=["status", "created_at"], name="Prolean_attempt_status_created_idx"),
        ),
    ]

