from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def _table_exists(schema_editor, table_name: str) -> bool:
    vendor = getattr(schema_editor.connection, "vendor", "")
    with schema_editor.connection.cursor() as cursor:
        if vendor == "postgresql":
            # IMPORTANT: Do NOT use to_regclass(%s) with an unquoted identifier here.
            # PostgreSQL folds unquoted identifiers to lower-case, while Django can
            # create quoted mixed-case table names (e.g. "Prolean_externallivejoininvite").
            # Instead, look up relname directly to preserve case.
            schema = ""
            relname = table_name
            if "." in table_name:
                schema, relname = table_name.split(".", 1)
                schema = schema.strip().strip('"')
                relname = relname.strip().strip('"')
            if schema:
                cursor.execute(
                    """
                    SELECT 1
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.relkind = 'r' AND n.nspname = %s AND c.relname = %s
                    LIMIT 1
                    """,
                    [schema, relname],
                )
                return cursor.fetchone() is not None
            cursor.execute(
                """
                SELECT 1
                FROM pg_class c
                WHERE c.relkind = 'r'
                  AND c.relname = %s
                  AND pg_table_is_visible(c.oid)
                LIMIT 1
                """,
                [relname],
            )
            return cursor.fetchone() is not None
        if vendor == "sqlite":
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name = %s",
                [table_name],
            )
            return cursor.fetchone() is not None
        if vendor == "mysql":
            cursor.execute("SHOW TABLES LIKE %s", [table_name])
            return cursor.fetchone() is not None
    return False


class CreateModelIfNotExists(migrations.CreateModel):
    """
    CreateModel variant that won't fail if the table already exists.
    Useful for recovering from manual/previous schema changes in production.
    """

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        model = to_state.apps.get_model(app_label, self.name)
        table = model._meta.db_table
        if _table_exists(schema_editor, table):
            return
        try:
            schema_editor.create_model(model)
        except Exception as exc:
            # If a previous deploy already created the table, CREATE TABLE will fail.
            # In PostgreSQL, that failure aborts the current transaction and will cause:
            #   psycopg2.errors.InFailedSqlTransaction
            # unless we explicitly rollback before continuing.
            msg = str(exc).lower()
            if "already exists" in msg or "duplicate" in msg:
                try:
                    schema_editor.connection.rollback()
                except Exception:
                    pass
                return
            raise


class Migration(migrations.Migration):
    dependencies = [
        ("Prolean", "0004_externallivestudentstat_hand_raised_seconds_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        CreateModelIfNotExists(
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
                "indexes": [
                    models.Index(fields=["session_id", "created_at"], name="Prolean_ext_session_created_idx"),
                    models.Index(fields=["session_id", "student_cin"], name="Prolean_ext_session_cin_idx"),
                    models.Index(fields=["session_id", "used_at"], name="Prolean_ext_session_used_idx"),
                ],
            },
        ),
        CreateModelIfNotExists(
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
                "indexes": [
                    models.Index(fields=["session_id", "created_at"], name="Prolean_attempt_session_created_idx"),
                    models.Index(fields=["ip_address", "created_at"], name="Prolean_attempt_ip_created_idx"),
                    models.Index(fields=["token_hash", "created_at"], name="Prolean_attempt_token_created_idx"),
                    models.Index(fields=["status", "created_at"], name="Prolean_attempt_status_created_idx"),
                ],
            },
        ),
    ]
