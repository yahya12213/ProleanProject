from django.db import migrations


def _is_postgres(schema_editor) -> bool:
    return getattr(getattr(schema_editor, "connection", None), "vendor", "") == "postgresql"


def _resolve_visible_table(schema_editor, logical_name: str) -> str:
    name = str(logical_name or "").strip().strip('"')
    if not name:
        return ""
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.relname
            FROM pg_class c
            WHERE c.relkind = 'r'
              AND pg_table_is_visible(c.oid)
              AND (c.relname = %s OR c.relname = %s)
            LIMIT 1
            """,
            [name, name.lower()],
        )
        row = cursor.fetchone()
        if not row or not row[0]:
            return ""
        relname = str(row[0]).replace('"', "")
        return f'"{relname}"'


def forwards(apps, schema_editor):
    """
    Production recovery migration:
    ensure the core columns used by the invite creation path exist, even if an
    earlier manual/failed deploy created an incomplete table schema.
    """
    if not _is_postgres(schema_editor):
        return

    invites = _resolve_visible_table(schema_editor, "Prolean_externallivejoininvite")
    if not invites:
        return

    stmts: list[str] = [
        f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS session_id varchar(64) DEFAULT ''",
        f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS student_cin varchar(50) DEFAULT ''",
    ]

    # Recreate expected indexes now that the columns exist.
    stmts += [
        f'CREATE INDEX IF NOT EXISTS "Prolean_ext_session_created_idx" ON {invites} ("session_id", "created_at")',
        f'CREATE INDEX IF NOT EXISTS "Prolean_ext_session_cin_idx" ON {invites} ("session_id", "student_cin")',
        f'CREATE INDEX IF NOT EXISTS "Prolean_ext_session_used_idx" ON {invites} ("session_id", "used_at")',
    ]

    with schema_editor.connection.cursor() as cursor:
        for sql in stmts:
            try:
                cursor.execute(sql)
            except Exception:
                try:
                    schema_editor.connection.rollback()
                except Exception:
                    pass


def backwards(apps, schema_editor):
    return


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("Prolean", "0006_external_live_join_invites_schema_guard"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]

