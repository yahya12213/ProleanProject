from django.db import migrations


def _is_postgres(schema_editor) -> bool:
    return getattr(getattr(schema_editor, "connection", None), "vendor", "") == "postgresql"


def _quote_ident(value: str) -> str:
    return '"' + str(value or "").replace('"', '""') + '"'


def _find_all_candidate_tables(schema_editor, logical_name: str) -> list[tuple[str, str]]:
    """
    Return a list of (schema, table) for all tables whose relname matches the
    logical name or its lowercased variant, across all non-system schemas.

    This handles cases where earlier deploy attempts created both:
      - "Prolean_externallivejoininvite" (quoted, mixed-case)
      - prolean_externallivejoininvite (unquoted, lower-case)
    """
    name = str(logical_name or "").strip().strip('"')
    if not name:
        return []
    lower = name.lower()
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT n.nspname, c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND (c.relname = %s OR c.relname = %s)
            ORDER BY
              CASE WHEN c.relname = %s THEN 0 ELSE 1 END,
              n.nspname ASC
            """,
            [name, lower, name],
        )
        return [(str(r[0]), str(r[1])) for r in (cursor.fetchall() or []) if r and r[0] and r[1]]


def forwards(apps, schema_editor):
    """
    Production recovery migration (broad):
    add core columns on *all* candidate invite/attempt tables to ensure the table
    Django queries against has the required schema.
    """
    if not _is_postgres(schema_editor):
        return

    invite_tables = _find_all_candidate_tables(schema_editor, "Prolean_externallivejoininvite")
    attempt_tables = _find_all_candidate_tables(schema_editor, "Prolean_externallivejoinattempt")
    if not invite_tables and not attempt_tables:
        return

    def _qualified(schema: str, table: str) -> str:
        return f"{_quote_ident(schema)}.{_quote_ident(table)}"

    stmts: list[str] = []

    for schema, table in invite_tables:
        q = _qualified(schema, table)
        stmts += [
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS session_id varchar(64) DEFAULT ''",
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS student_cin varchar(50) DEFAULT ''",
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS token_hash varchar(128)",
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS expires_at timestamptz",
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS revoked_at timestamptz",
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS used_at timestamptz",
        ]

    for schema, table in attempt_tables:
        q = _qualified(schema, table)
        stmts += [
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS session_id varchar(64) DEFAULT ''",
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS student_cin varchar(50) DEFAULT ''",
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS token_hash varchar(128) DEFAULT ''",
            f"ALTER TABLE {q} ADD COLUMN IF NOT EXISTS status varchar(30)",
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
        ("Prolean", "0007_external_live_join_invites_add_core_columns"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]

