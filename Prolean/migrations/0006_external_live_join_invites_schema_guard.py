from django.db import migrations


def _is_postgres(schema_editor) -> bool:
    return getattr(getattr(schema_editor, "connection", None), "vendor", "") == "postgresql"


def _resolve_visible_table(schema_editor, logical_name: str) -> str:
    """
    Resolve the actual visible PostgreSQL table name for a logical Django db_table.

    Handles environments where a previous manual migration created the same table
    in lowercase (unquoted) vs mixed-case (quoted).

    Returns a safely quoted identifier like '"ActualName"' or empty string if missing.
    """
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
    Production safety net:
    earlier deploy attempts may have created the join-invite tables with an older/incomplete schema.
    This migration makes best-effort to add any missing columns + indexes without failing.
    """
    if not _is_postgres(schema_editor):
        return

    stmts: list[str] = []

    invites = _resolve_visible_table(schema_editor, "Prolean_externallivejoininvite")
    attempts = _resolve_visible_table(schema_editor, "Prolean_externallivejoinattempt")
    if not invites and not attempts:
        return

    # ExternalLiveJoinInvite columns (best-effort; nullable is fine for inserts).
    if invites:
        stmts += [
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS student_name varchar(120) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS student_email varchar(254) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS student_phone varchar(50) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS token_hash varchar(128)",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS expires_at timestamptz",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS revoked_at timestamptz",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_at timestamptz",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_user_agent text DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_device_label varchar(120) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_sec_ch_ua text DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_sec_ch_platform varchar(60) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_sec_ch_mobile varchar(20) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_ip varchar(64) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_location varchar(160) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_browser varchar(60) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_os varchar(60) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS used_device_type varchar(20) DEFAULT ''",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS created_at timestamptz",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS updated_at timestamptz",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS created_by_id bigint",
            f"ALTER TABLE {invites} ADD COLUMN IF NOT EXISTS user_id bigint",
        ]

    # ExternalLiveJoinAttempt columns.
    if attempts:
        stmts += [
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS session_id varchar(64) DEFAULT ''",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS student_cin varchar(50) DEFAULT ''",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS token_hash varchar(128) DEFAULT ''",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS ip_address varchar(64) DEFAULT ''",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS location varchar(160) DEFAULT ''",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS user_agent text DEFAULT ''",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS status varchar(30)",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS detail varchar(220) DEFAULT ''",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS created_at timestamptz",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS invite_id bigint",
            f"ALTER TABLE {attempts} ADD COLUMN IF NOT EXISTS user_id bigint",
        ]

    # Indexes used by the feature (IF NOT EXISTS makes this safe).
    if invites:
        stmts += [
            # Invite: token hash uniqueness
            f'CREATE UNIQUE INDEX IF NOT EXISTS prolean_ext_invite_token_hash_uniq ON {invites} ("token_hash")',
            # Invite: expected query patterns
            f'CREATE INDEX IF NOT EXISTS "Prolean_ext_session_created_idx" ON {invites} ("session_id", "created_at")',
            f'CREATE INDEX IF NOT EXISTS "Prolean_ext_session_cin_idx" ON {invites} ("session_id", "student_cin")',
            f'CREATE INDEX IF NOT EXISTS "Prolean_ext_session_used_idx" ON {invites} ("session_id", "used_at")',
        ]
    if attempts:
        stmts += [
            # Attempt: expected query patterns
            f'CREATE INDEX IF NOT EXISTS "Prolean_attempt_session_created_idx" ON {attempts} ("session_id", "created_at")',
            f'CREATE INDEX IF NOT EXISTS "Prolean_attempt_ip_created_idx" ON {attempts} ("ip_address", "created_at")',
            f'CREATE INDEX IF NOT EXISTS "Prolean_attempt_token_created_idx" ON {attempts} ("token_hash", "created_at")',
            f'CREATE INDEX IF NOT EXISTS "Prolean_attempt_status_created_idx" ON {attempts} ("status", "created_at")',
        ]

    with schema_editor.connection.cursor() as cursor:
        for sql in stmts:
            try:
                cursor.execute(sql)
            except Exception:
                # Never block deploy on best-effort schema recovery.
                try:
                    schema_editor.connection.rollback()
                except Exception:
                    pass


def backwards(apps, schema_editor):
    # No-op: this is a production guard migration.
    return


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("Prolean", "0005_external_live_join_invites"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
