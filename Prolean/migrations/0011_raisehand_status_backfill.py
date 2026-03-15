from django.db import migrations
from django.db.models import F


def forwards(apps, schema_editor):
    RaiseHand = apps.get_model("Prolean", "ExternalLiveRaiseHand")
    # Map legacy statuses to new set
    RaiseHand.objects.filter(status="approved").update(status="speaking")
    RaiseHand.objects.filter(status="hold").update(status="pending")
    RaiseHand.objects.filter(status="rejected").update(status="finished")
    # Preserve original ordering where possible
    RaiseHand.objects.filter(request_time__isnull=True).update(request_time=F("created_at"))


def backwards(apps, schema_editor):
    # No reverse mapping
    return


class Migration(migrations.Migration):
    dependencies = [
        ("Prolean", "0010_rename_prolean_attempt_session_created_idx_prolean_ext_session_9f904c_idx_and_more"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
