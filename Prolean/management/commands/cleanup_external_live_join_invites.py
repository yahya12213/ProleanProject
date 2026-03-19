from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from Prolean.models import ExternalLiveJoinAttempt, ExternalLiveJoinInvite


class Command(BaseCommand):
    help = "Cleanup expired/old one-click external live join invites and attempts."

    def add_arguments(self, parser):
        parser.add_argument("--expired-days", type=int, default=14, help="Delete expired invites older than N days.")
        parser.add_argument("--used-days", type=int, default=90, help="Delete used invites older than N days.")
        parser.add_argument("--attempt-days", type=int, default=30, help="Delete join attempts older than N days.")

    def handle(self, *args, **options):
        now = timezone.now()
        expired_days = int(options["expired_days"])
        used_days = int(options["used_days"])
        attempt_days = int(options["attempt_days"])

        expired_cutoff = now - timedelta(days=max(1, expired_days))
        used_cutoff = now - timedelta(days=max(1, used_days))
        attempt_cutoff = now - timedelta(days=max(1, attempt_days))

        expired_qs = ExternalLiveJoinInvite.objects.filter(
            used_at__isnull=True,
            expires_at__lt=expired_cutoff,
        )
        used_qs = ExternalLiveJoinInvite.objects.filter(
            used_at__lt=used_cutoff,
        )
        attempts_qs = ExternalLiveJoinAttempt.objects.filter(created_at__lt=attempt_cutoff)

        expired_count = expired_qs.count()
        used_count = used_qs.count()
        attempt_count = attempts_qs.count()

        expired_qs.delete()
        used_qs.delete()
        attempts_qs.delete()

        self.stdout.write(
            self.style.SUCCESS(
                f"Deleted invites: expired={expired_count}, used={used_count}; attempts={attempt_count}."
            )
        )

