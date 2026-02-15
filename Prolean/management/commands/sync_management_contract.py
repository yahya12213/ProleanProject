from django.core.management.base import BaseCommand

from Prolean.integration.sync import ContractSyncService


class Command(BaseCommand):
    help = "Synchronize Prolean projections with management-system contract updates."

    def handle(self, *args, **options):
        result = ContractSyncService().run()
        if result.get("ok"):
            self.stdout.write(
                self.style.SUCCESS(
                    f"Sync completed. Cursor={result.get('cursor')} "
                    f"updates={result.get('updates_count', 0)}"
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    f"Sync failed. Cursor={result.get('cursor')} error={result.get('error')}"
                )
            )

