from django.core.management.base import BaseCommand

from core.catalog import update


class Command(BaseCommand):
    help = "Re-import rules into this server's cache (optionally upgrading the analyzers first)."

    def add_arguments(self, parser):
        parser.add_argument("--upgrade-tools", action="store_true", help="Upgrade analyzers before importing")

    def handle(self, upgrade_tools, **_):
        meta = update.run_update(upgrade=upgrade_tools, log=self.stdout.write)
        self.stdout.write(f"{meta['rules']} imported rules; failed sources: {meta['failed_sources'] or 'none'}")
