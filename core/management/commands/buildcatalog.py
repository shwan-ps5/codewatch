from django.core.management.base import BaseCommand

from core import catalog
from core.catalog.build import build


class Command(BaseCommand):
    help = "Re-import catalog/imported/ (the snapshot shipped in the repository). Custom rules are untouched."

    def handle(self, **_):
        target = catalog.BUNDLED_DIR / "imported"
        previous = catalog.read_json(target / "rules.json", [])
        meta = build(target, log=self.stdout.write, previous=previous)
        catalog.reload()
        self.stdout.write(f"{meta['rules']} imported rules")
