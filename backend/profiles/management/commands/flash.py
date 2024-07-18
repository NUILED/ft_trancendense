from django.core.management.base import BaseCommand
from django.apps import apps
from django.db import transaction

class Command(BaseCommand):
    help = 'Truncate all tables in the database'

    def handle(self, *args, **kwargs):
        with transaction.atomic():
            models = apps.get_models()
            for model in models:
                model.objects.all().delete()
                self.stdout.write(f'Truncated {model.__name__} table')

        self.stdout.write(self.style.SUCCESS('Successfully truncated all tables'))
