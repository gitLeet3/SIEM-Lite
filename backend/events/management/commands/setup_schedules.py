from django.core.management.base import BaseCommand
from django_q.models import Schedule


class Command(BaseCommand):
    help = 'Sets up Django-Q schedules for detection jobs'

    def handle(self, *args, **kwargs):
        Schedule.objects.get_or_create(
            name='Run all detectors',
            defaults={
                'func': 'events.detectors.run_all_detectors',
                'schedule_type': Schedule.MINUTES,
                'minutes': 1,
            }
        )
        self.stdout.write(self.style.SUCCESS('Schedules configured successfully'))
