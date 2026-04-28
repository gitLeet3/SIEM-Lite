from datetime import datetime, timedelta
from django.db.models import Count
from .models import Event, Alert


def run_all_detectors():
    detect_brute_force()
    detect_admin_probing()
    detect_error_spike()


def detect_brute_force(window_minutes=5, threshold=5):
    cutoff = datetime.now() - timedelta(minutes=window_minutes)

    results = Event.objects.filter(
        category='auth_failure',
        timestamp__gte=cutoff
    ).values('source_ip').annotate(
        attempts=Count('id')
    ).filter(
        attempts__gte=threshold
    )

    for result in results:
        ip = result['source_ip']
        attempts = result['attempts']

        if not ip:
            continue

        already_alerted = Alert.objects.filter(
            rule='brute_force',
            source_ip=ip,
            status='open',
            created_at__gte=cutoff
        ).exists()

        if already_alerted:
            continue

        sources = list(
            Event.objects.filter(
                category='auth_failure',
                source_ip=ip,
                timestamp__gte=cutoff
            ).values_list('source', flat=True).distinct()
        )

        Alert.objects.create(
            rule='brute_force',
            severity='critical',
            source_ip=ip,
            description=(
                f"{attempts} failed login attempts from {ip} "
                f"via {', '.join(sources)} "
                f"within the last {window_minutes} minutes."
            ),
            evidence={
                'attempts': attempts,
                'window_minutes': window_minutes,
                'threshold': threshold,
                'sources': sources,
            }
        )


def detect_admin_probing(window_minutes=10, threshold=5):
    cutoff = datetime.now() - timedelta(minutes=window_minutes)

    results = Event.objects.filter(
        source='nginx',
        timestamp__gte=cutoff,
        parsed__path__in=[
            '/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config'
        ]
    ).values('source_ip').annotate(
        attempts=Count('id')
    ).filter(
        attempts__gte=threshold
    )

    for result in results:
        ip = result['source_ip']
        attempts = result['attempts']

        already_alerted = Alert.objects.filter(
            rule='admin_probing',
            source_ip=ip,
            status='open',
            created_at__gte=cutoff
        ).exists()

        if already_alerted:
            continue

        Alert.objects.create(
            rule='admin_probing',
            severity='high',
            source_ip=ip,
            description=(
                f"{attempts} attempts to access sensitive endpoints from {ip} "
                f"within the last {window_minutes} minutes."
            ),
            evidence={
                'attempts': attempts,
                'window_minutes': window_minutes,
                'threshold': threshold,
            }
        )


def detect_error_spike(window_minutes=5, threshold=20):
    cutoff = datetime.now() - timedelta(minutes=window_minutes)

    count = Event.objects.filter(
        source='nginx',
        category='error',
        timestamp__gte=cutoff
    ).count()

    if count >= threshold:
        already_alerted = Alert.objects.filter(
            rule='error_spike',
            status='open',
            created_at__gte=cutoff
        ).exists()

        if not already_alerted:
            Alert.objects.create(
                rule='error_spike',
                severity='medium',
                description=(
                    f"{count} HTTP errors detected within "
                    f"the last {window_minutes} minutes."
                ),
                evidence={
                    'error_count': count,
                    'window_minutes': window_minutes,
                    'threshold': threshold,
                }
            )