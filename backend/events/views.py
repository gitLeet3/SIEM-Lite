from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone
from .models import Event, Alert
from .serializers import EventSerializer, AlertSerializer, RawLogSerializer
from .parsers import PAMParser, NginxParser


PARSERS = {
    'pam': PAMParser(),
    'nginx': NginxParser(),
}


@api_view(['POST'])
def ingest(request):
    serializer = RawLogSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    source = serializer.validated_data['source']
    line = serializer.validated_data['line']

    parser = PARSERS.get(source)
    if not parser:
        return Response(
            {'error': f'No parser for source: {source}'},
            status=status.HTTP_400_BAD_REQUEST
        )

    normalized = parser.parse(line)
    if not normalized:
        return Response(
            {'detail': 'Line did not match any known pattern'},
            status=status.HTTP_204_NO_CONTENT
        )

    event = Event.objects.create(
        timestamp=normalized.timestamp,
        source=normalized.source,
        category=normalized.category,
        severity=normalized.severity,
        source_ip=normalized.source_ip,
        username=normalized.username,
        action=normalized.action,
        outcome=normalized.outcome,
        raw=normalized.raw,
        parsed=normalized.parsed,
    )

    return Response(EventSerializer(event).data, status=status.HTTP_201_CREATED)


class EventViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    filterset_fields = ['source', 'category', 'severity', 'source_ip']


class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    filterset_fields = ['severity', 'status', 'rule']
