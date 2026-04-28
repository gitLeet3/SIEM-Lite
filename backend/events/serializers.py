from rest_framework import serializers
from .models import Event, Alert


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'


class RawLogSerializer(serializers.Serializer):
    source = serializers.ChoiceField(choices=['nginx', 'pam', 'app'])
    line = serializers.CharField()
