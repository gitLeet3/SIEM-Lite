from django.db import models

class Event(models.Model):

    class Source(models.TextChoices):
        NGINX = 'nginx', 'Nginx'
        PAM = 'pam', 'PAM'
        APP = 'app', 'Application'

    class Category(models.TextChoices):
        AUTH_FAILURE = 'auth_failure', 'Authentication Failure'
        AUTH_SUCCESS = 'auth_success', 'Authentication Success'
        ACCESS = 'access', 'Access'
        ERROR = 'error', 'Error'

    class Severity(models.TextChoices):
        INFO = 'info', 'Info'
        WARNING = 'warning', 'Warning'
        CRITICAL = 'critical', 'Critical'

    timestamp = models.DateTimeField()
    source = models.CharField(max_length=20, choices=Source.choices)
    category = models.CharField(max_length=20, choices=Category.choices)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    username = models.CharField(max_length=100, null=True, blank=True)
    action = models.CharField(max_length=255, null=True, blank=True)
    outcome = models.CharField(max_length=50, null=True, blank=True)
    raw = models.TextField()
    parsed = models.JSONField(default=dict)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp} {self.source} {self.category}"


class Alert(models.Model):

    class Severity(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'

    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        ACKNOWLEDGED = 'acknowledged', 'Acknowledged'
        RESOLVED = 'resolved', 'Resolved'

    rule = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    username = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField()
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.rule} {self.severity} {self.status}"
