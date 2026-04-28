import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NormalizedEvent:
    timestamp: datetime
    source: str
    category: str
    severity: str
    raw: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    parsed: dict = field(default_factory=dict)


class BaseParser:
    def parse(self, raw_line: str) -> Optional[NormalizedEvent]:
        raise NotImplementedError


class PAMParser(BaseParser):
    
    FAILED_PASSWORD = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
        r'Failed password for (?:invalid user )?(?P<username>\S+) '
        r'from (?P<ip>\S+) port'
    )
    
    ACCEPTED_PASSWORD = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
        r'Accepted password for (?P<username>\S+) '
        r'from (?P<ip>\S+) port'
    )

    SUDO = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
        r'sudo:.*USER=(?P<username>\S+).*COMMAND=(?P<command>.+)'
    )

    def _parse_timestamp(self, month, day, time):
        year = datetime.now().year
        return datetime.strptime(
            f"{year} {month} {day} {time}", "%Y %b %d %H:%M:%S"
        )

    def parse(self, raw_line: str) -> Optional[NormalizedEvent]:

        match = self.FAILED_PASSWORD.search(raw_line)
        if match:
            return NormalizedEvent(
                timestamp=self._parse_timestamp(
                    match.group('month'),
                    match.group('day'),
                    match.group('time')
                ),
                source='pam',
                category='auth_failure',
                severity='warning',
                source_ip=match.group('ip'),
                username=match.group('username'),
                outcome='failure',
                raw=raw_line.strip(),
                parsed={'mechanism': 'ssh'}
            )

        match = self.ACCEPTED_PASSWORD.search(raw_line)
        if match:
            return NormalizedEvent(
                timestamp=self._parse_timestamp(
                    match.group('month'),
                    match.group('day'),
                    match.group('time')
                ),
                source='pam',
                category='auth_success',
                severity='info',
                source_ip=match.group('ip'),
                username=match.group('username'),
                outcome='success',
                raw=raw_line.strip(),
                parsed={'mechanism': 'ssh'}
            )

        match = self.SUDO.search(raw_line)
        if match:
            return NormalizedEvent(
                timestamp=self._parse_timestamp(
                    match.group('month'),
                    match.group('day'),
                    match.group('time')
                ),
                source='pam',
                category='auth_success',
                severity='info',
                username=match.group('username'),
                action=match.group('command').strip(),
                outcome='success',
                raw=raw_line.strip(),
                parsed={'mechanism': 'sudo'}
            )

        return None


class NginxParser(BaseParser):

    LOG_PATTERN = re.compile(
        r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" '
        r'(?P<status>\d+) (?P<bytes>\d+)'
    )

    SENSITIVE_PATHS = ['/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config']

    def _severity(self, status: int, path: str) -> str:
        if any(path.startswith(p) for p in self.SENSITIVE_PATHS):
            return 'warning'
        if status >= 500:
            return 'warning'
        return 'info'

    def _category(self, status: int) -> str:
        if status >= 400:
            return 'error'
        return 'access'

    def parse(self, raw_line: str) -> Optional[NormalizedEvent]:
        match = self.LOG_PATTERN.search(raw_line)
        if not match:
            return None

        status = int(match.group('status'))
        path = match.group('path')
        ip = match.group('ip')

        timestamp = datetime.strptime(
            match.group('time'), "%d/%b/%Y:%H:%M:%S %z"
        ).replace(tzinfo=None)

        return NormalizedEvent(
            timestamp=timestamp,
            source='nginx',
            category=self._category(status),
            severity=self._severity(status, path),
            source_ip=ip if ip != '-' else None,
            action=f"{match.group('method')} {path}",
            outcome='success' if status < 400 else 'failure',
            raw=raw_line.strip(),
            parsed={
                'status_code': status,
                'bytes': int(match.group('bytes')),
                'method': match.group('method'),
                'path': path,
            }
        )
