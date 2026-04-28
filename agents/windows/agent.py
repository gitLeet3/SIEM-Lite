import time
import requests
import sys
import json
from datetime import datetime

API_URL = "http://192.168.88.128:8000/api/ingest/"
POLL_INTERVAL = 5

RELEVANT_EVENT_IDS = {
    4625: 'auth_failure',
    4624: 'auth_success',
    4672: 'auth_success',
    4648: 'auth_success',
    4719: 'error',
    4964: 'error',
}

try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import win32con
    import winerror
    import pywintypes
except ImportError:
    print("[!] pywin32 is not installed.")
    print("[!] Run: pip install pywin32")
    sys.exit(1)


def format_event(event, log_type):
    event_id = event.EventID & 0xFFFF
    category = RELEVANT_EVENT_IDS.get(event_id)

    if not category:
        return None

    try:
        strings = event.StringInserts or []
    except Exception:
        strings = []

    timestamp = datetime.strptime(
        str(event.TimeGenerated), "%Y-%m-%d %H:%M:%S"
    )

    username = None
    source_ip = None
    action = None

    if event_id == 4625:
        username = strings[5] if len(strings) > 5 else None
        source_ip = strings[19] if len(strings) > 19 else None
        action = 'logon_failure'

    elif event_id == 4624:
        username = strings[5] if len(strings) > 5 else None
        source_ip = strings[18] if len(strings) > 18 else None
        action = 'logon_success'

    elif event_id == 4672:
        username = strings[1] if len(strings) > 1 else None
        action = 'privilege_assigned'

    raw = (
        f"EventID={event_id} "
        f"Source={event.SourceName} "
        f"Time={timestamp} "
        f"User={username} "
        f"IP={source_ip}"
    )

    return {
        'timestamp': timestamp.isoformat(),
        'event_id': event_id,
        'category': category,
        'username': username,
        'source_ip': source_ip,
        'action': action,
        'raw': raw,
        'log_type': log_type,
    }


def send_event(formatted):
    raw_line = json.dumps(formatted)
    try:
        response = requests.post(API_URL, json={
            'source': 'windows',
            'line': raw_line
        }, timeout=5)
        if response.status_code == 201:
            print(f"[+] Ingested EventID={formatted['event_id']} user={formatted['username']} ip={formatted['source_ip']}")
        elif response.status_code == 204:
            pass
        else:
            print(f"[!] Unexpected response {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("[!] Could not connect to API. Is Django running?")
    except Exception as e:
        print(f"[!] Error: {e}")


def watch_log(log_name):
    print(f"[*] Watching Windows Event Log: {log_name}")
    hand = win32evtlog.OpenEventLog(None, log_name)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    win32evtlog.ReadEventLog(hand, flags, 0)

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                event_id = event.EventID & 0xFFFF
                if event_id in RELEVANT_EVENT_IDS:
                    formatted = format_event(event, log_name)
                    if formatted:
                        send_event(formatted)
        else:
            time.sleep(POLL_INTERVAL)


def run():
    print(f"[*] Starting Windows agent")
    print(f"[*] Posting to: {API_URL}")

    watch_log('Security')


if __name__ == '__main__':
    run()
