import time
import requests
import os
import sys
import platform
import subprocess
import threading

if platform.system() != 'Linux':
    print("[!] This agent can only run on Linux.")
    sys.exit(1)

API_URL = "http://127.0.0.1:8000/api/ingest/"
NGINX_LOG = "/var/log/nginx/access.log"
POLL_INTERVAL = 1


def send_line(source, line):
    try:
        response = requests.post(API_URL, json={
            'source': source,
            'line': line
        }, timeout=5)
        if response.status_code == 201:
            print(f"[+] {source}: {line[:80]}")
        elif response.status_code == 204:
            pass
        else:
            print(f"[!] Unexpected {response.status_code}: {line[:80]}")
    except requests.exceptions.ConnectionError:
        print("[!] Could not connect to API. Is Django running?")
    except Exception as e:
        print(f"[!] Error: {e}")


def tail_file(filepath, source):
    print(f"[*] Watching file: {filepath}")
    with open(filepath, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                send_line(source, line.strip())
            else:
                time.sleep(POLL_INTERVAL)


def tail_journal(source):
    print(f"[*] Watching journald for: {source}")
    process = subprocess.Popen(
        ['journalctl', '-u', 'ssh', '-f', '-o', 'short', '-n', '0'],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    for line in process.stdout:
        line = line.strip()
        if line:
            send_line('pam', line)


def run():
    print(f"[*] Starting Linux agent")
    print(f"[*] Posting to: {API_URL}")

    threads = []

    journal_thread = threading.Thread(
        target=tail_journal,
        args=('pam',),
        daemon=True
    )
    threads.append(journal_thread)

    if os.path.exists(NGINX_LOG):
        nginx_thread = threading.Thread(
            target=tail_file,
            args=(NGINX_LOG, 'nginx'),
            daemon=True
        )
        threads.append(nginx_thread)
    else:
        print(f"[!] Nginx log not found at {NGINX_LOG}, skipping")

    for t in threads:
        t.start()

    print(f"[*] Agent running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")


if __name__ == '__main__':
    run()
