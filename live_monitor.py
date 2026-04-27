import subprocess
import re
import datetime

print("Monitoring SSH logs in real-time...\n")

process = subprocess.Popen(
    ["journalctl", "-u", "ssh", "-f", "--no-pager"],
    stdout=subprocess.PIPE,
    text=True
)

ip_counts = {}
alerted_ips = set()
blocked_ips = set()

def write_alert(message):
    with open("alerts.log", "a") as f:
        f.write(message + "\n")

try:
    with open("blocked_ips.txt", "r") as f:
        for line in f:
            blocked_ips.add(line.strip())
except FileNotFoundError:
    pass

for line in process.stdout:
    if "Failed password" in line:
        print("[!] Failed login detected")

        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)

            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            print(f"[{timestamp}] [INFO] {ip} attempt #{ip_counts[ip]}")

            if ip_counts[ip] >= 3:
                if ip_counts[ip] == 3:
                    alert = f"[{timestamp}] [MEDIUM] Suspicious activity from {ip}"
                    print(alert)
                    write_alert(alert)

                elif ip_counts[ip] == 4:
                    alert = f"[{timestamp}] [HIGH] Brute force likely from {ip}"
                    print(alert)
                    write_alert(alert)

                elif ip_counts[ip] >= 5:
                    alert = f"[{timestamp}] [CRITICAL] Active attack from {ip} ({ip_counts[ip]} attempts)"
                    print(alert)
                    write_alert(alert)

                if ip not in alerted_ips:
                    alerted_ips.add(ip)

                if ip not in blocked_ips:
                    action = f"[{timestamp}] [ACTION] Blocking {ip} (simulated)"
                    print(action)
                    write_alert(action)

                    with open("blocked_ips.txt", "a") as f:
                        f.write(ip + "\n")

                    blocked_ips.add(ip)
