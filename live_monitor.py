import subprocess
import re

print("Monitoring SSH logs in real-time...\n")

process = subprocess.Popen(
    ["journalctl", "-u", "ssh", "-f", "--no-pager"],
    stdout=subprocess.PIPE,
    text=True
)

ip_counts = {}
alerted_ips = set()

for line in process.stdout:
    if "Failed password" in line:
        print("[!] Failed login detected")

        match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)

            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            print(f"[INFO] {ip} attempt #{ip_counts[ip]}")

            if ip_counts[ip] >= 3 and ip not in alerted_ips:
                 print(f"[ALERT] LIVE brute force detected from {ip}\n")
                 print(f"[ACTION] Blocking {ip}")
                 subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
                 alerted_ips.add(ip)
