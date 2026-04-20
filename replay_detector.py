import re

ip_counts = {}
alerted_ips = set()

with open("sample_logs.txt", "r") as f:
    for line in f:
        if "Failed password" in line:
            print("[!] Failed login detected")

            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)

                ip_counts[ip] = ip_counts.get(ip, 0) + 1
                print(f"[INFO] {ip} attempt #{ip_counts[ip]}")

                if ip_counts[ip] >= 3 and ip not in alerted_ips:
                    print(f"[ALERT] Possible brute force detected from {ip}")
                    alerted_ips.add(ip)
