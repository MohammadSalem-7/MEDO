import os
import ipaddress
import threading
from datetime import datetime

# ANSI Colors
BLUE = "\033[94m"
GREEN = "\033[92m"
WHITE = "\033[97m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Save results
def save_results(filename, content):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

# Ping function
def ping_ip(ip, active_ips):
    cmd = f"ping -c 1 -W 1 {ip} > /dev/null 2>&1"
    if os.system(cmd) == 0:
        active_ips.append(ip)

# Network scanner
def scan_network(subnet):
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        print(f"{CYAN}❌ Invalid subnet format.{RESET}")
        return

    active_ips = []
    threads = []

    print(f"\n{BLUE}🔍 Scanning network: {subnet}{RESET}")
    for ip in network.hosts():
        t = threading.Thread(target=ping_ip, args=(str(ip), active_ips))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    result = f"📅 Scan Time: {datetime.now()}\n"
    result += f"📶 Active Devices ({len(active_ips)} found):\n"
    result += "\n".join(f"- {ip}" for ip in active_ips)

    print(f"\n{GREEN}{result}{RESET}")
    save_results("termux_scan_results.txt", result)
    print(f"\n{WHITE}✅ Results saved to 'termux_scan_results.txt'{RESET}")

# Main
def main():
    print(f"{BLUE}🛠️  M E D O - Termux Network Scanner{RESET}")
    print(f"{WHITE}" + "=" * 45 + f"{RESET}")
    subnet = input(f"{CYAN}🌐 Enter subnet (e.g., 192.168.1.0/24): {RESET}")
    scan_network(subnet)

if __name__ == "__main__":
    main()
