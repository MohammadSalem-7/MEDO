import os
import subprocess
import platform
import ipaddress
import threading
from datetime import datetime

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def save_results(filename, content):
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(content)
    print(f"\n💾 Results saved to: {filename}")

# Section 1: Scan nearby Wi-Fi networks
def scan_wifi():
    print("🔍 Scanning nearby Wi-Fi networks...\n")
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True, text=True)
        else:
            result = subprocess.check_output(["nmcli", "-f", "SSID,SIGNAL,BARS,SECURITY", "dev", "wifi"], text=True)
        
        print(result)
        save_results("wifi_results.txt", result)

    except Exception as e:
        print(f"⚠️ Error while scanning Wi-Fi: {e}")

# Section 2: Scan devices on local network using ping
def ping_ip(ip, active_ips):
    cmd = f"ping -{'n' if platform.system() == 'Windows' else 'c'} 1 -w 500 {ip}"
    result = os.system(f"{cmd} > nul 2>&1" if platform.system() == "Windows" else f"{cmd} > /dev/null 2>&1")
    if result == 0:
        active_ips.append(ip)

def scan_devices():
    print("🔍 Scanning active devices on your network...\n")
    subnet_input = input("🌐 Enter subnet (e.g., 192.168.1.0/24): ")

    try:
        network = ipaddress.IPv4Network(subnet_input, strict=False)
    except ValueError:
        print("❌ Invalid subnet format.")
        return

    active_ips = []
    threads = []

    print("🔄 Scanning in progress, please wait...")

    for ip in network.hosts():
        t = threading.Thread(target=ping_ip, args=(str(ip), active_ips))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    result_text = f"📅 Scan Time: {datetime.now()}\n\n📶 Active Devices ({len(active_ips)} found):\n"
    result_text += "\n".join(f"- {ip}" for ip in active_ips)

    print(result_text)
    save_results("device_results.txt", result_text)

# Main menu
def main():
    while True:
        clear()
        print("🛠️  M E D O - Network Scanner")
        print("=" * 35)
        print("1️⃣  Scan nearby Wi-Fi networks")
        print("2️⃣  Scan devices on your network")
        print("3️⃣  Exit")
        choice = input("\n📥 Select an option: ")

        if choice == '1':
            scan_wifi()
        elif choice == '2':
            scan_devices()
        elif choice == '3':
            print("👋 Exiting... Stay safe!")
            break
        else:
            print("❌ Invalid choice!")

        input("\n🔁 Press Enter to return to the main menu...")

if __name__ == "__main__":
    main()
