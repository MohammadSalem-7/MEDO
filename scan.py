import wifi
from wifi import Cell
import time
from scapy.all import ARP, Ether, srp
import socket
import netifaces

def scan_wifi_networks():
    print("Scanning for nearby Wi-Fi networks...")
    try:
        networks = Cell.all('wlan0')  # 'wlan0' is the typical Wi-Fi interface on Android
        if not networks:
            print("No Wi-Fi networks found. Ensure Wi-Fi is enabled.")
            return
        
        for network in networks:
            ssid = network.ssid if network.ssid else "Hidden SSID"
            signal = network.signal
            encryption = network.encryption_type if network.encryption_type else "Open"
            print(f"Network: {ssid}")
            print(f"Signal Strength: {signal} dBm")
            print(f"Encryption: {encryption}")
            if encryption == "Open":
                print(f"Warning: {ssid} is an open network (no encryption)!")
            elif "WPA" not in encryption.upper():
                print(f"Note: {ssid} uses weak encryption ({encryption}).")
            print("-" * 40)
        
        print(f"Total networks found: {len(networks)}")
    
    except Exception as e:
        print(f"Error occurred while scanning Wi-Fi: {str(e)}")
        print("Ensure Wi-Fi is enabled and you have the necessary permissions.")

def get_local_ip():
    try:
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if 'wlan0' in iface:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
        return None
    except Exception:
        return None

def scan_connected_devices():
    print("\nScanning for devices on the same network...")
    try:
        # Get local IP and network interface
        local_ip = get_local_ip()
        if not local_ip:
            print("Could not determine local IP. Ensure you're connected to a Wi-Fi network.")
            return
        
        # Assume the network is a typical /24 subnet
        ip_range = ".".join(local_ip.split(".")[:-1]) + ".0/24"
        
        # Create ARP request packet
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Send packet and receive responses
        result = srp(packet, timeout=3, verbose=0)[0]
        
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        if not devices:
            print("No devices found on the network.")
            return
        
        # Display device information
        print(f"Found {len(devices)} devices on the network:")
        for device in devices:
            try:
                hostname = socket.gethostbyaddr(device['ip'])[0]
            except socket.herror:
                hostname = "Unknown"
            print(f"IP: {device['ip']}")
            print(f"MAC: {device['mac']}")
            print(f"Hostname: {hostname}")
            print("-" * 40)
    
    except Exception as e:
        print(f"Error occurred while scanning devices: {str(e)}")
        print("Ensure you have the necessary permissions and are connected to a network.")

if __name__ == "__main__":
    print("Starting Wi-Fi and Device Scanner...")
    scan_wifi_networks()
    print("\n" + "=" * 50 + "\n")
    scan_connected_devices()
    time.sleep(1)  # Short pause to ensure scans complete
