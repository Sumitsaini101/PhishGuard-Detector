from scapy.all import ARP, Ether, srp
import socket

def get_local_ip():
    """ 
    A quick trick to automatically find your computer's IP address 
    so we know which subnet to scan.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually connect, just routes the packet to figure out the local IP
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def scan_network(ip_range=None):
    """
    Sends an ARP broadcast to discover all active devices on the local network.
    """
    if ip_range is None:
        # Auto-detect the subnet (e.g., turns 192.168.1.45 into 192.168.1.0/24)
        local_ip = get_local_ip()
        ip_range = local_ip.rsplit('.', 1)[0] + '.0/24'
        
    print(f"Broadcasting ARP Request to subnet: {ip_range}...")
    
    # 1. Create the ARP request packet
    arp_request = ARP(pdst=ip_range)
    
    # 2. Create the Ethernet broadcast packet (ff:ff:ff:ff:ff:ff hits every router port)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # 3. Stack them together into a single frame
    arp_request_broadcast = broadcast/arp_request
    
    # 4. Send the packet and capture the responses (srp = Send/Receive Packets)
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for sent, received in answered_list:
        # psrc = IP Address, hwsrc = Hardware (MAC) Address
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        
    return devices

# ==========================================
# QUICK TEST RUNNER
# ==========================================
if __name__ == "__main__":
    print("Initializing PhishGuard Network Scanner...\n")
    try:
        found_devices = scan_network()
        
        print("\n--- DEVICES FOUND ON YOUR NETWORK ---")
        print("IP Address\t\tMAC Address")
        print("-----------------------------------------")
        for device in found_devices:
            print(f"{device['ip']}\t\t{device['mac']}")
            
    except PermissionError:
        print("CRITICAL ERROR: Packet sniffing requires Administrator privileges!")
        print("Please run VS Code as Administrator and try again.")