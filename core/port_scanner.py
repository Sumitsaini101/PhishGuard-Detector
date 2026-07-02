import socket
import concurrent.futures

def scan_single_port(ip, port):
    """
    Attempts to connect to a specific port on the target IP.
    Returns the port number and True if open, False if closed.
    """
    try:
        # Create a network socket (AF_INET = IPv4, SOCK_STREAM = TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a very short timeout (0.5 seconds). 
        # If the door doesn't open immediately, we move on.
        s.settimeout(0.5) 
        
        # connect_ex returns 0 if the connection was successful (port is open)
        result = s.connect_ex((ip, port))
        s.close()
        
        if result == 0:
            return port, True
        return port, False
    except Exception:
        return port, False

def scan_target(target_ip):
    """
    Scans a curated list of notoriously vulnerable and common ports.
    Uses multithreading to scan them simultaneously for speed.
    """
    # A dictionary mapping port numbers to the services that normally run on them
    target_ports = {
        21: "FTP (File Transfer - Often unencrypted)",
        22: "SSH (Secure Shell - Remote Login)",
        23: "Telnet (Insecure Remote Login - DANGER)",
        25: "SMTP (Email Routing)",
        53: "DNS (Domain Name System)",
        80: "HTTP (Web Traffic - Unencrypted)",
        110: "POP3 (Email Retrieval - Unencrypted)", 
        443: "HTTPS (Secure Web Traffic)",
        445: "SMB (Windows File Sharing - Ransomware Vector)",
        3306: "MySQL (Database - Data Leak Vector)",
        3389: "RDP (Remote Desktop - Hacker favorite)",
        5432: "PostgreSQL (Database - Data Leak Vector)",
        5900: "VNC (Virtual Network Computing - Remote Screen Access)",
        6379: "Redis (In-memory Data Structure Store)",
        27017: "MongoDB (NoSQL Database - Ransomware Target)"
    }
    
    print(f"\n[+] Initiating Port Scan on Target: {target_ip}")
    print("[+] Firing up multithreading engine...\n")
    
    open_ports = []
    
    # Use a ThreadPool to send out 10 simultaneous connection attempts
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        # Map out the tasks
        future_to_port = {executor.submit(scan_single_port, target_ip, port): port for port in target_ports.keys()}
        
        # Process them as they finish
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append({
                    "port": port,
                    "service": target_ports[port]
                })
                
    return open_ports

# ==========================================
# QUICK TEST RUNNER
# ==========================================
if __name__ == "__main__":
    import sys # Need this to exit gracefully if they type a bad IP
    
    print("Initializing PhishGuard Vulnerability Scanner...\n")
    
    # 1. Ask the user for input
    raw_target = input("Enter an IP address or domain to scan (e.g., 8.8.8.8 or google.com): ").strip()
    
    # 2. Translate domains to IPs (if they typed 'google.com', this finds its actual IP)
    try:
        target_ip = socket.gethostbyname(raw_target)
    except socket.gaierror:
        print(f"\n[-] ERROR: Could not resolve '{raw_target}'. Please check the spelling.")
        sys.exit()
        
    if raw_target != target_ip:
        print(f"[*] Resolved '{raw_target}' to IP: {target_ip}")
        
    # 3. Run the deep scan
    results = scan_target(target_ip)
    
    # 4. Print the final report
    if len(results) == 0:
        print(f"\n[-] Target {target_ip} is secure. No exposed database or system ports found.")
    else:
        print("\n--- OPEN PORTS DETECTED ---")
        for data in results:
            print(f"⚠️ Port {data['port']} is OPEN -> {data['service']}")