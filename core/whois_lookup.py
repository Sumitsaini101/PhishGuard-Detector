import whois

def get_domain_intel(domain):
    """
    Performs a WHOIS lookup to return registration metadata.
    """
    try:
        # Query the WHOIS database
        w = whois.whois(domain)
        
        # Format the data into a readable dictionary
        intel = {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "whois_server": w.whois_server
        }
        
        # Handle lists (sometimes WHOIS returns a list for dates)
        if isinstance(intel["creation_date"], list):
            intel["creation_date"] = intel["creation_date"][0]
            
        return True, intel
    
    except Exception as e:
        return False, str(e)

# ==========================================
# QUICK TEST
# ==========================================
if __name__ == "__main__":
    domain = input("Enter domain to investigate (e.g., google.com): ").strip()
    success, data = get_domain_intel(domain)
    
    if success:
        print(f"\n--- OSINT REPORT: {domain} ---")
        for key, value in data.items():
            print(f"{key.upper()}: {value}")
    else:
        print(f"[-] Error: {data}")