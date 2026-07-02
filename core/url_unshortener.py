import requests
import sys

def unroll_url(short_url):
    """
    Safely follows redirects of a shortened URL to find its true destination.
    Uses browser spoofing and Session persistence to bypass advanced bot-detection.
    """
    if not short_url.startswith('http'):
        short_url = 'http://' + short_url

    print(f"\n[+] Intercepting and unrolling: {short_url}")
    
    # 1. Advanced Disguise Headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }
    
    try:
        # 2. The Session Object (Mimics a persistent browser tab)
        session = requests.Session()
        
        # 3. Execute the request
        response = session.get(short_url, headers=headers, allow_redirects=True, timeout=10)
        
        # 4. DIAGNOSTIC RADAR: See exactly what the server thinks of us
        print(f"[*] Diagnostic: Server responded with HTTP {response.status_code}")
        
        # Catch common error codes before evaluating redirects
        if response.status_code == 404:
            return False, "BROKEN LINK: This short-link does not exist or has been deleted (HTTP 404)."
        elif response.status_code in [403, 429]:
            return False, "FIREWALL BLOCK: The server recognized the script and refused to route it."
        elif response.status_code >= 400:
            return False, f"SERVER ERROR: The server returned an error code (HTTP {response.status_code})."
            
        final_url = response.url
        
        if final_url != short_url:
            return True, final_url
        else:
            return False, final_url
    except requests.exceptions.RequestException as e:
        return False, f"CONNECTION ERROR: {str(e)}"
# ==========================================
# QUICK TEST RUNNER
# ==========================================
if __name__ == "__main__":
    print("Initializing PhishGuard Link Interceptor...\n")
    
    target_link = input("Enter a short-link to investigate (e.g., bit.ly/3JQ...): ").strip()
    
    if not target_link:
        print("[-] No URL provided. Exiting.")
        sys.exit()
        
    is_redirected, final_destination = unroll_url(target_link)
    
    if is_redirected:
        print("\n🚨 REDIRECT DETECTED!")
        print(f"--> True Destination: {final_destination}")
    elif "BLOCK" in final_destination or "ERROR" in final_destination:
        print(f"\n[-] {final_destination}")
    else:
        print("\n✅ NO REDIRECT DETECTED.")
        print("--> The URL goes exactly where it says it goes.")