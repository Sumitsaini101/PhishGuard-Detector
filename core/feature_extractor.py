import re
from urllib.parse import urlparse

def extract_features(url):
    """
    Extracts 9 advanced numerical features from a URL for ML analysis.
    Includes fail-safes for malformed/dirty data.
    """
    try:
        # 1. Force the input to be a string (handles Pandas NaN/null values)
        url = str(url).strip()
        
        # 2. Ensure URL has a scheme for the parser
        if not url.startswith('http'):
            url = 'http://' + url

        # 3. Safely parse the URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            scheme = parsed.scheme
        except Exception:
            # Fallback if the URL is completely mangled (e.g., Invalid IPv6)
            domain = ""
            scheme = ""

        # Feature 1: Total URL Length
        url_length = len(url)
        
        # Feature 2: Domain Length
        domain_length = len(domain)
        
        # Feature 3: Total Dots 
        dot_count = url.count('.')
        
        # Feature 4: Hyphens in Domain
        hyphen_count = domain.count('-')
        
        # Feature 5: Presence of @ Symbol 
        at_symbol = 1 if '@' in url else 0
        
        # Feature 6: Raw IP Address Detection
        # Check the domain if it exists, otherwise check the whole URL
        ip_presence = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain if domain else url) else 0
        
        # Feature 7: Suspicious Keywords
        keywords = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'support', 'free']
        keyword_count = sum(1 for word in keywords if word in url.lower())
        
        # Feature 8: HTTPS Status 
        https_status = 1 if scheme == 'https' else 0
        
        # Feature 9: Subdomain Count 
        subdomain_count = max(0, domain.count('.') - 1) if domain else 0

        return [
            url_length, 
            domain_length, 
            dot_count, 
            hyphen_count, 
            at_symbol, 
            ip_presence, 
            keyword_count, 
            https_status, 
            subdomain_count
        ]
        
    except Exception:
        # Absolute worst-case scenario: return safe defaults so the script doesn't crash
        return [0, 0, 0, 0, 0, 0, 0, 0, 0]

# --- Quick Test ---
if __name__ == "__main__":
    # Testing with a deliberately broken URL
    test_url = "http://[invalid-ipv6-bracket-test/login"
    print(f"Extracting features for: {test_url}")
    print(f"Features array: {extract_features(test_url)}")