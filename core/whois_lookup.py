import whois
from urllib.parse import urlparse

def get_domain_intel(domain_input):
    """
    Fetches WHOIS data for a given domain.
    Includes auto-cleanup so if a user pastes 'https://google.com/login',
    it automatically strips it down to just 'google.com'.
    """
    try:
        # 1. Clean up the input (Remove https://, www, and paths)
        domain_input = domain_input.strip()
        if "http" in domain_input:
            parsed = urlparse(domain_input)
            clean_domain = parsed.netloc
        else:
            clean_domain = domain_input
            
        # Strip 'www.' if it exists, as WHOIS prefers the root domain
        if clean_domain.startswith("www."):
            clean_domain = clean_domain[4:]

        # 2. Fetch the data
        w = whois.whois(clean_domain)
        
        # 3. Handle cases where the domain isn't registered
        if w.domain_name is None:
            return False, "Domain not found or not registered."
            
        # 4. Format the output safely
        data = {
            "creation_date": w.creation_date[0] if type(w.creation_date) == list else w.creation_date,
            "registrar": w.registrar
        }
        
        return True, data
        
    except Exception as e:
        return False, str(e)

# Quick Test
if __name__ == "__main__":
    success, data = get_domain_intel("https://www.github.com/login")
    if success:
        print(f"Success! Created: {data['creation_date']}, Registrar: {data['registrar']}")
    else:
        print(f"Failed: {data}")