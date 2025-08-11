"""
WHOIS Lookup Tool
- Retrieve domain registration details
- For reconnaissance and security assessments
- Requires: pip install python-whois
"""

import whois

def lookup_domain(domain):
    #Perform a WHOIS lookup for the given domain.
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    print("=== WHOIS Lookup Tool ===")
    domain = input("Enter domain name (e.g., example.com): ").strip()

    result = lookup_domain(domain)
    print("\n--- WHOIS Information ---")
    print(result)
