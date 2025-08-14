"""
Basic Vulnerability Scanner with Shodan Integration
- Checks HTTP Security Headers
- Extracts SSL/TLS Certificate Info
- Displays Server Banner
- Fetches open ports, services & vulnerabilities from Shodan
"""

import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

# === INSERT YOUR SHODAN API KEY HERE ===
SHODAN_API_KEY = "SHODAN_API_KEY"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def check_headers(url):
    print("\n[+] Checking HTTP Security Headers...")
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers

        for header in SECURITY_HEADERS:
            if header in headers:
                print(f"[OK] {header}: {headers[header]}")
            else:
                print(f"[MISSING] {header}")
    except Exception as e:
        print(f"[ERROR] Could not fetch headers: {e}")

def check_ssl(domain):
    print("\n[+] Checking SSL/TLS Certificate...")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(f"[OK] Issuer: {cert['issuer']}")
            print(f"[OK] Valid From: {cert['notBefore']}")
            print(f"[OK] Valid Until: {cert['notAfter']}")
            
            expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.utcnow()).days
            print(f"[INFO] Days until expiry: {days_left}")
    except Exception as e:
        print(f"[ERROR] Could not retrieve SSL certificate: {e}")

def check_server_banner(url):
    print("\n[+] Checking Server Banner...")
    try:
        res = requests.head(url, timeout=5)
        server = res.headers.get("Server", "Not Found")
        print(f"[INFO] Server Banner: {server}")
    except Exception as e:
        print(f"[ERROR] Could not retrieve server banner: {e}")

def shodan_lookup(ip):
    print("\n[+] Shodan Lookup...")
    try:
        shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        r = requests.get(shodan_url, timeout=10)

        if r.status_code != 200:
            print(f"[ERROR] Shodan API request failed: {r.text}")
            return
        
        data = r.json()
        print(f"[INFO] IP: {data.get('ip_str', 'N/A')}")
        print(f"[INFO] Organization: {data.get('org', 'N/A')}")
        print(f"[INFO] Operating System: {data.get('os', 'N/A')}")

        print("\n[Open Ports]")
        for item in data.get('data', []):
            port = item.get('port')
            service = item.get('product', 'Unknown')
            print(f" - {port} ({service})")

        vulns = data.get('vulns', {})
        if vulns:
            print("\n[Vulnerabilities]")
            for vuln in vulns:
                print(f" - {vuln}")
        else:
            print("\n[INFO] No vulnerabilities found in Shodan database.")
    except Exception as e:
        print(f"[ERROR] Could not query Shodan: {e}")

if __name__ == "__main__":
    print("=== Basic Vulnerability Scanner with Shodan ===")
    target_url = input("Enter target URL (e.g., https://example.com): ").strip()

    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc

    check_headers(target_url)
    check_ssl(domain)
    check_server_banner(target_url)

    try:
        ip_addr = socket.gethostbyname(domain)
        shodan_lookup(ip_addr)
    except Exception as e:
        print(f"[ERROR] Could not resolve domain to IP: {e}")
