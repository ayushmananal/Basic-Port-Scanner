"""
Fast Subdomain Scanner (Threaded)
- Finds active subdomains quickly using multithreading
- Requires: pip install requests
"""

import requests
import concurrent.futures

def check_subdomain(sub, domain):
    url = f"http://{sub}.{domain}"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code < 400:
            return url
    except requests.RequestException:
        return None

def scan_subdomains(domain, subdomains):
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_subdomain, sub, domain): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(f"[+] Found: {result}")
                found.append(result)
    return found

if __name__ == "__main__":
    print("=== Fast Subdomain Scanner ===")
    target_domain = input("Enter target domain (e.g., example.com): ").strip()

    subdomains_list = [
        "www", "mail", "ftp", "test", "dev", "portal", "api",
        "staging", "shop", "blog", "news", "admin", "secure",
        "cdn", "static", "images", "beta", "cloud", "forum"
    ]

    results = scan_subdomains(target_domain, subdomains_list)

    print("\n--- Active Subdomains ---")
    for sub in results:
        print(sub)
