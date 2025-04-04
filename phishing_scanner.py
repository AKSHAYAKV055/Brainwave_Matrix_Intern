import re
import requests
from urllib.parse import urlparse

# Common suspicious keywords and domain tricks
suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking']
suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']

def is_suspicious_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    reasons = []

    # Check for shortened URL
    if domain in shorteners:
        reasons.append("URL shortening service used")

    # Check for suspicious keywords
    for keyword in suspicious_keywords:
        if keyword in path or keyword in domain:
            reasons.append(f"Suspicious keyword found: {keyword}")
    
    # Check for uncommon or suspicious TLDs
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            reasons.append(f"Suspicious TLD used: {tld}")
    
    # Check for excessive dots (subdomain tricking)
    if domain.count('.') > 2:
        reasons.append("Too many subdomains (potential obfuscation)")

    return reasons

def check_url_status(url):
    try:
        response = requests.get(url, timeout=5)
        return f"URL responded with status code: {response.status_code}"
    except requests.exceptions.RequestException:
        return "Failed to connect to the URL"

def main():
    url = input("Enter the URL to scan: ").strip()
    print("\n[+] Scanning URL:", url)

    reasons = is_suspicious_url(url)
    if reasons:
        print("\n[!] Warning: This URL may be suspicious due to the following reasons:")
        for reason in reasons:
            print("   -", reason)
    else:
        print("\n[+] No obvious phishing indicators found in the URL.")

    print("\n[+] Performing live check...")
    status = check_url_status(url)
    print("   -", status)

if __name__ == "__main__":
    main()
