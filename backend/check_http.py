import requests

url = "http://testphp.vulnweb.com/"
print(f"Checking {url}...")

try:
    r = requests.get(url, allow_redirects=False, timeout=10)
    print(f"Status: {r.status_code}")
    print(f"HSTS: {r.headers.get('strict-transport-security', 'MISSING')}")
    print(f"X-Content-Type-Options: {r.headers.get('x-content-type-options', 'MISSING')}")
    print(f"X-Frame-Options: {r.headers.get('x-frame-options', 'MISSING')}")
    print(f"CSP: {r.headers.get('content-security-policy', 'MISSING')}")
    
    # Check for cookies
    cookies = r.headers.get('set-cookie', 'NONE')
    print(f"Cookies: {cookies[:100] if cookies != 'NONE' else 'NONE'}...")
except Exception as e:
    print(f"Error: {e}")
