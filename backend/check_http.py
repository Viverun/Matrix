import requests

url = "http://codersclub.apsit.edu.in/"
print(f"Checking {url}...")

try:
    r = requests.get(url, allow_redirects=False, timeout=10)
    print(f"Status: {r.status_code}")
    if 'location' in r.headers:
        print(f"Redirects to: {r.headers['location']}")
    else:
        print("No redirect - HTTP accessible!")
    print(f"HSTS: {r.headers.get('strict-transport-security', 'NONE')}")
except Exception as e:
    print(f"Error: {e}")
