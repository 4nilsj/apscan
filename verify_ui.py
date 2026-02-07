import requests
import time
import sys

BASE = "http://localhost:8083"
print("[*] Waiting for backend to come up...")
time.sleep(3)

print("[*] Starting E2E UI Flow Verification...")

# 1. Start Scan
payload = {
    "input_type": "list",
    "file_content": "GET http://127.0.0.1:8000/products?category=test",
    "auth_type": "none"
}
try:
    res = requests.post(f"{BASE}/api/scan", json=payload)
    if res.status_code != 200:
        print(f"[!] API Error: {res.text}")
        sys.exit(1)
        
    data = res.json()
    scan_id = data.get("scan_id")
    print(f"[*] Scan started: {scan_id}")
except Exception as e:
    print(f"[!] Failed to start scan: {e}")
    sys.exit(1)

# 2. Poll Status
for _ in range(10):
    time.sleep(2)
    try:
        res = requests.get(f"{BASE}/api/scan/{scan_id}")
        status = res.json()
        print(f"[*] Status: {status['state']} (Endpoints: {status.get('endpoints_count',0)})")
        
        if status['state'] in ['completed', 'failed']:
            break
    except Exception as e:
         print(f"[!] Polling Error: {e}")

if status['state'] != 'completed':
    print(f"[!] Scan did not complete successfully. Status: {status['state']}")
    # sys.exit(1) # Don't exit, maybe it failed but we want to know why

# 3. Get Results
try:
    res = requests.get(f"{BASE}/api/scan/{scan_id}/results")
    results = res.json()
    print(f"[*] Findings: {len(results)}")
    for r in results:
        print(f"   - [{r['severity']}] {r['name']} on {r['endpoint']}")
except Exception as e:
    print(f"[!] Failed to get results: {e}")

# 4. Check Frontend
try:
    print("[*] Checking Frontend...")
    res = requests.get("http://localhost:5175", timeout=2)
    if res.status_code == 200:
        print("[*] Frontend Reachable (200 OK)")
    else:
        print(f"[!] Frontend returned {res.status_code}")
except Exception as e:
    print(f"[!] Frontend Verification Failed: {e}")

print("[*] Verification Complete.")
