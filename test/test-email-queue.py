#!/usr/bin/env python3
"""Email Queue Firewall Test - Tests throttling queue"""
import argparse, base64, json, random, sys, threading, time, requests

TARGET = "http://localhost:2525"

RESULTS = {}
LOCK = threading.Lock()

def do_req(path, headers=None, body=None, actor="unknown"):
    url = f"{TARGET}{path}"
    hdrs = headers or {}
    hdrs.setdefault("Content-Type", "application/json")
    data = json.dumps(body).encode() if body else None
    req = requests.Request("POST", url, data=data, headers=hdrs)
    try:
        resp = requests.send(req.prepare(), timeout=10)
        status = resp.status_code
        try:
            data = resp.json()
        except:
            data = {}
    except Exception as e:
        print(f"ERROR: {e}")
        status = 0
        data = {}
    
    with LOCK:
        RESULTS[actor] = RESULTS.get(actor, {"blocked": 0, "throttled": 0, "sent": 0})
        r = RESULTS[actor]
        
        if status == 550:  # Blocked
            r["blocked"] = r.get("blocked", 0) + 1
        elif status == 429:  # Throttled/Queued
            r["throttled"] = r.get("throttled", 0) + 1
            print(f"  [{actor}] QUEUED (status {status})")
        else:
            r["sent"] = r.get("sent", 0) + 1
    
    return status, data

def smtp(user, pwd, to, subject, body, ip, actor):
    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    hdrs = {"Authorization": f"Basic {auth}", "From": user, "To": to, "Subject": subject, "X-Sender-IP": ip}
    return do_req("/api/submit", hdrs, {"to": to, "subject": subject, "body": body}, actor)

# Test 1: Normal user - should get sent
def test_normal(target, duration):
    print("[Normal] Normal user")
    start = time.time()
    while time.time() - start < duration:
        smtp("alice@example.com", "pass123", "bob@co.com", "Meeting", "Hi", "192.168.1.100", "normal")
        time.sleep(random.uniform(5, 15))

# Test 2: High volume - should get queued
def test_high_volume(target, duration):
    print("[HighVol] High volume (should be queued)")
    start = time.time()
    while time.time() - start < duration:
        smtp("evil@bad.com", "bad123", f"victim{random.randint(1,100)}@test.com", "Spam", "Click", "10.99.1.1", "high_volume")
        time.sleep(random.uniform(0.1, 0.3))

# Test 3: Burst - should get queued
def test_burst(target, duration):
    print("[Burst] Rapid burst (should be queued)")
    start = time.time()
    while time.time() - start < duration:
        smtp("burst@att.com", "att123", f"v{random.randint(1,50)}@t.com", "Msg", "Content", "10.10.10.10", "burst")
        time.sleep(0.05)  # Very fast

def main():
    print(f"\n{'='*60}")
    print("  EMAIL QUEUE FIREWALL TEST")
    print(f"  Target: {TARGET}")
    print(f"{'='*60}\n")
    
    # Check server
    try:
        r = requests.get(f"{TARGET}/health", timeout=5)
        print(f"Server OK: {r.json()}\n")
    except Exception as e:
        print(f"ERROR: {e}")
        print("Start server: node test_server/email_server.js")
        sys.exit(1)
    
    threads = [
        threading.Thread(target=test_normal, args=(TARGET, 20)),
        threading.Thread(target=test_high_volume, args=(TARGET, 20)),
        threading.Thread(target=test_burst, args=(TARGET, 10)),
    ]
    
    for t in threads: t.start()
    for t in threads: t.join()
    
    print(f"\n{'='*60}")
    print("  RESULTS")
    print(f"{'='*60}")
    
    for actor, r in RESULTS.items():
        total = r.get("blocked", 0) + r.get("throttled", 0) + r.get("sent", 0)
        print(f"{actor:<15} sent:{r.get('sent',0):>3} queued:{r.get('throttled',0):>3} blocked:{r.get('blocked',0):>3}")
    
    # Test unblock
    print(f"\n{'='*60}")
    print("  TESTING UNBLOCK + QUEUE RELEASE")
    print(f"{'='*60}")
    
    # Get queue status before
    r = requests.get(f"{TARGET}/admin/queue/evil@bad.com", timeout=5)
    print(f"Queue before unblock: {r.json().get('queued', [])}")
    
    # Unblock and release
    r = requests.post(f"{TARGET}/admin/unblock", json={"userId": "evil@bad.com", "releaseQueue": True}, timeout=5)
    print(f"Unblock response: {r.json()}")
    
    print(f"\n{'='*60}")
    print("  TEST COMPLETE")
    print(f"{'='*60}")

if __name__ == "__main__": main()