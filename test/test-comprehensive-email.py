#!/usr/bin/env python3
"""Comprehensive Email Firewall Test"""
import argparse, base64, json, random, sys, threading, time
from urllib import request, error

TARGET = "http://localhost:2526"
RESULTS = {k: {"blocked": 0, "allowed": 0} for k in [
    "normal_users", "mobile_users", "new_employees", "trusted_users",
    "spammers", "new_ip_flood", "mass_bcc", "credential_stuffers"
]}
LOCK = threading.Lock()

def do_req(target, path, headers=None, body=None, actor="unknown"):
    url = f"{target}{path}"
    hdrs = headers or {}
    hdrs.setdefault("Content-Type", "application/json")
    data = json.dumps(body).encode() if body else None
    req = request.Request(url, data=data, headers=hdrs, method="POST")
    status = 0
    try:
        resp = request.urlopen(req, timeout=15)
        status = resp.status
        resp.read()
    except error.HTTPError as e:
        status = e.code
        try: 
            e.read()
        except: 
            pass
    except Exception:
        status = 0
    with LOCK:
        RESULTS["total"] = RESULTS.get("total", 0) + 1
        if actor not in RESULTS: RESULTS[actor] = {"blocked": 0, "allowed": 0}
        r = RESULTS[actor]
        r["sent"] = r.get("sent", 0) + 1
        if status == 550 or status == 403:
            RESULTS[actor]["blocked"] += 1
            print(f"  [{actor}] BLOCKED status={status}")
        else:
            RESULTS[actor]["allowed"] += 1
    return status

def smtp_send(target, user, password, to, subject, body, ip, bcc="", actor="unknown"):
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    hdrs = {"Authorization": f"Basic {auth}", "From": user, "To": to, 
            "Subject": subject, "X-Sender-IP": ip}
    if bcc: hdrs["Bcc"] = bcc
    return do_req(target, "/api/submit", hdrs, {"to": to, "subject": subject, "body": body}, actor)

def gen_recipients(count, domain="example.com"):
    return ",".join([f"user{i}@{domain}" for i in range(random.randint(1, count))])

# Test 1: Normal user
def test_normal_1(target, duration):
    print("  [Normal-1] Normal user")
    for _ in range(int(duration / 10)):
        smtp_send(target, "alice@example.com", "pass123", "bob@example.com", "Meeting", "Hi", "192.168.1.100", "normal_users")
        time.sleep(random.uniform(5, 15))

# Test 2: Mobile user (changing IPs)
def test_normal_2(target, duration):
    print("  [Normal-2] Mobile user")
    for _ in range(int(duration / 12)):
        ip = random.choice(["10.0.0.50", "10.0.0.51"])
        smtp_send(target, "bob@example.com", "pass456", "team@company.com", "Update", "Team", ip, "mobile_users")
        time.sleep(random.uniform(8, 20))

# Test 3: Spammer (high volume!)
def test_spammer(target, duration):
    print("  [Spammer] HIGH volume spam")
    start = time.time()
    while time.time() - start < duration:
        to = gen_recipients(random.randint(40, 80), "victims.com")
        bcc = gen_recipients(random.randint(20, 50), "spam.com")
        smtp_send(target, "spam@bad.com", "bad123", to, "WIN!!!", "Click here!!!", "10.99.1.1", bcc, "spammers")
        time.sleep(random.uniform(0.1, 0.5))

# Test 4: New IP flood
def test_new_ip_flood(target, duration):
    print("  [NewIPFlood] High volume new IP")
    start = time.time()
    while time.time() - start < duration:
        smtp_send(target, "charlie@example.com", "pass789", f"test{random.randint(1,100)}@test.com", "Quick", "Test", "198.51.100.99", "new_ip_flood")
        time.sleep(random.uniform(0.1, 0.3))

# Test 5: Mass BCC
def test_mass_bcc(target, duration):
    print("  [MassBCC] Mass BCC")
    start = time.time()
    while time.time() - start < duration:
        to = "undisclosed@list.com"
        bcc = gen_recipients(random.randint(30, 60), "secret.com")
        smtp_send(target, "bcc@attacker.com", "att123", to, "Private", "List", "10.10.10.10", bcc, "mass_bcc")
        time.sleep(random.uniform(1.0, 3.0))

# Test 6: Credential stuffer
def test_credential_stuff(target, duration):
    print("  [CredStuff] Credential stuffing")
    passwords = ["password123", "123456", "admin", "letmein"]
    start = time.time()
    while time.time() - start < duration:
        ip = random.choice(["10.200.1.1", "10.200.1.2"])
        smtp_send(target, "admin@example.com", random.choice(passwords), "victim@test.com", "Reset", "Password", ip, "credential_stuffers")
        time.sleep(random.uniform(0.5, 2.0))

def report():
    print("\n" + "=" * 60)
    print("  EMAIL FIREWALL TEST RESULTS")
    print("=" * 60)
    
    normals = ["normal_users", "mobile_users", "new_employees", "trusted_users"]
    attackers = ["spammers", "new_ip_flood", "mass_bcc", "credential_stuffers"]
    
    print("\n  NORMAL USERS:")
    fp = 0
    for a in normals:
        r = RESULTS.get(a, {"blocked": 0, "allowed": 0})
        print(f"    {a:<20} {r['blocked']} blocked / {r.get('sent',0)} total {'[OK]' if r['blocked']==0 else '[BLOCKED]'}")

    print("\n  ATTACKERS:")
    tp = 0
    for a in attackers:
        r = RESULTS.get(a, {"blocked": 0, "allowed": 0})
        print(f"    {a:<20} {r['blocked']} blocked / {r.get('sent',0)} total {'[DETECTED]' if r['blocked']>0 else '[MISSED]'}")

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Normal users blocked: {sum(RESULTS.get(a,{}).get('blocked',0) for a in normals)}")
    print(f"  Attackers blocked: {sum(RESULTS.get(a,{}).get('blocked',0) for a in attackers)}")
    print("=" * 60)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default=TARGET)
    p.add_argument("--duration", type=int, default=45)
    args = p.parse_args()
    
    print("\n  COMPREHENSIVE EMAIL FIREWALL TEST")
    print(f"  Target: {args.target}, Duration: {args.duration}s\n")
    
    try:
        request.Request(f"{args.target}/health").get_response()
    except:
        print(f"ERROR: Cannot connect to {args.target}")
        sys.exit(1)
    
    threads = [
        threading.Thread(target=test_normal_1, args=(args.target, args.duration)),
        threading.Thread(target=test_normal_2, args=(args.target, args.duration)),
        threading.Thread(target=test_spammer, args=(args.target, args.duration)),
        threading.Thread(target=test_new_ip_flood, args=(args.target, args.duration)),
        threading.Thread(target=test_mass_bcc, args=(args.target, args.duration)),
        threading.Thread(target=test_credential_stuff, args=(args.target, args.duration)),
    ]
    
    for t in threads: t.start()
    for t in threads: t.join()
    report()

if __name__ == "__main__": main()