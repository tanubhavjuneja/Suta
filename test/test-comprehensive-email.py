#!/usr/bin/env python3
"""
Comprehensive Email Firewall Test
Tests detection accuracy AND false positives

Usage:
  python test/test-comprehensive-email.py --duration 120
"""

import argparse
import base64
import json
import random
import sys
import threading
import time
from urllib import request, error

TARGET = "http://localhost:2525"
RESULTS = {
    "normal_users": {"blocked": 0, "allowed": 0},
    "mobile_users": {"blocked": 0, "allowed": 0},
    "new_employees": {"blocked": 0, "allowed": 0},
    "trusted_users": {"blocked": 0, "allowed": 0},
    "spammers": {"blocked": 0, "allowed": 0},
    "new_ip_flood": {"blocked": 0, "allowed": 0},
    "mass_bcc": {"blocked": 0, "allowed": 0},
    "credential_stuffers": {"blocked": 0, "allowed": 0},
    "distributed": {"blocked": 0, "allowed": 0},
    "account_hijack": {"blocked": 0, "allowed": 0},
    "phishing": {"blocked": 0, "allowed": 0},
    "gradual_spam": {"blocked": 0, "allowed": 0},
}
LOCK = threading.Lock()

def send_email(target, user, password, to, subject, body, ip, bcc="", actor="unknown"):
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    hdrs = {
        "Authorization": f"Basic {auth}",
        "From": user,
        "To": to,
        "Subject": subject,
        "X-Sender-IP": ip,
    }
    if bcc:
        hdrs["Bcc"] = bcc
    
    url = f"{target}/api/submit"
    data = json.dumps({"to": to, "subject": subject, "body": body}).encode()
    req = request.Request(url, data=data, headers=hdrs, method="POST")
    
    status = 0
    try:
        resp = request.urlopen(req, timeout=15)
        status = resp.status
        resp.read()
    except error.HTTPError as e:
        status = e.code
        try: e.read()
        except: pass
    except Exception:
        status = 0
    
    with LOCK:
        if actor not in RESULTS:
            RESULTS[actor] = {"blocked": 0, "allowed": 0}
        
        if status in (403, 550):
            RESULTS[actor]["blocked"] += 1
        else:
            RESULTS[actor]["allowed"] += 1
    
    return status

def gen_recipients(count, domain="example.com"):
    return ",".join([f"user{i}@{domain}" for i in range(random.randint(1, count))])

# === NORMAL USER TESTS (should NEVER be blocked) ===
def test_normal_1(target, duration):
    """Normal user from known IP"""
    print("  [Normal-1] Normal user from known IP")
    start = time.time()
    while time.time() - start < duration:
        send_email(target, "alice@example.com", "pass123", 
                "bob@example.com", "Meeting", "Hi Bob, let's meet", 
                "192.168.1.100", actor="normal_users")
        time.sleep(random.uniform(5, 15))
    print("  [Normal-1] Done")

def test_normal_2(target, duration):
    """Normal user on mobile (changing IPs)"""
    print("  [Normal-2] Mobile user")
    start = time.time()
    while time.time() - start < duration:
        ip = random.choice(["10.0.0.50", "10.0.0.51", "10.0.0.52"])
        send_email(target, "bob@example.com", "pass456",
                "team@company.com", "Update", "Team update",
                ip, actor="mobile_users")
        time.sleep(random.uniform(8, 20))
    print("  [Normal-2] Done")

def test_normal_3(target, duration):
    """New employee first emails"""
    print("  [Normal-3] New employee")
    start = time.time()
    count = 0
    while count < 15 and time.time() - start < duration:
        send_email(target, "new@company.com", "new123",
                "manager@company.com", "Introduction", "Hi, I'm new",
                "203.0.113.100", actor="new_employees")
        count += 1
        time.sleep(random.uniform(3, 8))
    print("  [Normal-3] Done")

def test_normal_4(target, duration):
    """Trusted admin user"""
    print("  [Normal-4] Trusted admin user")
    start = time.time()
    while time.time() - start < duration:
        send_email(target, "admin@company.com", "admin123",
                "all@company.com", "Announcement", "Company update",
                "203.0.113.50", actor="trusted_users")
        time.sleep(random.uniform(10, 30))
    print("  [Normal-4] Done")

# === ATTACKER TESTS (should be blocked) ===
def test_spammer(target, duration):
    print("  [Spammer] Bulk spam")
    start = time.time()
    while time.time() - start < duration:
        to = gen_recipients(random.randint(40, 80), "victims.com")
        bcc = gen_recipients(random.randint(20, 50), "spam.com")
        send_email(target, "spam@bad.com", "bad123", to, "WIN!!!", "Click here!!!",
                "10.99.1.1", bcc, actor="spammers")
        time.sleep(random.uniform(0.2, 1.0))
    print("  [Spammer] Done")

def test_new_ip_flood(target, duration):
    print("  [NewIPFlood] High volume from new IP")
    start = time.time()
    while time.time() - start < duration:
        send_email(target, "charlie@example.com", "pass789",
                f"test{random.randint(1,100)}@test.com", "Quick", "Test",
                "198.51.100.99", actor="new_ip_flood")
        time.sleep(random.uniform(0.1, 0.5))
    print("  [NewIPFlood] Done")

def test_mass_bcc(target, duration):
    print("  [MassBCC] Mass BCC")
    start = time.time()
    while time.time() - start < duration:
        to = "undisclosed@list.com"
        bcc = gen_recipients(random.randint(30, 60), "secret.com")
        send_email(target, "bcc@attacker.com", "att123", to, "Private", "List",
                "10.10.10.10", bcc, actor="mass_bcc")
        time.sleep(random.uniform(1.0, 3.0))
    print("  [MassBCC] Done")

def test_cred_stuff(target, duration):
    print("  [CredStuff] Credential stuffing")
    start = time.time()
    passwords = ["password123", "123456", "admin", "letmein"]
    while time.time() - start < duration:
        ip = random.choice(["10.200.1.1", "10.200.1.2"])
        send_email(target, "admin@example.com", random.choice(passwords),
                "victim@test.com", "Reset", "Password", ip, actor="credential_stuffers")
        time.sleep(random.uniform(0.5, 2.0))
    print("  [CredStuff] Done")

def test_distributed(target, duration):
    print("  [Distributed] Distributed IPs")
    start = time.time()
    ips = [f"10.50.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(30)]
    while time.time() - start < duration:
        ip = random.choice(ips)
        send_email(target, "bot@attacker.net", "bot123",
                f"target{random.randint(1,500)}@victim.com", "Targeted", "Message",
                ip, actor="distributed")
        time.sleep(random.uniform(0.3, 1.5))
    print("  [Distributed] Done")

def test_account_hijack(target, duration):
    print("  [AccountHack] Account compromise")
    start = time.time()
    phase = 0
    while time.time() - start < duration:
        if int(time.time() - start) < duration / 2:
            ip = "192.168.1.100"
            phase = 0
        else:
            ip = "203.0.113.77"
            phase = 1
        
        send_email(target, "alice@example.com", "pass123",
                "team@company.com", f"Update {int(time.time()-start)}",
                "Important" if phase == 1 else "Normal", ip, actor="account_hijack")
        time.sleep(random.uniform(1.0, 3.0))
    print("  [AccountHack] Done")

def test_phishing(target, duration):
    print("  [Phishing] Phishing campaign")
    start = time.time()
    while time.time() - start < duration:
        send_email(target, "security@fake-bank.com", "fake123",
                f"customer{random.randint(1,300)}@bank.com",
                random.choice(["Verify account", "Security alert", "Account suspended"]),
                "Click: http://fake.com/verify", "10.88.88.1", actor="phishing")
        time.sleep(random.uniform(0.5, 2.0))
    print("  [Phishing] Done")

def test_gradual(target, duration):
    print("  [GradualSpam] Gradual escalation")
    start = time.time()
    count = 0
    while time.time() - start < duration:
        if count < 20:
            delay = random.uniform(20, 40)
        elif count < 50:
            delay = random.uniform(5, 10)
        elif count < 100:
            delay = random.uniform(2, 5)
        else:
            delay = random.uniform(0.5, 2)
        
        send_email(target, "gradual@spam.com", "spam123",
                f"victim{count}@test.com", "Msg", "Spam",
                "10.33.33.1", actor="gradual_spam")
        count += 1
        time.sleep(delay)
    print("  [GradualSpam] Done")

def report():
    print("\n" + "=" * 70)
    print("  EMAIL FIREWALL TEST RESULTS")
    print("=" * 70)
    
    # Separate normal vs attackers
    normal = ["normal_users", "mobile_users", "new_employees", "trusted_users"]
    attackers = ["spammers", "new_ip_flood", "mass_bcc", "credential_stuffers",
                "distributed", "account_hijack", "phishing", "gradual_spam"]
    
    print("\n  === NORMAL USERS (should NOT be blocked) ===")
    fp_total = 0
    for actor in normal:
        r = RESULTS.get(actor, {"blocked": 0, "allowed": 0})
        blocked = r["blocked"]
        allowed = r["allowed"]
        total = blocked + allowed
        if total > 0:
            fp_rate = (blocked / total) * 100
            status = "❌ BLOCKED" if blocked > 0 else "✅ OK"
            print(f"    {actor:<20} {blocked:>3} blocked / {total:>3} total ({fp_rate:.1f}%) {status}")
            fp_total += blocked
    
    print("\n  === ATTACKERS (should be blocked) ===")
    tp_total = 0
    for actor in attackers:
        r = RESULTS.get(actor, {"blocked": 0, "allowed": 0})
        blocked = r["blocked"]
        allowed = r["allowed"]
        total = blocked + allowed
        if total > 0:
            tp_rate = (blocked / total) * 100
            status = "✅ BLOCKED" if blocked > 0 else "❌ MISSED"
            print(f"    {actor:<20} {blocked:>3} blocked / {total:>3} total ({tp_rate:.1f}%) {status}")
            tp_total += blocked
    
    # Summary
    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    
    if fp_total > 0:
        print(f"\n  ❌ PROBLEM: {fp_total} false positives (normal users blocked)")
    else:
        print(f"\n  ✅ GOOD: No false positives")
    
    if tp_total > 0:
        print(f"  ✅ Detection: {tp_total} attackers blocked")
    else:
        print(f"  ❌ PROBLEM: No attackers detected")
    
    # Overall accuracy
    all_blocked = sum(RESULTS[k]["blocked"] for k in RESULTS)
    all_allowed = sum(RESULTS[k]["allowed"] for k in RESULTS)
    all_total = all_blocked + all_allowed
    
    if all_total > 0:
        block_rate = (all_blocked / all_total) * 100
        print(f"\n  Overall block rate: {block_rate:.1f}%")
    
    print("=" * 70)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default=TARGET)
    p.add_argument("--duration", type=int, default=90)
    p.add_argument("--threads", type=int, default=4)
    args = p.parse_args()
    
    print("\n" + "=" * 70)
    print("  COMPREHENSIVE EMAIL FIREWALL TEST")
    print(f"  Target:    {args.target}")
    print(f"  Duration:  {args.duration}s")
    print("=" * 70)
    
    # Test connectivity
    try:
        req = request.Request(f"{args.target}/health")
        resp = request.urlopen(req, timeout=5)
        print(f"  Target OK: {resp.status}\n")
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)
    
    print("  Running tests...\n")
    
    threads = [
        threading.Thread(target=test_normal_1, args=(args.target, args.duration)),
        threading.Thread(target=test_normal_2, args=(args.target, args.duration)),
        threading.Thread(target=test_normal_3, args=(args.target, args.duration)),
        threading.Thread(target=test_normal_4, args=(args.target, args.duration)),
    ]
    
    attacks = [test_spammer, test_new_ip_flood, test_mass_bcc, test_cred_stuff,
              test_distributed, test_account_hijack, test_phishing, test_gradual]
    
    for i in range(args.threads):
        threads.append(threading.Thread(target=attacks[i % len(attacks)], 
                                   args=(args.target, args.duration)))
    
    start = time.time()
    for t in threads:
        t.start()
    
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(10)
            print(f"  [{int(time.time()-start)}s]")
    except KeyboardInterrupt:
        print("\n  Stopping...")
    
    for t in threads:
        t.join()
    
    report()

if __name__ == "__main__":
    main()