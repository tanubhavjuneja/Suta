#!/usr/bin/env python3
"""
Email Attack Simulator - Comprehensive Testing

Tests both detection AND checks for false positives (normal users blocked).
Mimics different attacker types with realistic behaviors.

Usage:
  python test_server/email_attack_sim.py --target http://localhost:2525 --duration 120
"""

import argparse
import base64
import json
import random
import string
import sys
import threading
import time
from urllib import request, error

# Config
DEFAULT_TARGET = "http://localhost:2525"
RESULTS = {
    "total": 0, "sent": 0, "blocked": 0, "errors": 0,
    "by_actor": {}, "false_positives": [], "true_positives": []
}
LOCK = threading.Lock()

def do_request(target, path, headers=None, body=None, actor="unknown"):
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
        try: e.read()
        except: pass
    except Exception:
        status = 0
    
    with LOCK:
        RESULTS["total"] += 1
        if actor not in RESULTS["by_actor"]:
            RESULTS["by_actor"][actor] = {"sent": 0, "blocked": 0, "allowed": 0}
        r = RESULTS["by_actor"][actor]
        r["sent"] += 1
        
        if status in (403, 550):
            RESULTS["blocked"] += 1
            r["blocked"] += 1
        elif status == 250 or 200 <= status < 300:
            RESULTS["sent"] += 1
            r["allowed"] += 1
        else:
            RESULTS["errors"] += 1
    
    return status

def smtp_send(target, user, password, to, subject, body, ip, bcc="", actor="unknown"):
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
    
    body_data = {"to": to, "subject": subject, "body": body}
    return do_request(target, "/api/submit", hdrs, body_data, actor)

def gen_recipients(count, domain="example.com"):
    return ",".join([f"user{i}@{domain}" for i in range(random.randint(1, count))])

# ═══════════════════════════════════════════════════════════
# TEST 1: NORMAL USER - Should NEVER be blocked
# ═══════════════════════════════════════════════════════════
def test_normal_user(target, duration):
    name = "Normal"
    user = "alice@example.com"
    password = "pass123"
    known_ip = "192.168.1.100"
    
    print(f"  [{name}] Normal user from known IP")
    start = time.time()
    
    while time.time() - start < duration:
        to = random.choice(["bob@example.com", "charlie@example.com", "david@example.com"])
        subject = random.choice(["Meeting", "Question", "Project update", "Thanks", "Quick chat"])
        body = random.choice([
            "Hi, can we schedule a meeting for next week?",
            "Thanks for your help with the project!",
            "Can you review the document when you have time?",
            "Looking forward to hearing from you.",
            "Here's the update you requested.",
        ])
        
        status = smtp_send(target, user, password, to, subject, body, known_ip, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["false_positives"].append({"actor": name, "reason": "Normal user blocked"})
        
        time.sleep(random.uniform(5.0, 15.0))
    
    print(f"  [{name}] Done")

def test_normal_mobile(target, duration):
    name = "MobileUser"
    user = "bob@example.com"
    password = "pass456"
    mobile_ips = ["10.0.0.50", "10.0.0.51", "10.0.0.52"]
    
    print(f"  [{name}] User on mobile network (changing IPs)")
    start = time.time()
    
    while time.time() - start < duration:
        ip = random.choice(mobile_ips)
        to = "team@company.com"
        subject = "Mobile update"
        body = "Sending from mobile"
        
        status = smtp_send(target, user, password, to, subject, body, ip, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["false_positives"].append({"actor": name, "reason": "Mobile user blocked"})
        
        time.sleep(random.uniform(8.0, 20.0))
    
    print(f"  [{name}] Done")

def test_new_employee(target, duration):
    name = "NewEmployee"
    user = "new@company.com"
    password = "new123"
    new_ip = "203.0.113.100"
    
    print(f"  [{name}] New employee, first few emails")
    start = time.time()
    
    for _ in range(10):
        to = "manager@company.com"
        subject = "Introduction"
        body = "Hi, I'm new to the team"
        
        status = smtp_send(target, user, password, to, subject, body, new_ip, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["false_positives"].append({"actor": name, "reason": "New employee blocked"})
        
        time.sleep(random.uniform(2.0, 5.0))
    
    print(f"  [{name}] Done")

# ═══════════════════════════════════════════════════════════
# TEST 2: ATTACKER TYPES
# ═══════════════════════════════════════════════════════════
def test_spammer_bulk(target, duration):
    name = "Spammer"
    user = "spam@bad.com"
    password = "bad123"
    ip = "10.99.1.1"
    
    print(f"  [{name}] Bulk spam sender")
    start = time.time()
    
    while time.time() - start < duration:
        to = gen_recipients(random.randint(40, 80), "victims.com")
        bcc = gen_recipients(random.randint(20, 50), "more-victims.com")
        subject = random.choice(["WIN PRIZE!!!", "CLICK NOW!!!", "ACT NOW!!!"])
        body = "You won $1,000,000!!!"
        
        status = smtp_send(target, user, password, to, subject, body, ip, bcc, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["true_positives"].append({"actor": name})
        
        time.sleep(random.uniform(0.2, 1.0))
    
    print(f"  [{name}] Done")

def test_new_ip_flood(target, duration):
    name = "NewIPFlood"
    user = "charlie@example.com"
    password = "pass789"
    new_ip = "198.51.100.99"
    
    print(f"  [{name}] High volume from new IP")
    start = time.time()
    
    while time.time() - start < duration:
        to = f"test{random.randint(1,100)}@test.com"
        subject = "Quick"
        body = "Test"
        
        status = smtp_send(target, user, password, to, subject, body, new_ip, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["true_positives"].append({"actor": name})
        
        time.sleep(random.uniform(0.1, 0.5))
    
    print(f"  [{name}] Done")

def test_mass_bcc(target, duration):
    name = "MassBCC"
    user = "bcc@attacker.com"
    password = "att123"
    ip = "10.10.10.10"
    
    print(f"  [{name}] Mass BCC to hide recipients")
    start = time.time()
    
    while time.time() - start < duration:
        to = "undisclosed@list.com"
        bcc = gen_recipients(random.randint(30, 60), "secret-list.com")
        subject = "Private list"
        body = "Here's the list"
        
        status = smtp_send(target, user, password, to, subject, body, ip, bcc, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["true_positives"].append({"actor": name})
        
        time.sleep(random.uniform(1.0, 3.0))
    
    print(f"  [{name}] Done")

def test_credential_stuffing(target, duration):
    name = "CredStuff"
    target_user = "admin@example.com"
    ips = ["10.200.1.1", "10.200.1.2", "10.200.1.3"]
    
    passwords = ["password123", "123456", "admin", "letmein", "welcome", "qwerty"]
    
    print(f"  [{name}] Credential stuffing")
    start = time.time()
    
    while time.time() - start < duration:
        ip = ips[random.randint(0, len(ips)-1)]
        password = random.choice(passwords)
        
        status = smtp_send(target, target_user, password, "victim@test.com", "Reset", password, ip, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["true_positives"].append({"actor": name})
        
        time.sleep(random.uniform(0.5, 2.0))
    
    print(f"  [{name}] Done")

def test_distributed(target, duration):
    name = "Distributed"
    user = "attack@bot.net"
    password = "bot123"
    ips = [f"10.50.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(50)]
    
    print(f"  [{name}] Distributed across many IPs")
    start = time.time()
    
    while time.time() - start < duration:
        ip = random.choice(ips)
        to = f"target{random.randint(1,1000)}@victim.com"
        
        status = smtp_send(target, user, password, to, "Targeted", "Message", ip, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["true_positives"].append({"actor": name})
        
        time.sleep(random.uniform(0.3, 1.5))
    
    print(f"  [{name}] Done")

def test_account_compromise(target, duration):
    name = "AccountHack"
    user = "alice@example.com"
    password = "pass123"
    hack_ip = "203.0.113.77"
    
    print(f"  [{name}] Account compromise - normal user, then suddenly high volume")
    start = time.time()
    phase = 0
    
    while time.time() - start < duration:
        if int(time.time() - start) < duration / 2:
            ip = "192.168.1.100"  # Known IP
            if phase != 0:
                phase = 0
        else:
            ip = hack_ip  # Hacked from new IP
            if phase != 1:
                phase = 1
        
        to = "team@company.com"
        subject = f"Update {int(time.time()-start)}"
        body = "Important" if phase == 1 else "Normal"
        
        status = smtp_send(target, user, password, to, subject, body, ip, name)
        
        if phase == 1 and status in (403, 550):
            with LOCK:
                RESULTS["true_positives"].append({"actor": name})
        
        time.sleep(random.uniform(1.0, 3.0))
    
    print(f"  [{name}] Done")

def test_phishing_campaign(target, duration):
    name = "Phishing"
    user = "security@fake-bank.com"
    password = "fake123"
    ip = "10.88.88.1"
    
    print(f"  [{name}] Phishing campaign")
    start = time.time()
    
    while time.time() - start < duration:
        to = f"customer{random.randint(1,500)}@bank.com"
        subject = random.choice([
            "Verify your account",
            "Security alert",
            "Account suspended",
            "Urgent action required",
        ])
        body = "Click here to verify: http://fake-bank.com/verify"
        
        status = smtp_send(target, user, password, to, subject, body, ip, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["true_positives"].append({"actor": name})
        
        time.sleep(random.uniform(0.5, 2.0))
    
    print(f"  [{name}] Done")

def test_gradual_spam(target, duration):
    name = "GradualSpam"
    user = "gradual@spam.com"
    password = "spam123"
    ip = "10.33.33.1"
    
    print(f"  [{name}] Starts slow, ramps up (evades threshold)")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        to = f"victim{count}@test.com"
        
        if count < 20:
            delay = random.uniform(20.0, 40.0)  # Very slow start
        elif count < 50:
            delay = random.uniform(5.0, 10.0)  # Ramp up
        elif count < 100:
            delay = random.uniform(2.0, 5.0)
        else:
            delay = random.uniform(0.5, 2.0)  # Full speed
        
        subject = f"Message {count}"
        body = "Spam content"
        
        status = smtp_send(target, user, password, to, subject, body, ip, name)
        
        if status in (403, 550):
            with LOCK:
                RESULTS["true_positives"].append({"actor": name})
        
        count += 1
        time.sleep(delay)
    
    print(f"  [{name}] Done")

# ═══════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════
def report():
    print("\n" + "=" * 70)
    print("  EMAIL FIREWALL TEST RESULTS")
    print("=" * 70)
    
    t = RESULTS["total"] or 1
    print(f"\n  Total Requests: {RESULTS['total']}")
    print(f"  Sent:         {RESULTS['sent']}")
    print(f"  Blocked:     {RESULTS['blocked']}")
    print(f"  Errors:      {RESULTS['errors']}")
    print(f"  Block Rate:   {(RESULTS['blocked']/t)*100:.1f}%")
    
    # By actor
    print(f"\n  {'Actor':<15} {'Sent':>6} {'Allowed':>8} {'Blocked':>8}")
    print(f"  {'-'*15} {'-'*6} {'-'*8} {'-'*8}")
    for actor, r in sorted(RESULTS["by_actor"].items()):
        print(f"  {actor:<15} {r['sent']:>6} {r['allowed']:>8} {r['blocked']:>8}")
    
    # False positives (normal users blocked)
    fp = len(RESULTS["false_positives"])
    tp = len(RESULTS["true_positives"])
    
    print(f"\n  === DETECTION ACCURACY ===")
    print(f"  True Positives (attackers blocked):  {tp}")
    print(f"  False Positives (normals blocked): {fp}")
    
    if fp > 0:
        print(f"\n  ⚠️  FALSE POSITIVES DETECTED:")
        for fpn in RESULTS["false_positives"]:
            print(f"    - {fpn['actor']}: {fpn['reason']}")
    
    # Verdict
    print(f"\n  === VERDICT ===")
    if fp == 0 and tp > 0:
        print("  ✅ GOOD: Normal users NOT blocked, attackers blocked")
    elif fp == 0 and tp == 0:
        print("  ⚠️  No detection - check thresholds")
    else:
        print(f"  ⚠️  PROBLEM: {fp} normal users blocked")
    
    print("=" * 70)

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default=DEFAULT_TARGET)
    p.add_argument("--duration", type=int, default=90)
    p.add_argument("--threads", type=int, default=5)
    args = p.parse_args()
    
    print("\n" + "=" * 70)
    print("  EMAIL ATTACK SIMULATOR - COMPREHENSIVE TEST")
    print(f"  Target:    {args.target}")
    print(f"  Duration:  {args.duration}s")
    print(f"  Threads:   {args.threads}")
    print("=" * 70)
    
    # Test connectivity
    try:
        req = request.Request(f"{args.target}/health")
        resp = request.urlopen(req, timeout=5)
        print(f"  Target OK: {resp.status}\n")
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)
    
    # Start threads
    threads = []
    
    # Normal users (false positive tests)
    threads.append(threading.Thread(target=test_normal_user, args=(args.target, args.duration)))
    threads.append(threading.Thread(target=test_normal_mobile, args=(args.target, args.duration)))
    threads.append(threading.Thread(target=test_new_employee, args=(args.target, args.duration)))
    
    # Attackers
    attacks = [
        test_spammer_bulk,
        test_new_ip_flood,
        test_mass_bcc,
        test_credential_stuffing,
        test_distributed,
        test_account_compromise,
        test_phishing_campaign,
        test_gradual_spam,
    ]
    
    for i in range(args.threads):
        fn = attacks[i % len(attacks)]
        threads.append(threading.Thread(target=fn, args=(args.target, args.duration)))
    
    for t in threads:
        t.start()
    
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(10)
            print(f"  [{int(time.time())}s] Total: {RESULTS['total']}, Blocked: {RESULTS['blocked']}")
    except KeyboardInterrupt:
        print("\n  Stopping...")
    
    for t in threads:
        t.join()
    
    report()

if __name__ == "__main__":
    main()