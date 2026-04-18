#!/usr/bin/env python3
"""
email_attack_sim.py — Email Attack Simulator

Tests email firewall with:
1. Normal users - varied recipients, normal volume, human timing
2. Spammers - mass BCC, high volume
3. NEW_IP attackers - from new IPs, high volume
4. Targeted attackers - low volume but suspicious patterns
5. Account compromise - rapid sending after login

Usage:
  python email_attack_sim.py --target http://localhost:2525 --duration 120
"""

import argparse
import base64
import json
import random
import string
import sys
import threading
import time
from datetime import datetime
from urllib import request, error

# Config
DEFAULT_TARGET = "http://localhost:2525"
RESULTS = {
    "total": 0, "sent": 0, "blocked": 0, "blocked_users": 0, "blocked_ips": 0, 
    "errors": 0, "actors": {}
}
LOCK = threading.Lock()
ADMIN_TRUSTED = {}  # Will be populated by admin actions

# Email generation
def gen_recipients(count, domain="example.com"):
    return [f"user{i}@{domain}" for i in range(random.randint(1, count))]

def gen_email_content(pattern="normal"):
    templates = {
        "normal": [
            "Hi, just following up on our conversation.",
            "Thanks for your help with the project!",
            "Can we schedule a meeting for next week?",
            "Here's the document you requested.",
            "Looking forward to hearing from you.",
        ],
        "spam": [
            "MAKE MONEY FAST!!!",
            "CLICK HERE TO WIN PRIZE!!!",
            "Your account has been compromised!",
            "URGENT: Verify your password now!",
            "Congratulations, you've won $1,000,000!",
        ],
        "phishing": [
            "Your account will be suspended.",
            "Please verify your identity.",
            "Unusual login detected.",
            "Click to confirm your email.",
            "Security alert: action required.",
        ],
    }
    if pattern == "random":
        return random.choice(templates[random.choice(["spam", "phishing"])])
    return random.choice(templates.get(pattern, templates["normal"]))

# HTTP helpers
def do_email(target, method, headers=None, body=None, actor="unknown"):
    url = f"{target}{method}"
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
        if actor not in RESULTS["actors"]:
            RESULTS["actors"][actor] = {"sent": 0, "blocked": 0, "allowed": 0}
        a = RESULTS["actors"][actor]
        a["sent"] += 1
        
        if status == 550 or status == 403:
            RESULTS["blocked"] += 1
            RESULTS["blocked_users"] += 1
            a["blocked"] += 1
        elif 200 <= status < 400 or status == 250:
            RESULTS["sent"] += 1
            a["sent"] += 1
        else:
            RESULTS["errors"] += 1
    
    return status

def do_smtp(target, user, password, to, subject, body, ip, actor="unknown"):
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    
    hdrs = {
        "Authorization": f"Basic {auth}",
        "From": user,
        "To": to,
        "Subject": subject,
        "X-Sender-IP": ip,
    }
    
    # Convert recipients to comma-separated
    if isinstance(to, list):
        to = ",".join(to)
    
    body_data = {"to": to, "subject": subject, "body": body}
    
    status = do_email(target, "/api/submit", hdrs, body_data, actor)
    return status

# ═══════════════════════════════════════════════════════════════
#  NORMAL EMAIL USER — Should NEVER be blocked
# ═══════════════════════════════════════════════════════════════
def normal_user(target, duration):
    name = "NormalUser"
    user = "alice@example.com"
    password = "pass123"
    ips = ["192.168.1.100", "10.0.0.5"]  # Known IPs
    
    print(f"  [{name}] Starting - normal email patterns")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        ip = random.choice(ips)
        to = random.choice(["bob@example.com", "charlie@example.com", "david@example.com"])
        subject = random.choice(["Meeting", "Question", "Update", "Thanks", "Follow up"])
        body = gen_email_content("normal")
        
        status = do_smtp(target, user, password, to, subject, body, ip, name)
        count += 1
        
        # Normal timing: 3-10 seconds between emails
        time.sleep(random.uniform(3.0, 10.0))
    
    print(f"  [{name}] Done - {count} emails sent")

# ═══════════════════════════════════════════════════════════
#  SPAMMER — Mass BCC, high volume
# ═══════════════════════════════════════════════════════════════
def spammer(target, duration):
    name = "Spammer"
    user = "evil@spam-domain.com"
    password = "hack123"
    ip = "10.100.1.50"
    
    print(f"  [{name}] Starting - mass BCC spam")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        to = ",".join(gen_recipients(random.randint(30, 80), "badsite.com"))
        bcc = ",".join(gen_recipients(random.randint(20, 50), "spam.com"))
        
        subject = random.choice([
            "MAKE MONEY FAST!!!",
            "CLICK HERE NOW!!!",
            "URGENT: Your account!",
        ])
        body = gen_email_content("spam")
        
        status = do_smtp(target, user, password, to, subject, body, ip, name)
        count += 1
        
        if count % 10 == 0:
            print(f"  [{name}] {count} spam emails")
        
        # High volume but with small delays
        time.sleep(random.uniform(0.5, 2.0))
    
    print(f"  [{name}] Done - {count} spam emails")

# ═══════════════════════════════════════════════════════════
#  NEW IP ATTACKER — High volume from new IP
# ═══════════════════════════════════════════════════════════════
def new_ip_attacker(target, duration):
    name = "NewIPAttacker"
    user = "charlie@example.com"
    password = "pass789"
    new_ip = "203.0.113.99"  # Never seen before
    
    print(f"  [{name}] Starting - high volume from new IP")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        to = random.choice(["test1@example.com", "test2@example.com", "test3@example.com"])
        subject = "Quick question"
        body = "Hi there"
        
        status = do_smtp(target, user, password, to, subject, body, new_ip, name)
        count += 1
        
        if count % 20 == 0:
            print(f"  [{name}] {count} from new IP")
        
        time.sleep(random.uniform(0.3, 1.0))
    
    print(f"  [{name}] Done - {count} emails from new IP")

# ═══════════════════════════════════════════════════════════
#  CREDENTIAL STUFFER — Trying many passwords
# ═══════════════════════════════════════════════════════
def credential_stuffer(target, duration):
    name = "CredStuff"
    target_user = "admin@example.com"
    ips = ["10.200.1.1", "10.200.1.2", "10.200.1.3"]
    
    passwords = ["password123", "123456", "admin", "letmein", "welcome1", 
                "monkey", "dragon", "master", "qwerty", "test1234"]
    
    print(f"  [{name}] Starting - credential stuffing")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        ip = ips[count % len(ips)]
        password = random.choice(passwords)
        
        # Try login via email sending
        status = do_smtp(target, target_user, password, "victim@example.com", 
                      "Password reset", "Your password is: " + password, ip, name)
        count += 1
        
        if count % 15 == 0:
            print(f"  [{name}] {count} attempts")
        
        # Slow enough to bypass rate limit
        time.sleep(random.uniform(0.8, 2.0))
    
    print(f"  [{name}] Done - {count} attempts")

# ═══════════════════════════════════════════════════════════
#  DISTRIBUTED ATTACKER — Rotates IPs
# ═══════════════════════════════════════════════════════════
def distributed_attacker(target, duration):
    name = "DistAttacker"
    user = "attacker@bad.net"
    password = "hacked"
    ips = [f"10.50.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(30)]
    
    print(f"  [{name}] Starting - distributed IPs")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        ip = ips[random.randint(0, len(ips)-1)]
        to = f"target{count}@victim.com"
        
        status = do_smtp(target, user, password, to, "Urgent", "Click here", ip, name)
        count += 1
        
        if count % 25 == 0:
            print(f"  [{name}] {count} distributed emails")
        
        time.sleep(random.uniform(0.5, 1.5))
    
    print(f"  [{name}] Done - {count} distributed emails")

# ═══════════════════════════════════════════════════════════
#  MIXED BEHAVIOR — Normal then attack
# ═══════════════════════════════════════════════════════════
def mixed_behavior(target, duration):
    name = "MixedBot"
    user = "bob@example.com"
    password = "pass456"
    known_ip = "192.168.1.101"
    new_ips = ["203.0.113.1", "203.0.113.2"]
    
    print(f"  [{name}] Starting - behaves normally, then attacks")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        # First half: normal, second half: attack
        if int(time.time() - start) < duration / 2:
            to = "colleague@company.com"
            subject = "Quick question"
            body = "Can we meet tomorrow?"
            ip = known_ip
        else:
            # Attack mode
            to = ",".join(gen_recipients(30, "target.com"))
            subject = "URGENT"
            body = "Click here!!!"
            ip = random.choice(new_ips)
        
        status = do_smtp(target, user, password, to, subject, body, ip, name)
        count += 1
        
        time.sleep(random.uniform(1.0, 3.0))
    
    print(f"  [{name}] Done - {count} mixed emails")

# ═══════════════════════════════════════════════════════════
#  ADMIN TRUSTED TEST
# ═══════════════════════════════════════════════════════
def admin_trusted_test(target, duration):
    name = "AdminTrusted"
    user = "david@example.com"
    password = "test999"
    trusted_ip = "203.0.113.50"  # In known IPs
    
    print(f"  [{name}] Starting - admin trusted user from known IP")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        to = "team@company.com"
        subject = f"Update #{count+1}"
        body = "Important update"
        
        # This IP should be trusted
        status = do_smtp(target, user, password, to, subject, body, trusted_ip, name)
        count += 1
        
        if count % 15 == 0:
            print(f"  [{name}] {count} (should be allowed)")
        
        time.sleep(random.uniform(2.0, 5.0))
    
    print(f"  [{name}] Done - {count} trusted emails")

# ═══════════════════════════════════════════════════════════
#  REPORT
# ═══════════════════════════════════════════════════════════════
def report():
    t = RESULTS["total"] or 1
    print("\n" + "=" * 60)
    print("  EMAIL ATTACK SIMULATION RESULTS")
    print("=" * 60)
    print(f"\n  Total Requests: {RESULTS['total']}")
    print(f"  Sent:          {RESULTS['sent']}")
    print(f"  Blocked:       {RESULTS['blocked']}")
    print(f"  Errors:        {RESULTS['errors']}")
    print(f"\n  Block Rate:    {(RESULTS['blocked']/t)*100:.1f}%")
    
    print(f"\n  {'Actor':<18} {'Sent':>6} {'Allowed':>8} {'Blocked':>8}")
    print(f"  {'-'*18} {'-'*6} {'-'*8} {'-'*8}")
    
    for actor, data in sorted(RESULTS["actors"].items()):
        print(f"  {actor:<18} {data['sent']:>6} {data.get('allowed', data['sent']-data['blocked']):>8} {data['blocked']:>8}")
    
    # Verdict
    normal = RESULTS["actors"].get("NormalUser", {})
    admin = RESULTS["actors"].get("AdminTrusted", {})
    
    print("\n  Verdict:")
    if normal.get("blocked", 0) == 0:
        print("    [OK] Normal users NOT blocked")
    else:
        print(f"    [X] Normal users blocked {normal['blocked']} times (FALSE POSITIVE)")
    
    if admin.get("blocked", 0) == 0:
        print("    [OK] Admin trusted users NOT blocked")
    else:
        print(f"    [X] Admin trusted blocked {admin['blocked']} times (should be allowed)")
    
    attackers_blocked = sum(d["blocked"] for a, d in RESULTS["actors"].items() 
                       if a not in ("NormalUser", "AdminTrusted"))
    if attackers_blocked > 0:
        print(f"    [OK] Attackers blocked: {attackers_blocked}")
    else:
        print("    [X] No attackers blocked")
    
    print("=" * 60 + "\n")

# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════
def main():
    p = argparse.ArgumentParser(description="Email Attack Simulator")
    p.add_argument("--target", default=DEFAULT_TARGET)
    p.add_argument("--duration", type=int, default=90)
    p.add_argument("--threads", type=int, default=4)
    args = p.parse_args()
    
    print("\n" + "=" * 60)
    print("  Email Attack Simulator - Behavioral Testing")
    print(f"  Target:    {args.target}")
    print(f"  Duration:  {args.duration}s")
    print(f"  Threads:   {args.threads}")
    print("=" * 60)
    
    # Test connectivity
    try:
        req = request.Request(f"{args.target}/health")
        resp = request.urlopen(req, timeout=10)
        print(f"  Target reachable: {resp.status}\n")
    except Exception as e:
        print(f"  ERROR: Cannot reach target: {e}")
        print("  Start email server: node test_server/email_server.js")
        sys.exit(1)
    
    print("  Starting attack threads...\n")
    
    threads = [
        threading.Thread(target=normal_user, args=(args.target, args.duration)),
        threading.Thread(target=admin_trusted_test, args=(args.target, args.duration)),
        threading.Thread(target=spammer, args=(args.target, args.duration)),
        threading.Thread(target=new_ip_attacker, args=(args.target, args.duration)),
    ]
    
    # Add attacker threads
    attacks = [credential_stuffer, distributed_attacker, mixed_behavior]
    for i in range(args.threads - 2):
        fn = attacks[i % len(attacks)]
        threads.append(threading.Thread(target=fn, args=(args.target, args.duration)))
    
    start = time.time()
    for t in threads:
        t.start()
    
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(10)
            elapsed = int(time.time() - start)
            print(f"  [{elapsed:>3}s] Sent: {RESULTS['sent']:>4} | Blocked: {RESULTS['blocked']:>3}")
    except KeyboardInterrupt:
        print("\n  Stopping...")
    
    for t in threads:
        t.join(timeout=3)
    
    report()

if __name__ == "__main__":
    main()