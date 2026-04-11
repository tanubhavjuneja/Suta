#!/usr/bin/env python3
"""
attack_sim.py — API Attack Simulator with Realistic Behavioral Patterns

Tests detection engine with:
1. Normal users - should be allowed (varied endpoints, natural timing)
2. Slow attackers - bypass rate limit but trigger ML detection
3. Smart enumeration - rotate IPs, vary timing, use proper headers
4. Credential testing - slow enough to not trigger rate limit

Usage:
  python attack_sim.py --target http://localhost:3000 --duration 120
"""

import argparse
import json
import random
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib import request, error
from datetime import datetime
import os

# ── Config ───────────────────────────────────────────────────
DEFAULT_TARGET = "http://localhost:3000"
RESULTS = {"total": 0, "allowed": 0, "blocked": 0, "throttled": 0, "errors": 0, "actors": {}}
LOCK = threading.Lock()

# ── IP Generation ──────────────────────────────────────────
def gen_ip():
    """Generate random public IP."""
    while True:
        octs = [random.randint(1, 254) for _ in range(4)]
        if octs[0] not in (10, 127) and not (octs[0] == 172 and 16 <= octs[1] <= 31) and not (octs[0] == 192 and octs[1] == 168):
            return ".".join(str(o) for o in octs)

def gen_ip_pool(count=5):
    return [gen_ip() for _ in range(count)]

# ── HTTP Request ───────────────────────────────────────────
def do_req(target, method, path, headers=None, body=None, actor="unknown"):
    url = f"{target}{path}"
    hdrs = headers or {}
    hdrs.setdefault("Content-Type", "application/json")
    
    data = json.dumps(body).encode() if body else None
    req = request.Request(url, data=data, headers=hdrs, method=method)
    
    status = 0
    try:
        resp = request.urlopen(req, timeout=15)
        status = resp.status
        resp.read()
    except error.HTTPError as e:
        status = e.code
        e.read()
    except Exception:
        status = 0
    
    with LOCK:
        RESULTS["total"] += 1
        if actor not in RESULTS["actors"]:
            RESULTS["actors"][actor] = {"sent": 0, "allowed": 0, "blocked": 0, "throttled": 0}
        a = RESULTS["actors"][actor]
        a["sent"] += 1
        
        if status == 403:
            RESULTS["blocked"] += 1
            a["blocked"] += 1
        elif status == 429:
            RESULTS["throttled"] += 1
            a["throttled"] += 1
        elif 200 <= status < 400:
            RESULTS["allowed"] += 1
            a["allowed"] += 1
        else:
            RESULTS["errors"] += 1
    
    return status

# ═══════════════════════════════════════════════════════════════
#  NORMAL USER — Should NEVER be blocked
# ═══════════════════════════════════════════════════════════════
def normal_user(target, duration):
    name = "NormalUser"
    ip = "203.45.67.89"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.validtoken",
        "X-Forwarded-For": ip,
    }
    
    # Diverse, realistic endpoints
    paths = [
        ("GET", "/api/health"),
        ("GET", "/api/products/1"),
        ("GET", "/api/products/5"),
        ("GET", "/api/products/12"),
        ("GET", "/api/search?q=shoes"),
        ("GET", "/api/search?q=jacket"),
        ("GET", "/api/listings"),
        ("GET", "/api/listings?page=2"),
        ("GET", "/api/users/42/profile"),
        ("GET", "/api/products/8"),
    ]
    
    print(f"  [NormalUser] Starting - varied endpoints, human timing")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        method, path = random.choice(paths)
        status = do_req(target, method, path, headers, actor=name)
        count += 1
        
        # Human timing: 2-8 seconds between requests
        time.sleep(random.uniform(2.0, 8.0))
    
    print(f"  [NormalUser] Done - {count} requests, all allowed")

# ═══════════════════════════════════════════════════════════
#  SLOW CREDENTIAL STUFFER — Bypasses rate limit, triggers ML
# ═══════════════════════════════════════════════════════════
def slow_creds(target, duration):
    name = "SlowCreds"
    ips = gen_ip_pool(10)
    
    headers_base = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
    }
    
    usernames = [f"admin{i}@corp.com" for i in range(1, 200)]
    passwords = ["password123", "123456", "admin", "letmein", "welcome1", "monkey"]
    
    print(f"  [SlowCreds] Starting - slow login attempts, bypasses rate limit")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        ip = ips[count % len(ips)]
        hdrs = {**headers_base, "X-Forwarded-For": ip}
        
        body = {
            "username": random.choice(usernames),
            "password": random.choice(passwords),
        }
        
        status = do_req(target, "POST", "/api/auth/login", hdrs, body, actor=name)
        count += 1
        
        if count % 20 == 0:
            print(f"  [SlowCreds] {count} attempts -> status {status}")
        
        # Slow enough to bypass rate limit (0.8-1.5 seconds)
        time.sleep(random.uniform(0.8, 1.5))
    
    print(f"  [SlowCreds] Done - {count} attempts")

# ═══════════════════════════════════════════════════════════
#  SMART SCRAPER — Varies timing, uses proper headers
# ═══════════════════════════════════════════════════════════
def smart_scraper(target, duration):
    name = "SmartScraper"
    ips = gen_ip_pool(5)
    
    headers_base = {
        "User-Agent": "Mozilla/5.0 (compatible; Spider/1.0; +http://example.com)",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    }
    
    print(f"  [SmartScraper] Starting - profile enumeration with varied timing")
    start = time.time()
    count = 0
    user_id = 1
    
    while time.time() - start < duration:
        ip = ips[count % len(ips)]
        hdrs = {**headers_base, "X-Forwarded-For": ip}
        
        status = do_req(target, "GET", f"/api/users/{user_id}/profile", hdrs, actor=name)
        user_id = (user_id % 100) + 1
        count += 1
        
        if count % 30 == 0:
            print(f"  [SmartScraper] {count} profiles -> status {status}")
        
        # Varied timing: 0.4-1.2 seconds (just under rate limit)
        time.sleep(random.uniform(0.4, 1.2))
    
    print(f"  [SmartScraper] Done - {count} profiles")

# ═══════════════════════════════════════════════════════════
#  DISTRIBUTED ENUMERATOR — Changes IP per request
# ═══════════════════════════════════════════════════════════
def distributed_enum(target, duration):
    name = "DistEnum"
    ips = gen_ip_pool(20)  # Many IPs
    
    headers_base = {
        "User-Agent": "curl/8.4.0",
        "Accept": "*/*",
    }
    
    print(f"  [DistEnum] Starting - many IPs, slow enumeration")
    start = time.time()
    count = 0
    item_id = 1
    
    while time.time() - start < duration:
        # New IP for each request
        ip = ips[random.randint(0, len(ips) - 1)]
        hdrs = {**headers_base, "X-Forwarded-For": ip}
        
        # Alternate between endpoints
        path = f"/api/products/{item_id}" if count % 2 else f"/api/users/{item_id}"
        status = do_req(target, "GET", path, hdrs, actor=name)
        
        item_id = (item_id % 50) + 1
        count += 1
        
        if count % 40 == 0:
            print(f"  [DistEnum] {count} items -> status {status}")
        
        # Very slow to avoid rate limit
        time.sleep(random.uniform(1.0, 2.0))
    
    print(f"  [DistEnum] Done - {count} items")

# ═══════════════════════════════════════════════════════════
#  MIXED BEHAVIOR — Sometimes normal, sometimes attack
# ═══════════════════════════════════════════════════════════
def mixed_behavior(target, duration):
    name = "MixedBot"
    ips = gen_ip_pool(3)
    
    headers_normal = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/json",
        "Authorization": "Bearer some_token",
        "X-Forwarded-For": ips[0],
    }
    
    headers_attack = {
        "User-Agent": "python-requests/2.31.0",
        "Accept": "*/*",
    }
    
    print(f"  [MixedBot] Starting - behaves normally, then attacks")
    start = time.time()
    count = 0
    attack_mode = False
    
    while time.time() - start < duration:
        # Switch between normal and attack every 30 seconds
        if int(time.time() - start) % 60 < 30:
            # Normal mode
            hdrs = headers_normal
            path = random.choice(["/api/products/1", "/api/users/1/profile", "/api/search?q=test"])
            status = do_req(target, "GET", path, hdrs, actor=name)
            time.sleep(random.uniform(1.0, 3.0))
        else:
            # Attack mode - try auth endpoints
            hdrs = {**headers_attack, "X-Forwarded-For": ips[random.randint(0, len(ips)-1)]}
            body = {"username": "admin", "password": "wrongpass"}
            status = do_req(target, "POST", "/api/auth/login", hdrs, body, actor=name)
            time.sleep(random.uniform(0.5, 1.0))
        
        count += 1
    
    print(f"  [MixedBot] Done - {count} mixed requests")

# ═══════════════════════════════════════════════════════════
#  REPORT
# ═══════════════════════════════════════════════════════════
def report():
    t = RESULTS["total"] or 1
    print("\n" + "=" * 60)
    print("  ATTACK SIMULATION RESULTS")
    print("=" * 60)
    print(f"\n  Total Requests: {RESULTS['total']}")
    print(f"  Allowed:       {RESULTS['allowed']}")
    print(f"  Blocked:       {RESULTS['blocked']}")
    print(f"  Throttled:    {RESULTS['throttled']}")
    print(f"  Errors:       {RESULTS['errors']}")
    print(f"\n  Block Rate:   {(RESULTS['blocked']/t)*100:.1f}%")
    
    print(f"\n  {'Actor':<18} {'Sent':>6} {'Allow':>6} {'Block':>6} {'Throt':>6}")
    print(f"  {'-'*18} {'-'*6} {'-'*6} {'-'*6} {'-'*6}")
    
    for actor, data in sorted(RESULTS["actors"].items()):
        sent = data["sent"] or 1
        blk_pct = (data["blocked"] / sent) * 100
        print(f"  {actor:<18} {data['sent']:>6} {data['allowed']:>6} {data['blocked']:>6} {data['throttled']:>6}")
    
    # Verdict
    normal = RESULTS["actors"].get("NormalUser", {})
    if normal.get("blocked", 0) == 0:
        print("\n  [OK] Normal users NOT blocked (GOOD)")
    else:
        print(f"\n  [X] Normal users blocked {normal['blocked']} times (FALSE POSITIVE)")
    
    attackers_blocked = sum(d["blocked"] + d["throttled"] for a, d in RESULTS["actors"].items() if a != "NormalUser")
    if attackers_blocked > 0:
        print(f"  [OK] Attackers blocked/throttled {attackers_blocked} times (GOOD)")
    else:
        print("  [X] No attackers blocked (detection may be too slow)")
    
    print("=" * 60 + "\n")

# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════
def main():
    p = argparse.ArgumentParser(description="API Attack Simulator")
    p.add_argument("--target", default=DEFAULT_TARGET)
    p.add_argument("--duration", type=int, default=90)
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--no-normal", action="store_true")
    args = p.parse_args()
    
    print("\n" + "=" * 60)
    print("  API Attack Simulator - Behavioral Testing")
    print(f"  Target:    {args.target}")
    print(f"  Duration:  {args.duration}s")
    print(f"  Threads:   {args.threads}")
    print("=" * 60)
    
    # Test connectivity
    try:
        req = request.Request(f"{args.target}/api/health")
        resp = request.urlopen(req, timeout=10)
        print(f"  Target reachable: {resp.status}\n")
    except Exception as e:
        print(f"  ERROR: Cannot reach target: {e}")
        print("  Start the detection engine first: npm run dev")
        sys.exit(1)
    
    print("  Starting attack threads...\n")
    
    threads = []
    
    if not args.no_normal:
        threads.append(threading.Thread(target=normal_user, args=(args.target, args.duration)))
    
    # Attack profiles
    attacks = [slow_creds, smart_scraper, distributed_enum, mixed_behavior]
    for i in range(args.threads):
        fn = attacks[i % len(attacks)]
        threads.append(threading.Thread(target=fn, args=(args.target, args.duration)))
    
    start = time.time()
    for t in threads:
        t.start()
    
    # Progress
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(10)
            elapsed = int(time.time() - start)
            print(f"  [{elapsed:>3}s] Total: {RESULTS['total']:>4} | Allow: {RESULTS['allowed']:>4} | Block: {RESULTS['blocked']:>3} | Throt: {RESULTS['throttled']:>3}")
    except KeyboardInterrupt:
        print("\n  Stopping...")
    
    for t in threads:
        t.join(timeout=3)
    
    report()

if __name__ == "__main__":
    main()
