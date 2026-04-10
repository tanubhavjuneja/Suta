#!/usr/bin/env python3
"""
attack_sim.py — Multi-threaded API Attack Simulator with IP Masking
═══════════════════════════════════════════════════════════════

Simulates realistic attack scenarios using X-Forwarded-For IP masking.
Each attacker runs in its own thread with distinct behavioral patterns.

Usage:
  python attack_sim.py                            # Default: http://localhost:3000, 60s
  python attack_sim.py --target http://localhost:4000  # Via test server proxy
  python attack_sim.py --duration 120             # 2 minute run
  python attack_sim.py --threads 8                # More concurrent attackers

Attacker Profiles:
  [Control] Normal User  — slow, diverse, authenticated, real browser UA
  [Attack]  CredStuffer  — rapid POST /login, rotating creds, masked IPs
  [Attack]  DataScraper  — sequential /users/N/profile, consistent timing
  [Attack]  BruteForcer  — ultra-fast /login, curl UA, IP rotation per batch
  [Attack]  Enumerator   — systematic /products/N, no auth, rotating IPs
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

# ── Globals ───────────────────────────────────────────────────
DEFAULT_TARGET = "http://localhost:3000"
RESULTS_LOCK = threading.Lock()
PRINT_LOCK = threading.Lock()

results = {
    "total": 0,
    "allowed": 0,
    "blocked": 0,
    "throttled": 0,
    "errors": 0,
    "per_actor": {},
}

# ── IP Pool for masking ───────────────────────────────────────
def random_ip():
    """Generate a random public IP for X-Forwarded-For spoofing."""
    # Avoid private ranges
    while True:
        octets = [random.randint(1, 254) for _ in range(4)]
        if octets[0] not in (10, 127) and not (octets[0] == 172 and 16 <= octets[1] <= 31) and not (octets[0] == 192 and octets[1] == 168):
            return '.'.join(str(o) for o in octets)

def random_ip_from_subnet(base, count=1):
    """Generate IPs from a specific subnet for consistent actor fingerprint."""
    parts = base.split('.')
    ips = []
    for _ in range(count):
        # Pad to 4 octets if needed
        while len(parts) < 4:
            parts.append('0')
        p = parts[:]
        p[3] = str(random.randint(1, 254))
        ips.append('.'.join(p))
    return ips

# ── Logging ───────────────────────────────────────────────────
def log(actor_name, icon, message):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with PRINT_LOCK:
        try:
            print(f"  [{ts}] {icon} [{actor_name}] {message}")
        except UnicodeEncodeError:
            print(f"  [{ts}] [{actor_name}] {message}")

# ── HTTP Request Helper ──────────────────────────────────────
def do_request(target, method, path, headers=None, body=None, actor_name="unknown"):
    url = f"{target}{path}"
    hdrs = headers or {}
    hdrs["Content-Type"] = "application/json"

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

    with RESULTS_LOCK:
        results["total"] += 1
        if actor_name not in results["per_actor"]:
            results["per_actor"][actor_name] = {"sent": 0, "allowed": 0, "blocked": 0, "throttled": 0}
        actor = results["per_actor"][actor_name]
        actor["sent"] += 1

        if status == 403:
            results["blocked"] += 1
            actor["blocked"] += 1
        elif status == 429:
            results["throttled"] += 1
            actor["throttled"] += 1
        elif 200 <= status < 400:
            results["allowed"] += 1
            actor["allowed"] += 1
        else:
            results["errors"] += 1

    return status


# ═══════════════════════════════════════════════════════════════
#  NORMAL USER — Control group (should NEVER be blocked)
# ═══════════════════════════════════════════════════════════════
def normal_user(target, duration):
    name = "NormalUser"
    # Single consistent IP — real user
    my_ip = "203.45.67.89"
    log(name, "U", f"Starting -- consistent IP: {my_ip}, browser UA, authenticated")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.validtoken.signature",
        "Cache-Control": "no-cache",
        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Referer": "https://shop.example.com/browse",
        "X-Forwarded-For": my_ip,
        "X-Real-IP": my_ip,
    }

    # Realistic browsing: diverse endpoints, organic timing
    endpoints = [
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

    start = time.time()
    count = 0
    while time.time() - start < duration:
        method, path = endpoints[count % len(endpoints)]
        status = do_request(target, method, path, headers, actor_name=name)
        count += 1
        if count % 3 == 0:
            log(name, "U", f"req #{count} -> {status} ({method} {path})")
        if status == 403:
            log(name, "!", f"FALSE POSITIVE! Normal user blocked at req #{count}!")
        # Human-like: 3-10 second gaps
        time.sleep(random.uniform(3.0, 10.0))

    log(name, "U", f"Done -- {count} requests, all should be allowed")


# ═══════════════════════════════════════════════════════════════
#  CREDENTIAL STUFFER — Rotating IPs per batch
# ═══════════════════════════════════════════════════════════════
def credential_stuffer(target, duration, thread_id=0):
    name = f"CredStuff-{thread_id}"
    # Use a pool of IPs, rotating every 10 requests
    ip_pool = [random_ip() for _ in range(20)]
    current_ip_idx = 0
    log(name, "X", f"Starting -- {len(ip_pool)} masked IPs, rapid /login")

    usernames = [f"admin{i}@corp.com" for i in range(1, 500)]
    passwords = ["password123", "123456", "admin", "letmein", "welcome1",
                 "monkey", "dragon", "master", "qwerty", "abc123",
                 "P@ssw0rd!", "admin123", "root", "test123"]

    start = time.time()
    count = 0
    batch = 0
    while time.time() - start < duration:
        # Rotate IP every 10 requests
        if count % 10 == 0:
            current_ip_idx = (current_ip_idx + 1) % len(ip_pool)
            batch += 1

        ip = ip_pool[current_ip_idx]
        headers = {
            "User-Agent": "python-requests/2.31.0",
            "Accept": "*/*",
            "X-Forwarded-For": ip,
            "X-Real-IP": ip,
        }

        body = {
            "username": random.choice(usernames),
            "password": random.choice(passwords),
        }

        status = do_request(target, "POST", "/api/auth/login", headers, body, actor_name=name)
        count += 1

        if status == 403:
            log(name, "!", f"BLOCKED at attempt #{count} (IP: {ip})")
            time.sleep(3)
        elif count % 25 == 0:
            log(name, "X", f"attempt #{count} -> {status} (batch #{batch}, IP: {ip})")

        # Bot-like: 50-150ms
        time.sleep(random.uniform(0.05, 0.15))

    log(name, "X", f"Done -- {count} attempts across {len(ip_pool)} IPs")


# ═══════════════════════════════════════════════════════════════
#  DATA SCRAPER — Sequential enumeration with consistent timing
# ═══════════════════════════════════════════════════════════════
def data_scraper(target, duration, thread_id=0):
    name = f"Scraper-{thread_id}"
    # Scrapers often use a small pool of proxy IPs
    ip_pool = random_ip_from_subnet("45.33.32", 5)
    log(name, "S", f"Starting -- sequential /users/N/profile, {len(ip_pool)} proxy IPs")

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; DataMiner/2.0; +http://scraper.example.com)",
        "Accept": "application/json",
        "Authorization": "Bearer stolen_api_key_abc123xyz",
        "X-Forwarded-For": ip_pool[0],
        "X-Real-IP": ip_pool[0],
    }

    start = time.time()
    user_id = random.randint(1, 20)
    count = 0
    while time.time() - start < duration:
        # Rotate IPs every 30 requests
        if count % 30 == 0:
            ip = random.choice(ip_pool)
            headers["X-Forwarded-For"] = ip
            headers["X-Real-IP"] = ip

        status = do_request(target, "GET", f"/api/users/{user_id}/profile", headers, actor_name=name)
        count += 1
        user_id += 1

        if status == 403:
            log(name, "!", f"BLOCKED at profile #{user_id} (count: {count})")
            time.sleep(5)
        elif count % 40 == 0:
            log(name, "S", f"scraped {count} profiles (up to user #{user_id})")

        # Consistent bot timing: ~100-130ms
        time.sleep(random.uniform(0.10, 0.13))

    log(name, "S", f"Done -- {count} profiles scraped")


# ═══════════════════════════════════════════════════════════════
#  BRUTE FORCER — Ultra fast with IP rotation per request
# ═══════════════════════════════════════════════════════════════
def brute_forcer(target, duration, thread_id=0):
    name = f"Brute-{thread_id}"
    log(name, "B", f"Starting -- ultra-fast /login, new IP every 5 reqs")

    target_user = "admin@company.com"

    start = time.time()
    count = 0
    while time.time() - start < duration:
        # New IP every 5 requests
        ip = random_ip()
        headers = {
            "User-Agent": "curl/8.4.0",
            "Accept": "*/*",
            "X-Forwarded-For": ip,
            "X-Real-IP": ip,
        }

        for _ in range(5):
            if time.time() - start >= duration:
                break
            pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(6, 12)))
            body = {"username": target_user, "password": pwd}
            status = do_request(target, "POST", "/api/auth/login", headers, body, actor_name=name)
            count += 1

            if status == 403:
                log(name, "!", f"BLOCKED at attempt #{count}")
                time.sleep(5)
                break
            elif count % 40 == 0:
                log(name, "B", f"attempt #{count} -> {status}")

            # Ultra fast: 20-50ms
            time.sleep(random.uniform(0.02, 0.05))

    log(name, "B", f"Done -- {count} brute force attempts")


# ═══════════════════════════════════════════════════════════════
#  ENUMERATOR — Systematic product/user enumeration
# ═══════════════════════════════════════════════════════════════
def enumerator(target, duration, thread_id=0):
    name = f"Enum-{thread_id}"
    ip_pool = [random_ip() for _ in range(8)]
    log(name, "E", f"Starting -- systematic /products/N scan, {len(ip_pool)} IPs")

    start = time.time()
    product_id = 1
    count = 0
    while time.time() - start < duration:
        ip = ip_pool[count % len(ip_pool)]
        headers = {
            "User-Agent": "curl/8.4.0",
            "Accept": "*/*",
            "X-Forwarded-For": ip,
            "X-Real-IP": ip,
        }

        # Alternate between products and users
        if count % 3 == 0:
            path = f"/api/users/{product_id}"
        else:
            path = f"/api/products/{product_id}"
        
        status = do_request(target, "GET", path, headers, actor_name=name)
        count += 1
        product_id += 1

        if status == 403:
            log(name, "!", f"BLOCKED at item #{product_id}")
            time.sleep(5)
        elif count % 40 == 0:
            log(name, "E", f"enumerated {count} items")

        # Moderate speed: 100-200ms
        time.sleep(random.uniform(0.1, 0.2))

    log(name, "E", f"Done -- {count} items enumerated")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════
def print_report():
    total = results['total'] or 1
    blocked = results['blocked']
    allowed = results['allowed']

    print("\n")
    print("=" * 65)
    print("  ATTACK SIMULATION REPORT")
    print("=" * 65)
    print(f"\n  Total Requests:  {results['total']}")
    print(f"  Allowed:         {allowed}")
    print(f"  Blocked:         {blocked}")
    print(f"  Throttled:       {results['throttled']}")
    print(f"  Errors:          {results['errors']}")
    print(f"\n  Block Rate:      {(blocked/total)*100:.1f}%")
    print(f"\n  {'Actor':<22} {'Sent':>6} {'Allow':>6} {'Block':>6} {'Throt':>6} {'Blk%':>6}")
    print(f"  {'-'*22} {'-'*6} {'-'*6} {'-'*6} {'-'*6} {'-'*6}")

    for actor, data in sorted(results["per_actor"].items()):
        sent = data['sent'] or 1
        blk_pct = (data['blocked'] / sent) * 100
        marker = " <-- OK" if "Normal" in actor and data['blocked'] == 0 else ""
        marker = " <-- BLOCKED!" if "Normal" in actor and data['blocked'] > 0 else marker
        print(f"  {actor:<22} {data['sent']:>6} {data['allowed']:>6} {data['blocked']:>6} {data['throttled']:>6} {blk_pct:>5.1f}%{marker}")

    print("\n" + "=" * 65)

    # Summary verdict
    normal = results["per_actor"].get("NormalUser", {})
    if normal.get("blocked", 0) == 0:
        print("  PASS: Normal user was never blocked")
    else:
        print(f"  FAIL: Normal user was blocked {normal['blocked']} times (FALSE POSITIVE)")

    attacker_blocked = sum(d["blocked"] for name, d in results["per_actor"].items() if "Normal" not in name)
    if attacker_blocked > 0:
        print(f"  PASS: Attackers were blocked {attacker_blocked} times total")
    else:
        print("  WARN: No attackers were blocked (engine may need tuning)")

    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(description="API Attack Simulator with IP Masking")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target server URL")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--threads", type=int, default=6, help="Total attack threads")
    parser.add_argument("--no-normal", action="store_true", help="Skip normal user")
    args = parser.parse_args()

    print("\n")
    print("=" * 65)
    print("  API Attack Simulator v2.0 (Threaded + IP Masking)")
    print(f"  Target:    {args.target}")
    print(f"  Duration:  {args.duration}s")
    print(f"  Threads:   {args.threads} attack + 1 normal")
    print("=" * 65)

    # Connectivity test
    try:
        req = request.Request(f"{args.target}/api/health",
                              headers={"User-Agent": "healthcheck", "X-Forwarded-For": "127.0.0.1"})
        resp = request.urlopen(req, timeout=10)
        print(f"\n  Target reachable (status: {resp.status})\n")
    except Exception as e:
        print(f"\n  Cannot reach target: {e}")
        print(f"  1. npm run dev        (abuse engine on :3000)")
        print(f"  2. npm run test-server (test server on :4000)")
        sys.exit(1)

    print("  Launching threads...")
    print("-" * 65)

    threads = []

    # Normal user — always thread 0
    if not args.no_normal:
        t = threading.Thread(target=normal_user, args=(args.target, args.duration), name="NormalUser")
        threads.append(t)

    # Distribute attack threads across types
    attack_types = [
        (credential_stuffer, 3),   # delay seconds before start
        (data_scraper, 5),
        (brute_forcer, 2),
        (enumerator, 7),
    ]

    thread_id = 0
    for i in range(args.threads):
        attacker_fn, delay = attack_types[i % len(attack_types)]
        tid = thread_id
        thread_id += 1
        actual_delay = delay + (i // len(attack_types)) * 2  # Stagger

        def make_runner(fn, d, t_id):
            def runner():
                time.sleep(d)
                fn(args.target, args.duration - d, t_id)
            return runner

        t = threading.Thread(target=make_runner(attacker_fn, actual_delay, tid))
        threads.append(t)

    start_time = time.time()
    for t in threads:
        t.start()

    # Progress reporting
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(5)
            elapsed = int(time.time() - start_time)
            with RESULTS_LOCK:
                print(f"\n  [{elapsed:>3}s] Total: {results['total']:>4} | Allowed: {results['allowed']:>4} | Blocked: {results['blocked']:>3} | Errors: {results['errors']:>3}\n")
    except KeyboardInterrupt:
        print("\n  Interrupted -- waiting for threads...")

    for t in threads:
        t.join(timeout=5)

    print_report()


if __name__ == "__main__":
    main()
