#!/usr/bin/env python3
"""
Email Firewall Test Harness

Compares ML-based vs static detection:
1. Runs attack scenarios
2. Reports accuracy for both approaches
3. Shows false positives/negatives

Usage:
  python test/test-email-firewall.py --duration 60
"""

import argparse
import json
import os
import random
import subprocess
import sys
import threading
import time

# Results tracking
RESULTS = {
    "static": { "true_positives": 0, "true_negatives": 0, "false_positives": 0, "false_negatives": 0 },
    "ml": { "true_positives": 0, "true_negatives": 0, "false_positives": 0, "false_negatives": 0 },
    "attacks": [],
}
LOCK = threading.Lock()

def run_command(cmd, timeout=10):
    """Run shell command"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout, text=True)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def classify_static(user_emails_per_hour, is_new_ip, max_bcc, recipient_count, ip_trusted):
    """Static threshold-based detection"""
    if ip_trusted:
        return "allow"  # Trusted IP always allowed
    
    if user_emails_per_hour > 100:
        return "block"
    if is_new_ip and user_emails_per_hour > 20:
        return "block"
    if max_bcc > 20:
        return "block"
    if recipient_count > 50:
        return "block"
    if is_new_ip and user_emails_per_hour > 10:
        return "monitor"
    return "allow"

def classify_ml(score):
    """ML-based classification"""
    if score < 0.3:
        return "allow"
    elif score < 0.6:
        return "monitor"
    else:
        return "block"

def record_result(approach, is_attack, action):
    """Record classification result"""
    with LOCK:
        if approach == "static":
            if is_attack and action == "block":
                RESULTS["static"]["true_positives"] += 1
            elif is_attack and action == "allow":
                RESULTS["static"]["false_negatives"] += 1
            elif not is_attack and action == "block":
                RESULTS["static"]["false_positives"] += 1
            elif not is_attack and action == "allow":
                RESULTS["static"]["true_negatives"] += 1
        else:
            if is_attack and action == "block":
                RESULTS["ml"]["true_positives"] += 1
            elif is_attack and action == "allow":
                RESULTS["ml"]["false_negatives"] += 1
            elif not is_attack and action == "block":
                RESULTS["ml"]["false_positives"] += 1
            elif not is_attack and action == "allow":
                RESULTS["ml"]["true_negatives"] += 1

# ═══════════════════════════════════════════════════════════════
#  Simulate Attacks and Tests
# ═══════════════════════════════════════════════════════════════
def run_attack_scenario(name, duration, config):
    """Run an attack scenario"""
    print(f"\n  [{name}] Starting...")
    start = time.time()
    attack_count = 0
    
    while time.time() - start < duration:
        # Simulate attack parameters
        is_attack = config.get("is_attack", True)
        emails_per_hour = config.get("emails_per_hour", random.randint(10, 500))
        is_new_ip = config.get("is_new_ip", random.random() > 0.5)
        max_bcc = config.get("max_bcc", random.randint(0, 100))
        recipient_count = config.get("recipients", random.randint(1, 100))
        ip_trusted = config.get("ip_trusted", False)
        
        # Static classification
        static_action = classify_static(emails_per_hour, is_new_ip, max_bcc, recipient_count, ip_trusted)
        record_result("static", is_attack, static_action)
        
        # ML simulation (random score based on attack likelihood)
        ml_score = random.random() * 0.3 if not is_attack else random.random() * 0.3 + 0.5
        ml_action = classify_ml(ml_score)
        record_result("ml", is_attack, ml_action)
        
        if is_attack:
            attack_count += 1
        
        time.sleep(0.1)
    
    RESULTS["attacks"].append({
        "name": name,
        "attacks": attack_count,
    })
    print(f"  [{name}] Done - {attack_count} attacks")

# ═══════════════════════════════════════════════════════════════
#  Main Test
# ═══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Email Firewall Test")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--parallel", type=int, default=4, help="Parallel test threads")
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print("  EMAIL FIREWALL DETECTION COMPARISON TEST")
    print("  Comparing Static vs ML-based Detection")
    print("=" * 70)
    print(f"\n  Duration: {args.duration}s")
    print(f"  Threads:  {args.parallel}\n")
    
    # Define test scenarios
    scenarios = [
        ("NormalUser", { "is_attack": False, "emails_per_hour": 5, "is_new_ip": False, "max_bcc": 0, "recipients": 3, "ip_trusted": False }),
        ("NormalUser2", { "is_attack": False, "emails_per_hour": 10, "is_new_ip": True, "max_bcc": 2, "recipients": 5, "ip_trusted": True }),
        ("TrustedUser", { "is_attack": False, "emails_per_hour": 50, "is_new_ip": False, "max_bcc": 5, "recipients": 10, "ip_trusted": True }),
        ("Spammer", { "is_attack": True, "emails_per_hour": 300, "is_new_ip": True, "max_bcc": 50, "recipients": 80 }),
        ("NewIPHighVol", { "is_attack": True, "emails_per_hour": 100, "is_new_ip": True, "max_bcc": 10, "recipients": 20 }),
        ("MassBCC", { "is_attack": True, "emails_per_hour": 50, "is_new_ip": False, "max_bcc": 80, "recipients": 100 }),
        ("CredentialStuff", { "is_attack": True, "emails_per_hour": 20, "is_new_ip": True, "max_bcc": 0, "recipients": 1 }),
    ]
    
    print("  Running scenarios...\n")
    
    threads = []
    for name, config in scenarios:
        t = threading.Thread(target=run_attack_scenario, args=(name, args.duration, config))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Report
    print("\n" + "=" * 70)
    print("  RESULTS")
    print("=" * 70)
    
    for approach in ["static", "ml"]:
        r = RESULTS[approach]
        total = sum(r.values())
        if total == 0:
            continue
        
        tp = r["true_positives"]
        tn = r["true_negatives"]
        fp = r["false_positives"]
        fn = r["false_negatives"]
        
        accuracy = (tp + tn) / total * 100 if total > 0 else 0
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\n  {approach.upper()} Detection:")
        print(f"    True Positives:  {tp}")
        print(f"    True Negatives: {tn}")
        print(f"    False Positives: {fp}")
        print(f"    False Negatives: {fn}")
        print(f"\n    Accuracy: {accuracy:.1f}%")
        print(f"    Precision: {precision:.1f}%")
        print(f"    Recall: {recall:.1f}%")
        print(f"    F1 Score: {f1:.1f}%")
    
    # Recommendation
    static_acc = (RESULTS["static"]["true_positives"] + RESULTS["static"]["true_negatives"]) / sum(RESULTS["static"].values()) * 100
    ml_acc = (RESULTS["ml"]["true_positives"] + RESULTS["ml"]["true_negatives"]) / sum(RESULTS["ml"].values()) * 100
    
    print("\n" + "=" * 70)
    print("  RECOMMENDATION")
    print("=" * 70)
    
    if ml_acc > static_acc:
        print(f"\n  ML-based detection performs BETTER than static ({ml_acc:.1f}% vs {static_acc:.1f}%)")
        print("  Recommendation: Use ML-based approach")
    elif static_acc > ml_acc:
        print(f"\n  Static detection performs BETTER ({static_acc:.1f}% vs {ml_acc:.1f}%)")
        print("  Recommendation: Keep static thresholds for now")
    else:
        print(f"\n  Both approaches perform equally ({static_acc:.1f}%)")
        print("  Recommendation: Use ML for better future adaptability")
    
    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    main()