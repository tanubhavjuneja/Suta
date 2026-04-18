// src/enforcement/ipBlocklist.js
// ═══════════════════════════════════════════════════════════════
// Sandbox IP Blocklist — blocks IPs ONLY within the test
// environment. Does NOT touch system firewall or iptables.
// ═══════════════════════════════════════════════════════════════

class IPBlocklist {
  constructor() {
    this.blocked = new Map(); // ip → { actorId, reason, score, blockedAt, expiresAt }
    this.defaultTTL = 15 * 60 * 1000; // 15 minutes
  }

  block(ip, actorId, reason, score, ttlMs = this.defaultTTL) {
    const entry = {
      ip,
      actorId,
      reason,
      score,
      blockedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + ttlMs).toISOString(),
      expiresAtMs: Date.now() + ttlMs,
    };
    this.blocked.set(ip, entry);
    return entry;
  }

  unblock(ip) {
    return this.blocked.delete(ip);
  }

  isBlocked(ip) {
    const entry = this.blocked.get(ip);
    if (!entry) return false;
    if (Date.now() > entry.expiresAtMs) {
      this.blocked.delete(ip);
      return false;
    }
    return true;
  }

  getEntry(ip) {
    if (!this.isBlocked(ip)) return null;
    return this.blocked.get(ip);
  }

  getAll() {
    this.cleanup();
    return Array.from(this.blocked.values());
  }

  cleanup() {
    const now = Date.now();
    for (const [ip, entry] of this.blocked) {
      if (now > entry.expiresAtMs) this.blocked.delete(ip);
    }
  }

  get size() {
    this.cleanup();
    return this.blocked.size;
  }
}

const ipBlocklist = new IPBlocklist();
export default ipBlocklist;
