// src/enforcement/emailBlocklist.js
// ═══════════════════════════════════════════════════════════════
// Email Server Blocklist — extends blocking for email-specific use
//
// Blocks email senders based on user, IP, domain with admin trust support.
// ═══════════════════════════════════════════════════════════════════════

import userReputation from './userReputation.js';

class EmailBlocklist {
  constructor() {
    this.blockedUsers = new Map();
    this.blockedIPs = new Map();
    this.blockedDomains = new Map();
    this.monitoring = new Map();
    this.defaultTTL = 15 * 60 * 1000;
  }

  blockUser(userId, reason, score, ttlMs = this.defaultTTL) {
    if (userReputation.isUserTrustedByAdmin(userId)) {
      return { userId, action: 'ignored', reason: 'Admin trusted user' };
    }

    const entry = {
      userId,
      reason,
      score,
      blockedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + ttlMs).toISOString(),
      expiresAtMs: Date.now() + ttlMs,
    };
    this.blockedUsers.set(userId, entry);
    userReputation.recordMaliciousActivity(userId, score, reason);
    return entry;
  }

  blockIP(ip, userId, reason, score, ttlMs = this.defaultTTL) {
    if (userReputation.isIPTrustedByAdmin(ip)) {
      return { ip, action: 'ignored', reason: 'Admin trusted IP' };
    }

    const entry = {
      ip,
      userId,
      reason,
      score,
      blockedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + ttlMs).toISOString(),
      expiresAtMs: Date.now() + ttlMs,
    };
    this.blockedIPs.set(ip, entry);
    if (userId) {
      userReputation.recordMaliciousActivity(userId, score, `${reason} (IP: ${ip})`);
    }
    return entry;
  }

  blockDomain(domain, reason, score, ttlMs = this.defaultTTL) {
    const entry = {
      domain: domain.toLowerCase(),
      reason,
      score,
      blockedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + ttlMs).toISOString(),
      expiresAtMs: Date.now() + ttlMs,
    };
    this.blockedDomains.set(domain.toLowerCase(), entry);
    return entry;
  }

  unblockUser(userId) {
    return this.blockedUsers.delete(userId);
  }

  unblockIP(ip) {
    return this.blockedIPs.delete(ip);
  }

  unblockDomain(domain) {
    return this.blockedDomains.delete(domain);
  }

  isUserBlocked(userId) {
    const entry = this.blockedUsers.get(userId);
    if (!entry) return false;
    if (Date.now() > entry.expiresAtMs) {
      this.blockedUsers.delete(userId);
      return false;
    }
    return true;
  }

  isIPBlocked(ip) {
    const entry = this.blockedIPs.get(ip);
    if (!entry) return false;
    if (Date.now() > entry.expiresAtMs) {
      this.blockedIPs.delete(ip);
      return false;
    }
    return true;
  }

  isDomainBlocked(domain) {
    const entry = this.blockedDomains.get(domain.toLowerCase());
    if (!entry) return false;
    if (Date.now() > entry.expiresAtMs) {
      this.blockedDomains.delete(domain.toLowerCase());
      return false;
    }
    return true;
  }

  getUserEntry(userId) {
    if (!this.isUserBlocked(userId)) return null;
    return this.blockedUsers.get(userId);
  }

  getIPEntry(ip) {
    if (!this.isIPBlocked(ip)) return null;
    return this.blockedIPs.get(ip);
  }

  getDomainEntry(domain) {
    if (!this.isDomainBlocked(domain)) return null;
    return this.blockedDomains.get(domain.toLowerCase());
  }

  addMonitoring(userId, data) {
    const entry = {
      userId,
      ...data,
      startedAt: new Date().toISOString(),
      lastActivity: new Date().toISOString(),
      emailCount: (data.emailCount || 0),
      recipientCount: (data.recipientCount || 0),
    };
    this.monitoring.set(userId, entry);
    return entry;
  }

  updateMonitoring(userId, updates) {
    const existing = this.monitoring.get(userId);
    if (!existing) return this.addMonitoring(userId, updates);

    const updated = {
      ...existing,
      ...updates,
      lastActivity: new Date().toISOString(),
    };
    this.monitoring.set(userId, updated);
    return updated;
  }

  getMonitoring(userId) {
    return this.monitoring.get(userId);
  }

  isMonitoring(userId) {
    return this.monitoring.has(userId);
  }

  getAllBlocked() {
    this.cleanup();
    return {
      users: Array.from(this.blockedUsers.values()),
      ips: Array.from(this.blockedIPs.values()),
      domains: Array.from(this.blockedDomains.values()),
    };
  }

  getAllMonitoring() {
    return Array.from(this.monitoring.values());
  }

  cleanup() {
    const now = Date.now();
    for (const [userId, entry] of this.blockedUsers) {
      if (now > entry.expiresAtMs) this.blockedUsers.delete(userId);
    }
    for (const [ip, entry] of this.blockedIPs) {
      if (now > entry.expiresAtMs) this.blockedIPs.delete(ip);
    }
    for (const [domain, entry] of this.blockedDomains) {
      if (now > entry.expiresAtMs) this.blockedDomains.delete(domain);
    }
  }

  get size() {
    this.cleanup();
    return {
      users: this.blockedUsers.size,
      ips: this.blockedIPs.size,
      domains: this.blockedDomains.size,
      monitoring: this.monitoring.size,
    };
  }
}

const emailBlocklist = new EmailBlocklist();
export default emailBlocklist;