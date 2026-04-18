// src/enforcement/userReputation.js
// ═══════════════════════════════════════════════════════════════
// User Reputation Tracking for Email Firewall
//
// Tracks user behavior patterns including IP associations,
// email sending rates, and recipient counts to detect anomalies.
// ═══════════════════════════════════════════════════════════════

class UserReputation {
  constructor() {
    this.users = new Map(); // userId → UserProfile
    this.defaultTTL = 24 * 60 * 60 * 1000; // 24 hours for reputation data
  }

  getUserId(email) {
    return email?.toLowerCase().trim() || null;
  }

  getOrCreateUser(email) {
    const userId = this.getUserId(email);
    if (!userId) return null;

    if (!this.users.has(userId)) {
      this.users.set(userId, {
        userId,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        knownIPs: new Set(),
        totalEmailsSent: 0,
        recentEmails: [], // { timestamp, recipients: [], cc: [], bcc: [] }
        recentIPChanges: [],
        sessionCount: 0,
      });
    }

    const user = this.users.get(userId);
    user.lastSeen = Date.now();
    return user;
  }

  recordEmail(userId, ip, emailData) {
    const user = this.getOrCreateUser(userId);
    if (!user) return null;

    const entry = {
      timestamp: Date.now(),
      ip,
      recipients: emailData.recipients || [],
      cc: emailData.cc || [],
      bcc: emailData.bcc || [],
      subject: emailData.subject || '',
      hasAttachments: emailData.hasAttachments || false,
    };

    user.recentEmails.push(entry);
    user.totalEmailsSent++;

    // Keep only last 1000 entries
    if (user.recentEmails.length > 1000) {
      user.recentEmails = user.recentEmails.slice(-1000);
    }

    // Track IP if new
    if (ip && !user.knownIPs.has(ip)) {
      user.recentIPChanges.push({
        ip,
        timestamp: Date.now(),
        isNew: true,
      });

      // Keep only last 20 IP changes
      if (user.recentIPChanges.length > 20) {
        user.recentIPChanges = user.recentIPChanges.slice(-20);
      }
    }

    return user;
  }

  recordLogin(userId, ip) {
    const user = this.getOrCreateUser(userId);
    if (!user) return null;

    if (ip) {
      user.knownIPs.add(ip);
    }
    user.sessionCount++;

    return user;
  }

  isKnownIP(userId, ip) {
    const user = this.users.get(userId);
    if (!user) return false;
    return user.knownIPs.has(ip);
  }

  isNewIP(userId, ip) {
    return !this.isKnownIP(userId, ip);
  }

  getEmailsPerHour(userId) {
    const user = this.users.get(userId);
    if (!user || user.recentEmails.length === 0) return 0;

    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    const recent = user.recentEmails.filter(e => e.timestamp > oneHourAgo);
    return recent.length;
  }

  getRecipientsPerEmail(userId) {
    const user = this.users.get(userId);
    if (!user || user.recentEmails.length === 0) return 0;

    const recent = user.recentEmails.slice(-10);
    let total = 0;
    for (const email of recent) {
      total += (email.recipients?.length || 0) +
               (email.cc?.length || 0) +
               (email.bcc?.length || 0);
    }
    return Math.round(total / Math.max(recent.length, 1));
  }

  getUniqueRecipients24h(userId) {
    const user = this.users.get(userId);
    if (!user) return 0;

    const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
    const recent = user.recentEmails.filter(e => e.timestamp > oneDayAgo);

    const allRecipients = new Set();
    for (const email of recent) {
      for (const r of email.recipients || []) allRecipients.add(r);
      for (const r of email.cc || []) allRecipients.add(r);
      for (const r of email.bcc || []) allRecipients.add(r);
    }
    return allRecipients.size;
  }

  getRecentBCCMax(userId) {
    const user = this.users.get(userId);
    if (!user || user.recentEmails.length === 0) return 0;

    const recent = user.recentEmails.slice(-100);
    let max = 0;
    for (const email of recent) {
      const bccCount = email.bcc?.length || 0;
      if (bccCount > max) max = bccCount;
    }
    return max;
  }

  computeReputationScore(userId, ip) {
    const user = this.users.get(userId);
    if (!user) return 50; // Unknown user = medium risk

    let score = 50; // Base score

    // Factor: Known IP association
    if (user.knownIPs.has(ip)) {
      score -= 25; // Significant trust bonus
    } else if (user.knownIPs.size > 0) {
      score += 15; // Has history but this is new IP
    }

    // Factor: Account age (older = more trusted)
    const ageDays = (Date.now() - user.firstSeen) / (24 * 60 * 60 * 1000);
    if (ageDays > 30) score -= 15;
    else if (ageDays > 7) score -= 10;
    else if (ageDays > 1) score -= 5;

    // Factor: Volume history
    if (user.totalEmailsSent > 10000) score -= 15;
    else if (user.totalEmailsSent > 1000) score -= 10;
    else if (user.totalEmailsSent > 100) score -= 5;

    // Factor: High volume warnings
    const emailsPerHour = this.getEmailsPerHour(userId);
    if (emailsPerHour > 500) score += 30;
    else if (emailsPerHour > 200) score += 20;
    else if (emailsPerHour > 100) score += 10;

    // Factor: BCC abuse
    const maxBCC = this.getRecentBCCMax(userId);
    if (maxBCC > 50) score += 40;
    else if (maxBCC > 20) score += 20;

    return Math.max(0, Math.min(100, score));
  }

  getUserProfile(userId) {
    const user = this.users.get(userId);
    if (!user) return null;

    return {
      userId: user.userId,
      firstSeen: user.firstSeen,
      lastSeen: user.lastSeen,
      knownIPCount: user.knownIPs.size,
      totalEmailsSent: user.totalEmailsSent,
      recentEmailsCount: user.recentEmails.length,
      sessionCount: user.sessionCount,
      emailsPerHour: this.getEmailsPerHour(userId),
      recipientsPerEmail: this.getRecipientsPerEmail(userId),
      uniqueRecipients24h: this.getUniqueRecipients24h(userId),
    };
  }

  getAllUsers() {
    return Array.from(this.users.keys());
  }

  cleanup() {
    const now = Date.now();
    const oneDayAgo = now - (24 * 60 * 60 * 1000);

    for (const [userId, user] of this.users) {
      if (user.lastSeen < oneDayAgo) {
        this.users.delete(userId);
      }
    }
  }

  get size() {
    return this.users.size;
  }
}

const userReputation = new UserReputation();
export default userReputation;