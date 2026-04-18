// src/ingestion/emailFingerprintGenerator.js
// ═══════════════════════════════════════════════════════════════
// Generates user fingerprints for email firewall
//
// Identifies users based on email authentication (SMTP auth or webmail session)
// rather than network-level signals. Tracks user+IP associations.
// ═══════════════════════════════════════════════════════════════
import { createHash } from 'crypto';

export function generateUserFingerprint(email, ip) {
  const signals = [];

  // Primary: email address (normalized)
  signals.push(email?.toLowerCase().trim() || 'unknown');

  // Secondary: IP if available
  if (ip) signals.push(ip);

  const raw = signals.join('|||');
  const hash = createHash('sha256').update(raw).digest('hex');

  return hash.substring(0, 12);
}

export function generateSessionFingerprint(req) {
  const signals = [];

  // Session-based fingerprint from webmail or SMTP session
  signals.push(req.headers['x-session-id'] || req.headers['cookie'] || 'no-session');
  signals.push(req.headers['x-user-id'] || 'unknown');

  // Client IP from various sources
  const forwarded = req.headers['x-forwarded-for'];
  const realIp = req.headers['x-real-ip'];
  signals.push(forwarded || realIp || 'unknown');

  // User agent for session continuity
  signals.push(req.headers['user-agent'] || 'no-ua');

  const raw = signals.join('|||');
  const hash = createHash('sha256').update(raw).digest('hex');

  return hash.substring(0, 12);
}

export function extractClientIP(req) {
  // Check X-Forwarded-For header (common for proxies/load balancers)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // Take first IP if multiple are listed
    return forwarded.split(',')[0].trim();
  }

  // Check X-Real-IP header (nginx proxy)
  const realIp = req.headers['x-real-ip'];
  if (realIp) return realIp;

  // Fall back to remote address from the request object
  return req.socket?.remoteAddress || 'unknown';
}

export function parseEmailHeaders(req) {
  return {
    from: req.headers['from'] || '',
    to: req.headers['to'] || '',
    cc: req.headers['cc'] || '',
    bcc: req.headers['bcc'] || '',
    subject: req.headers['subject'] || '',
    replyTo: req.headers['reply-to'] || '',
    'x-sender-ip': req.headers['x-sender-ip'] || extractClientIP(req),
    'x-authenticated-user': req.headers['x-authenticated-user'] || '',
  };
}