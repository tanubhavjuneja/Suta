// test_server/email_server.js
// ═══════════════════════════════════════════════════════════════
// Email Test Server with Queue-Based Firewall
// Supports: Throttling queue, Block queue, Admin unblock with release
// ═══════════════════════════════════════════════════════════════
import express from 'express';

const app = express();
const PORT = 2525;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ═══════════════════════════════════════════════════════
// EMAIL QUEUE SYSTEM
// ═══════════════════════════════════════════════════════
const emailQueue = new Map();       // userId -> [{email, queuedAt, attempts}]
const blockedQueue = new Map();     // userId -> [{email, blockedAt, reason}]
const QUEUE_RETENTION_HOURS = 24;  // Configurable in settings

// ═══════════════════════════════════════════════════════
// Queue helper functions
// ═══════════════════════════════════════════════════════
function addToQueue(userId, email) {
  if (!emailQueue.has(userId)) {
    emailQueue.set(userId, []);
  }
  email.queuedAt = Date.now();
  email.attempts = 0;
  emailQueue.get(userId).push(email);
  
  // Limit queue size
  if (emailQueue.get(userId).length > 1000) {
    emailQueue.set(userId, emailQueue.get(userId).slice(-1000));
  }
}

function addToBlockedQueue(userId, email, reason) {
  if (!blockedQueue.has(userId)) {
    blockedQueue.set(userId, []);
  }
  email.blockedAt = Date.now();
  email.reason = reason;
  blockedQueue.get(userId).push(email);
}

function getQueuedEmails(userId) {
  return emailQueue.get(userId) || [];
}

function getBlockedEmails(userId) {
  return blockedQueue.get(userId) || [];
}

function releaseQueue(userId) {
  const queued = emailQueue.get(userId) || [];
  const released = [];
  
  for (const email of queued) {
    // Check if not expired
    const ageHours = (Date.now() - email.queuedAt) / 3600000;
    if (ageHours < QUEUE_RETENTION_HOURS) {
      released.push(email);
    }
  }
  
  // Clear queue
  emailQueue.delete(userId);
  return released;
}

function clearExpiredQueue() {
  const now = Date.now();
  const maxAge = QUEUE_RETENTION_HOURS * 3600000;
  
  for (const [userId, emails] of emailQueue) {
    const valid = emails.filter(e => now - e.queuedAt < maxAge);
    if (valid.length === 0) {
      emailQueue.delete(userId);
    } else {
      emailQueue.set(userId, valid);
    }
  }
  
  for (const [userId, emails] of blockedQueue) {
    const valid = emails.filter(e => now - e.blockedAt < maxAge);
    if (valid.length === 0) {
      blockedQueue.delete(userId);
    } else {
      blockedQueue.set(userId, valid);
    }
  }
}

// Clean expired every 5 minutes
setInterval(clearExpiredQueue, 300000);

// ═══════════════════════════════════════════════════════
// FIREWALL STATE
// ═════════���═════════════════════════════════════════════
const userScores = new Map();
const blockedUsers = new Set();
const trustedUsers = new Set();

// ═══════════════════════════════════════════════════════
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-sender-ip'] ||
         req.socket?.remoteAddress ||
         '127.0.0.1';
}

function assessEmail(userId, ip, emailData) {
  if (!userScores.has(userId)) {
    userScores.set(userId, { totalEmails: 0, recentEmails: [], lastIP: null, ipChanges: [] });
  }
  
  const state = userScores.get(userId);
  const now = Date.now();
  
  // Check if blocked but check queue release
  if (blockedUsers.has(userId)) {
    return { action: 'block', reason: 'Previously blocked', score: 100 };
  }
  
  // Check trusted
  if (trustedUsers.has(userId)) {
    return { action: 'allow', reason: 'Admin trusted', score: 0 };
  }
  
  state.totalEmails++;
  state.recentEmails.push({ timestamp: now });
  if (state.recentEmails.length > 500) state.recentEmails = state.recentEmails.slice(-500);
  
  let score = 0;
  let reasons = [];
  
  // Rapid burst - emails in last 30 seconds
  const recent30s = state.recentEmails.filter(e => now - e.timestamp < 30000).length;
  if (recent30s >= 5) {
    reasons.push('RAPID_BURST');
    score += 50;
  }
  
  // High volume - emails in last 60 seconds
  const recent60s = state.recentEmails.filter(e => now - e.timestamp < 60000).length;
  if (recent60s >= 10) {
    reasons.push('HIGH_60s');
    score += 40;
  }
  
  // High 5 min volume
  const recent5m = state.recentEmails.filter(e => now - e.timestamp < 300000).length;
  if (recent5m >= 30) {
    reasons.push('HIGH_5m');
    score += 30;
  }
  
  // IP change detection
  if (ip !== state.lastIP && state.lastIP !== null) {
    state.ipChanges.push({ oldIP: state.lastIP, newIP: ip, timestamp: now });
    reasons.push('IP_CHANGE');
    score += 15;
  }
  state.lastIP = ip;
  
  // BCC mass
  const bccCount = emailData.bcc?.split(',').filter(Boolean).length || 0;
  if (bccCount >= 10) {
    reasons.push('MASS_BCC');
    score += 35;
  }
  
  // Recipient mass
  const toCount = emailData.to?.split(',').filter(Boolean).length || 0;
  const ccCount = emailData.cc?.split(',').filter(Boolean).length || 0;
  if ((toCount + ccCount + bccCount) >= 30) {
    reasons.push('MASS_RECIPIENTS');
    score += 30;
  }
  
  score = Math.min(100, score);
  
  // Lower thresholds for testing
  let action = 'allow';
  if (score >= 85) {
    action = 'block';
    blockedUsers.add(userId);
  } else if (score >= 40) {
    action = 'throttle';  // Queue instead of block
  } else if (score >= 20 || !state.lastIP) {
    action = 'monitor';
  }
  
  return { action, reason: reasons.join(', ') || 'Normal', score };
}

// ═══════════════════════════════════════════════════════
// Test Users
// ═══════════════════════════════════════════════════════
const testUsers = new Map([
  ['alice@example.com', { password: 'pass123', name: 'Alice' }],
  ['bob@example.com', { password: 'pass456', name: 'Bob' }],
  ['charlie@example.com', { password: 'pass789', name: 'Charlie' }],
  ['david@example.com', { password: 'test999', name: 'David' }],
  ['admin@company.com', { password: 'admin123', name: 'Admin' }],
]);

// ════════════════════════════════════════════════���═��════
// Stats
// ═══════════════════════════════════════════════════════
let stats = { 
  total: 0, 
  sent: 0, 
  blocked: 0, 
  throttled: 0,
  queued: 0,
  released: 0 
};

// ═══════════════════════════════════════════════════════
// Routes
// ═══════════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({ 
  status: 'ok', 
  firewall: 'queue-based',
  queueRetentionHours: QUEUE_RETENTION_HOURS 
}));

app.get('/stats', (req, res) => {
  res.json({
    ...stats,
    queuedEmails: emailQueue.size,
    blockedEmails: blockedQueue.size,
    users: userScores.size,
  });
});

app.post('/stats/reset', (req, res) => {
  stats = { total: 0, sent: 0, blocked: 0, throttled: 0, queued: 0, released: 0 };
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════
// EMAIL SUBMIT
// ═══════════════════════════════════════════════════════
app.post('/api/submit', (req, res) => {
  stats.total++;
  
  const ip = getClientIP(req);
  const auth = req.headers['authorization'];
  
  let userId = 'unknown';
  if (auth?.startsWith('Basic ')) {
    try {
      const [u] = Buffer.from(auth.substring(6), 'base64').toString().split(':');
      userId = u;
    } catch (e) {}
  }
  
  if (!userId) return res.status(530).json({ error: 'Auth required' });
  
  const emailData = {
    to: req.body.to || '',
    cc: req.body.cc || '',
    bcc: req.body.bcc || '',
    subject: req.body.subject || '',
    body: req.body.body || '',
    from: userId,
    ip,
  };
  
  const result = assessEmail(userId, ip, emailData);
  console.log(`[${userId}] Action:${result.action} Score:${result.score}`);
  
  if (result.action === 'block') {
    stats.blocked++;
    addToBlockedQueue(userId, emailData, result.reason);
    return res.status(550).json({ 
      error: 'BLOCKED', 
      reason: result.reason, 
      score: result.score,
      queued: false
    });
  }
  
  if (result.action === 'throttle') {
    stats.throttled++;
    addToQueue(userId, emailData);
    stats.queued++;
    return res.status(429).json({ 
      error: 'THROTTLED', 
      reason: result.reason,
      score: result.score,
      queued: true,
      queuePosition: getQueuedEmails(userId).length,
      message: 'Email queued for retry'
    });
  }
  
  stats.sent++;
  res.status(250).json({ 
    code: 250, 
    message: 'OK', 
    score: result.score,
    queued: false
  });
});

// ═══════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (testUsers.get(email)?.password === password) {
    res.json({ success: true, sessionId: Math.random().toString(36).slice(2) });
  } else {
    res.status(401).json({ success: false });
  }
});

// ═══════════════════════════════════════════════════════
// ADMIN: Get queue status
// ══════════════════���═���══════════════════════════════════
app.get('/admin/queue/:userId', (req, res) => {
  const userId = req.params.userId;
  res.json({
    userId,
    queued: getQueuedEmails(userId).map(e => ({...e, age: Date.now() - e.queuedAt})),
    blocked: getBlockedEmails(userId).map(e => ({...e, age: Date.now() - e.blockedAt})),
  });
});

// ═══════════════════════════════════════════════════════
// ADMIN: Unblock and release queue
// ═══════════════════════════════════════════════════════
app.post('/admin/unblock', (req, res) => {
  const { userId, releaseQueue: release } = req.body;
  
  // Unblock user
  blockedUsers.delete(userId);
  
  // Release and send queued emails
  let releasedCount = 0;
  if (release) {
    const queued = releaseQueue(userId);
    for (const email of queued) {
      // Actually send email (in real system, would send to SMTP)
      console.log(`[RELEASED] ${userId} -> ${email.to}`);
      releasedCount++;
    }
    stats.released += releasedCount;
  }
  
  res.json({ 
    success: true, 
    userId,
    released: releasedCount,
    message: releasedCount > 0 ? `Released ${releasedCount} queued emails` : 'User unblocked'
  });
});

// ═══════════════════════════════════════════════════════
// ADMIN: Trust user
// ═══════════════════════════════════════════════════════
app.post('/admin/trust', (req, res) => {
  const { userId, trust } = req.body;
  if (trust) {
    trustedUsers.add(userId);
    // Release their queue
    const queued = releaseQueue(userId);
    stats.released += queued.length;
  } else {
    trustedUsers.delete(userId);
  }
  res.json({ success: true, userId, trusted: trust });
});

// ═══════════════════════════════════════════════════════
// ADMIN: Get settings
// ═══════════════════════════════════════════════════════
app.get('/admin/settings', (req, res) => {
  res.json({
    queueRetentionHours: QUEUE_RETENTION_HOURS,
    maxQueueSize: 1000,
    blockScore: 85,
    throttleScore: 40,
    monitorScore: 20,
  });
});

// ═══════════════════════════════════════════════════════
// Start
// ═══════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`\nEmail Server with Queue-Based Firewall`);
  console.log(`Port: ${PORT}`);
  console.log(`Queue retention: ${QUEUE_RETENTION_HOURS} hours`);
  console.log(`\nEndpoints:`);
  console.log(`  POST /api/submit  - Submit email`);
  console.log(`  GET  /stats       - Stats`);
  console.log(`  GET  /admin/queue/:userId - Queue status`);
  console.log(`  POST /admin/unblock - Unblock user`);
  console.log(`  POST /admin/trust  - Trust user\n`);
});

app.listen(PORT);