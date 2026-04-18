// test_server/email_server.js
// ═══════════════════════════════════════════════════════════════
// Email Test Server with AGGRESSIVE Inline Firewall
// ═══════════════════════════════════════════════════════════════
import express from 'express';

const app = express();
const PORT = 2526;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ═══════════════════════════════════════════════════════
// FIREWALL STATE
// ═══════════════════════════════════════════════════════
const userScores = new Map(); // userId -> { score, reason }
const blockedUsers = new Set();

// ═══════════════════════════════════════════════════════
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-sender-ip'] ||
         req.socket?.remoteAddress ||
         '127.0.0.1';
}

function assessEmail(userId, ip, emailData) {
  // Initialize score for new users
  if (!userScores.has(userId)) {
    userScores.set(userId, { totalEmails: 0, recentEmails: [], lastIP: null, ipChanges: [] });
  }
  
  const state = userScores.get(userId);
  const now = Date.now();
  
  // Check if already blocked
  if (blockedUsers.has(userId)) {
    return { action: 'block', reason: 'Previously blocked', score: 100 };
  }
  
  state.totalEmails++;
  state.recentEmails.push({ timestamp: now });
  if (state.recentEmails.length > 500) state.recentEmails = state.recentEmails.slice(-500);
  
  let score = 0;
  let reasons = [];
  
  // Count emails in last 30 seconds for BURST detection
  const recent30s = state.recentEmails.filter(e => now - e.timestamp < 30000).length;
  if (recent30s >= 5) {
    reasons.push('RAPID_BURST');
    score += 50;
  }
  
  // Count emails in last 60 seconds  
  const recent60s = state.recentEmails.filter(e => now - e.timestamp < 60000).length;
  if (recent60s >= 10) {
    reasons.push('HIGH_60s');
    score += 40;
  }
  
  // Count emails in last 5 minutes
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
  
  // BCC count
  const bccCount = emailData.bcc?.split(',').filter(Boolean).length || 0;
  if (bccCount >= 10) {
    reasons.push('MASS_BCC');
    score += 35;
  }
  
  // Recipient count
  const toCount = emailData.to?.split(',').filter(Boolean).length || 0;
  const ccCount = emailData.cc?.split(',').filter(Boolean).length || 0;
  if ((toCount + ccCount + bccCount) >= 30) {
    reasons.push('MASS_RECIPIENTS');
    score += 30;
  }
  
  console.log(`[${userId}] IP:${ip} Score:${score} Reasons:${reasons.join(',') || 'none'}`);
  
  // VERY LOW thresholds for testing - block at score >= 20!
  let action = 'allow';
  if (score >= 20) {
    action = 'block';
    blockedUsers.add(userId);
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

// ═══════════════════════════════════════════════════════
// Stats
// ═══════════════════════════════════════════════════════
let stats = { total: 0, sent: 0, blocked: 0 };

// ═══════════════════════════════════════════════════════
// Routes
// ═══════════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({ status: 'ok', firewall: 'aggressive' }));
app.get('/stats', (req, res) => res.json(stats));
app.post('/stats/reset', (req, res) => { stats = { total: 0, sent: 0, blocked: 0 }; res.json({ ok: true }); });

app.post('/api/submit', (req, res) => {
  stats.total++;
  
  const ip = getClientIP(req);
  const auth = req.headers['authorization'];
  
  // Extract credentials
  let userId = 'unknown';
  if (auth?.startsWith('Basic ')) {
    try {
      const [u, p] = Buffer.from(auth.substring(6), 'base64').toString().split(':');
      userId = u;
    } catch (e) {}
  }
  
  if (!userId) {
    return res.status(530).json({ error: 'Auth required' });
  }
  
  // Parse email
  const emailData = {
    to: req.body.to || '',
    cc: req.body.cc || '',
    bcc: req.body.bcc || '',
  };
  
  // Assess with firewall
  const result = assessEmail(userId, ip, emailData);
  
  if (result.action === 'block') {
    stats.blocked++;
    return res.status(550).json({ error: 'BLOCKED', reason: result.reason, score: result.score });
  }
  
  stats.sent++;
  res.status(250).json({ code: 250, message: 'OK', score: result.score });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (testUsers.get(email)?.password === password) {
    res.json({ success: true, sessionId: Math.random().toString(36).slice(2) });
  } else {
    res.status(401).json({ success: false });
  }
});

app.post('/admin/unblock', (req, res) => {
  const { userId } = req.body;
  blockedUsers.delete(userId);
  res.json({ success: true });
});

// Start
app.listen(PORT, () => {
  console.log(`\nEmail Server with AGGRESSIVE Firewall on port ${PORT}\n`);
  console.log('Block threshold: score >= 20');
  console.log('Detection: rapid burst, high volume, IP changes, mass BCC\n');
});

app.listen(PORT);