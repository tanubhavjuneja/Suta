// test_server/email_server.js
// ═══════════════════════════════════════════════════════════════
// Email Test Server — Simulates SMTP submission and webmail
// Protected by Email Firewall
// ═══════════════════════════════════════════════════════════════
import express from 'express';
import { createServer } from 'http';

const app = express();
const PORT = 2525;
const FIREWALL_URL = 'http://localhost:3000';

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ═══════════════════════════════════════════════════════════════
// Email Store (in-memory)
// ═══════════════════════════════════════════════════════════════
const emails = new Map();
const users = new Map();
const sessions = new Map();

function generateId() {
  return Math.random().toString(36).substring(2, 15);
}

// Seed test users
const testUsers = [
  { email: 'alice@example.com', password: 'pass123', name: 'Alice Smith', knownIPs: ['192.168.1.100', '10.0.0.5'] },
  { email: 'bob@example.com', password: 'pass456', name: 'Bob Jones', knownIPs: ['192.168.1.101'] },
  { email: 'charlie@example.com', password: 'pass789', name: 'Charlie Brown', knownIPs: [] },
  { email: 'david@example.com', password: 'test999', name: 'David Wilson', knownIPs: ['203.0.113.50'] },
  { email: 'eve@example.com', password: 'eve123', name: 'Eve Miller', knownIPs: ['198.51.100.25'] },
];

for (const u of testUsers) {
  users.set(u.email, { ...u, userId: generateId() });
}

// Track email stats
let stats = {
  total: 0,
  sent: 0,
  blocked: 0,
  blockedUsers: 0,
  blockedIPs: 0,
  errors: 0,
};

// ═══════════════════════════════════════════════════════════════
// Headers
// ═══════════════════════════════════════════════════════════════
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-sender-ip'] ||
         req.socket?.remoteAddress ||
         '127.0.0.1';
}

// ═══════════════════════════════════════════════════════════════
// Routes
// ═══════════════════════════════════════════════════════

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', server: 'email-test-server', port: PORT });
});

// Stats
app.get('/stats', (req, res) => {
  res.json({
    ...stats,
    blockRate: stats.total > 0 ? ((stats.blocked / stats.total) * 100).toFixed(1) + '%' : '0%',
  });
});

app.post('/stats/reset', (req, res) => {
  stats = { total: 0, sent: 0, blocked: 0, blockedUsers: 0, blockedIPs: 0, errors: 0 };
  res.json({ message: 'Stats reset' });
});

// ═══════════════════════════════════════════��═══════════════════
// SMTP-style Submission
// ═══════════════════════════════════════════════════════════════
app.post('/api/submit', async (req, res) => {
  stats.total++;
  
  const ip = getClientIP(req);
  const authHeader = req.headers['authorization'];
  const fromHeader = req.headers['from'] || req.body.from;
  const toHeader = req.headers['to'] || req.body.to;
  const ccHeader = req.headers['cc'] || req.body.cc;
  const bccHeader = req.headers['bcc'] || req.body.bcc;
  const subject = req.headers['subject'] || req.body.subject || '(No Subject)';
  
  // Extract user from auth or From header
  let userId = fromHeader;
  if (authHeader?.startsWith('Basic ')) {
    const creds = Buffer.from(authHeader.substring(6), 'base64').toString().split(':');
    userId = creds[0];
  }
  
  if (!userId) {
    return res.status(530).json({ error: 'Authentication required' });
  }
  
  // Forward to firewall for assessment
  try {
    const firewallReq = {
      headers: {
        'x-authenticated-user': userId,
        'x-sender-ip': ip,
        'from': fromHeader,
        'to': toHeader,
        'cc': ccHeader || '',
        'bcc': bccHeader || '',
        'subject': subject,
        'content-type': req.headers['content-type'] || 'text/plain',
      },
      socket: { remoteAddress: ip },
    };
    
    // Call firewall assessment endpoint
    const fwUrl = `${FIREWALL_URL}/api/email/assess`;
    const response = await fetch(fwUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': ip,
      },
      body: JSON.stringify({
        userId,
        ip,
        emailData: {
          recipients: toHeader?.split(',').map(e => e.trim()) || [],
          cc: ccHeader?.split(',').map(e => e.trim()) || [],
          bcc: bccHeader?.split(',').map(e => e.trim()) || [],
          subject,
        },
      }),
    });
    
    const assessment = await response.json().catch(() => null);
    
    if (response.status === 403 || assessment?.action === 'block') {
      stats.blocked++;
      stats.blockedUsers++;
      return res.status(550).json({
        error: 'Access denied',
        code: 'mailbox_unavailable',
        message: assessment?.reason || 'User blocked',
      });
    }
    
    // Store email
    const emailId = generateId();
    const email = {
      id: emailId,
      from: fromHeader,
      to: toHeader?.split(',').map(e => e.trim()),
      cc: ccHeader?.split(',').map(e => e.trim()),
      bcc: bccHeader?.split(',').map(e => e.trim()),
      subject,
      body: req.body.body || '',
      ip,
      timestamp: new Date().toISOString(),
      status: 'sent',
    };
    
    emails.set(emailId, email);
    stats.sent++;
    
    res.status(250).json({
      code: 250,
      message: 'OK',
      emailId,
    });
  } catch (e) {
    stats.errors++;
    // If firewall is down, allow through (fail open)
    const emailId = generateId();
    emails.set(emailId, {
      id: emailId,
      from: fromHeader,
      to: toHeader,
      subject,
      ip,
      timestamp: new Date().toISOString(),
      status: 'sent',
    });
    stats.sent++;
    res.status(250).json({ code: 250, message: 'OK', emailId, warning: 'firewall_unavailable' });
  }
});

// ═══════════════════════════════════════════════════════════════
// Webmail-style API
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = getClientIP(req);
  
  const user = users.get(email);
  if (!user || user.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
  
  // Create session
  const sessionId = generateId();
  sessions.set(sessionId, { userId: email, ip, created: Date.now() });
  
  res.json({
    success: true,
    sessionId,
    user: { email: user.email, name: user.name },
  });
});

app.get('/api/inbox', async (req, res) => {
  const auth = req.headers['authorization'];
  const session = sessions.get(auth);
  
  if (!session) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  // Return emails for this user
  const inbox = Array.from(emails.values())
    .filter(e => e.to?.includes(session.userId))
    .slice(-20);
  
  res.json({ emails: inbox, count: inbox.length });
});

app.post('/api/send', async (req, res) => {
  const auth = req.headers['authorization'];
  const session = sessions.get(auth);
  const ip = getClientIP(req);
  
  if (!session) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const { to, cc, bcc, subject, body } = req.body;
  
  // Forward to firewall
  try {
    const response = await fetch(`${FIREWALL_URL}/api/email/assess`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': ip,
      },
      body: JSON.stringify({
        userId: session.userId,
        ip,
        emailData: {
          recipients: to?.split(',').map(e => e.trim()) || [],
          cc: cc?.split(',').map(e => e.trim()) || [],
          bcc: bcc?.split(',').map(e => e.trim()) || [],
          subject,
          hasAttachments: req.headers['content-type']?.includes('multipart'),
        },
      }),
    });
    
    const assessment = await response.json().catch(() => null);
    
    if (response.status === 403 || assessment?.action === 'block') {
      stats.blocked++;
      return res.status(403).json({
        error: 'BLOCKED',
        reason: assessment?.reason || 'Rate limit exceeded',
      });
    }
    
    const emailId = generateId();
    emails.set(emailId, {
      id: emailId,
      from: session.userId,
      to: to?.split(',').map(e => e.trim()),
      cc, bcc,
      subject,
      body,
      ip,
      timestamp: new Date().toISOString(),
      status: 'sent',
    });
    
    stats.sent++;
    res.json({ success: true, emailId });
  } catch (e) {
    // Fail open
    const emailId = generateId();
    emails.set(emailId, {
      id: emailId,
      from: session.userId,
      to, subject, body,
      ip,
      timestamp: new Date().toISOString(),
      status: 'sent',
    });
    stats.sent++;
    res.json({ success: true, emailId, warning: 'firewall_unavailable' });
  }
});

// ═══════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════
function start() {
  console.log('');
  console.log('═══════════════════════════════════════════════════');
  console.log('  Email Test Server');
  console.log('  Protected by: Email Firewall');
  console.log('═══════════════════════════════════════════════════');
  console.log('');
  console.log(`   📧 SMTP:   localhost:${PORT}`);
  console.log(`   🌐 WebAPI:  http://localhost:${PORT}/api/*`);
  console.log(`   🛡️  Firewall: ${FIREWALL_URL}`);
  console.log('');
  console.log('  Endpoints:');
  console.log('    POST /api/submit     - SMTP-style submission');
  console.log('    POST /api/auth/login - Webmail login');
  console.log('    POST /api/send     - Send email (webmail)');
  console.log('    GET  /api/inbox    - Get inbox');
  console.log('    GET  /stats      - Server stats');
  console.log('');
  console.log('  Test users:');
  for (const u of testUsers) {
    console.log(`    ${u.email} / ${u.password}`);
  }
  console.log('');
  
  app.listen(PORT, () => {
    console.log(`   ✅ Server running on port ${PORT}`);
    console.log('');
  });
}

start();