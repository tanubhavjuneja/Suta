// src/server.js
// ═══════════════════════════════════════════════════════════════
// API Abuse Pattern Memory Engine — Main Server
// Hybrid: Transformer ML + Hindsight Agent Memory
// ═══════════════════════════════════════════════════════════════
import express from 'express';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import config from './config.js';
import { setupMemoryBank } from './memory/bankSetup.js';
import { abuseDetectionPipeline } from './engine/pipeline.js';
import eventLog from './engine/eventLog.js';
import hindsight from './memory/hindsightClient.js';
import memoryLayer from './memory/memoryLayer.js';
import ipBlocklist from './enforcement/ipBlocklist.js';
import { trainModel } from './ml/trainer.js';
import detector from './ml/model.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const server = createServer(app);

// ── WebSocket for real-time dashboard ────────────────────────
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws) => {
  console.log('📊 Dashboard client connected');

  // Send recent events on connect
  const recent = eventLog.getRecent(50);
  ws.send(JSON.stringify({ type: 'history', events: recent }));

  ws.on('close', () => console.log('📊 Dashboard client disconnected'));
});

// Forward engine events to all WebSocket clients
eventLog.on('event', (event) => {
  const msg = JSON.stringify({ type: 'event', event });
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(msg);
  }
});

// ── Express middleware ───────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files for dashboard
app.use('/dashboard', express.static(join(__dirname, 'dashboard')));

// ── ABUSE DETECTION PIPELINE — runs on ALL /api/* routes ─────
app.use('/api', abuseDetectionPipeline);

// ═══════════════════════════════════════════════════════════════
// DEMO API ROUTES — These are the "protected" endpoints that
// attackers will target. Normal business logic goes here.
// ═══════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', actorId: req.actorId });
});

// Simulated auth endpoint (credential stuffing target)
app.post('/api/auth/login', (req, res) => {
  res.json({
    success: false,
    message: 'Invalid credentials',
    actorId: req.actorId,
  });
});

// Simulated user lookup (enumeration target)
app.get('/api/users/:id', (req, res) => {
  res.json({
    id: req.params.id,
    name: `User ${req.params.id}`,
    actorId: req.actorId,
  });
});

// Simulated user profile (scraping target)
app.get('/api/users/:id/profile', (req, res) => {
  res.json({
    id: req.params.id,
    email: `user${req.params.id}@example.com`,
    bio: 'Sample bio data',
    actorId: req.actorId,
  });
});

// Simulated search (rate limit evasion target)
app.get('/api/search', (req, res) => {
  res.json({
    query: req.query.q || '',
    results: [{ id: 1, title: 'Result 1' }, { id: 2, title: 'Result 2' }],
    actorId: req.actorId,
  });
});

// Simulated listings
app.get('/api/listings', (req, res) => {
  res.json({
    page: req.query.page || 1,
    items: [{ id: 1, name: 'Item 1' }],
    actorId: req.actorId,
  });
});

// Simulated product lookup
app.get('/api/products/:id', (req, res) => {
  res.json({
    id: req.params.id,
    name: `Product ${req.params.id}`,
    price: 29.99,
    actorId: req.actorId,
  });
});

// ═══════════════════════════════════════════════════════════════
// ADMIN / DASHBOARD API ROUTES
// ═══════════════════════════════════════════════════════════════

// Get recent events
app.get('/admin/events', (req, res) => {
  const count = parseInt(req.query.count || '50', 10);
  const type = req.query.type || null;
  res.json(eventLog.getRecent(count, type));
});

// Get actor history
app.get('/admin/actor/:actorId', (req, res) => {
  res.json(eventLog.getActorHistory(req.params.actorId));
});

// Natural language query against entire memory bank
app.post('/admin/query', async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) return res.status(400).json({ error: 'question required' });

    const result = await memoryLayer.query(question);
    res.json({ answer: result.text || result, raw: result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Hindsight health check
app.get('/admin/hindsight/status', async (req, res) => {
  const alive = await hindsight.ping();
  res.json({ hindsight: alive ? 'connected' : 'unreachable', baseUrl: config.hindsight.baseUrl });
});

// ML model status
app.get('/admin/ml/status', (req, res) => {
  res.json({ model: detector.getSummary() });
});

// Blocked IPs list
app.get('/admin/blocked-ips', (req, res) => {
  res.json(ipBlocklist.getAll());
});

// Unblock an IP
app.delete('/admin/blocked-ips/:ip', (req, res) => {
  const removed = ipBlocklist.unblock(req.params.ip);
  res.json({ removed, ip: req.params.ip });
});

// ═══════════════════════════════════════════════════════════════
// STARTUP
// ═══════════════════════════════════════════════════════════════

async function start() {
  console.log('');
  console.log('═══════════════════════════════════════════════════');
  console.log('  API Abuse Pattern Memory Engine v2.0');
  console.log('  Hybrid: Transformer ML + Hindsight Agent Memory');
  console.log('═══════════════════════════════════════════════════');
  console.log('');

  // ── Step 1: Train Transformer Model ────────────────────────
  try {
    await trainModel(50);
    console.log(`🤖 Transformer model ready (${detector.getSummary().params} params)\n`);
  } catch (e) {
    console.error(`⚠️  ML model training failed: ${e.message}`);
    console.log('   Engine will start without ML scoring.\n');
  }

  // ── Step 2: Connect Hindsight ──────────────────────────────
  const alive = await hindsight.ping();
  if (alive) {
    console.log(`✅ Hindsight connected: ${config.hindsight.baseUrl}`);
    await setupMemoryBank();
  } else {
    console.log(`⚠️  Hindsight unreachable at ${config.hindsight.baseUrl}`);
    console.log(`   Engine will start but threat detection requires Hindsight.`);
    console.log(`   Set HINDSIGHT_BASE_URL in .env and restart.\n`);
  }

  // ── Step 3: Start Server ───────────────────────────────────
  server.listen(config.port, () => {
    console.log(`🚀 Server running on http://localhost:${config.port}`);
    console.log(`📊 Dashboard: http://localhost:${config.port}/dashboard`);
    console.log(`🔌 WebSocket: ws://localhost:${config.port}/ws`);
    console.log(`🛡️  Pipeline active on /api/* routes`);
    console.log('');
    console.log('Pipeline: Request → ML Score → Hindsight Recall → Reflect → Enforce');
    console.log('');
    console.log('Enforcement thresholds:');
    console.log(`   Block:    score >= ${config.enforcement.blockScore}`);
    console.log(`   Throttle: score >= ${config.enforcement.throttleScore}`);
    console.log(`   Monitor:  score >= ${config.enforcement.monitorScore}`);
    console.log(`   Allow:    score <  ${config.enforcement.monitorScore}`);
    console.log('');
  });
}

start().catch((e) => {
  console.error('Fatal startup error:', e);
  process.exit(1);
});
