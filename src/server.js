// src/server.js
// ═══════════════════════════════════════════════════════════════
// API Abuse Detection Engine — Main Server
// Multi-process architecture with worker threads
// ═══════════════════════════════════════════════════════════════
import express from 'express';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { 
  config, 
  loadUserConfig
} from './runtimeConfig.js';
import { setupMemoryBank } from './memory/bankSetup.js';
import eventLog from './engine/eventLog.js';
import hindsight from './memory/hindsightClient.js';
import memoryLayer from './memory/memoryLayer.js';
import { workerManager } from './workers/workerManager.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const server = createServer(app);

// Runtime state
let pipelineActive = false;
let ollamaAvailable = false;

// Load config on startup
loadUserConfig();

async function syncRuntimeConfigFromWorkers() {
  try {
    const result = await workerManager.getConfig();
    if (result.success && result.config) {
      Object.assign(config, result.config);
    }
  } catch (e) {
    // Keep existing runtime config when worker sync is unavailable
  }
}

// WebSocket for real-time dashboard
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws) => {
  console.log('[Dashboard] Client connected');
  workerManager.getEvents({ count: 500 }).then(result => {
    if (result.success) {
      ws.send(JSON.stringify({ type: 'history', events: result.events }));
    }
  });
  ws.on('close', () => console.log('[Dashboard] Client disconnected'));
});

// Listen for events from workers
workerManager.on('admin_log', (event) => {
  console.log('[Admin]', JSON.stringify(event));
  // Use the event's own type, not override
  const msg = JSON.stringify({ type: 'event', event });
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(msg);
  }
});

workerManager.on('pipeline_log', (event) => {
  const msg = JSON.stringify({ type: 'event', event: { type: 'pipeline_log', ...event } });
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(msg);
  }
});

workerManager.on('worker_log', (payload) => {
  if (payload.level === 'error') {
    console.error('[Worker]', payload.message);
  } else {
    console.log('[Worker]', payload.message);
  }
});

eventLog.on('event', (event) => {
  const msg = JSON.stringify({ type: 'event', event });
  for (const client of wss.clients) {
    if (client.readyState === 1) client.send(msg);
  }
});

// Express middleware
app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files for dashboard
app.use('/dashboard', express.static(join(__dirname, 'dashboard')));

// ABUSE DETECTION PIPELINE - only active when started
// Requests pass through immediately, ML classification runs async in background
app.all('/api/*', async (req, res, next) => {
  if (!pipelineActive) {
    next();
    return;
  }

  try {
    const parsed = parseRequest(req);
    const actorId = req.actorId || generateFingerprint(req);
    console.log(`[Server] Request: ${parsed.method} ${parsed.path} from ${parsed.ip} actor:${actorId}`);
    
    // Immediately process request with full context for behavioral scoring
    const userAgent = req.headers['user-agent'] || '';
    const hasAuth = !!(req.headers['authorization'] || req.headers['x-api-key']);
    const headerKeys = Object.keys(req.headers);

    const result = await workerManager.processRequest({
      ip: parsed.ip,
      actorId: actorId,
      method: parsed.method,
      path: parsed.path,
      userAgent: userAgent,
      hasAuth: hasAuth,
      headers: headerKeys,
    });

    console.log(`[Server] Pipeline result: action=${result.action} reason=${result.reason}`);

    // Block if action is block
    if (result.action === 'block') {
      res.status(403).json({
        error: 'BLOCKED',
        reason: result.reason,
      });
      return;
    }

    // Throttle if action is throttle - return 429 Too Many Requests
    if (result.action === 'throttle') {
      const delay = result.score > 70 ? 1000 : 500;
      await new Promise(r => setTimeout(r, delay));
      res.status(429).json({
        error: 'THROTTLED',
        reason: result.reason,
      });
      return;
    }

    // Store actorId for routes
    req.actorId = actorId;
    next();
  } catch (e) {
    console.error('[Server] Pipeline error:', e.message);
    next(); // Fail open
  }
});

// Helper functions (moved from pipeline)
function parseRequest(req) {
  return {
    ip: req.ip || req.headers['x-forwarded-for'] || '127.0.0.1',
    method: req.method,
    path: req.path,
    headers: req.headers,
    body: req.body,
  };
}

// Bot UA patterns that indicate automation tools
const BOT_UA_GROUP_PATTERNS = [
  'python-requests', 'python-urllib', 'python-httpx',
  'curl/', 'wget/', 'httpie/',
  'go-http-client', 'java/', 'okhttp/',
  'scrapy', 'selenium', 'puppeteer', 'playwright',
  'headlesschrome', 'phantomjs',
  'spider', 'scraper', 'crawler', 'bot',
  'apache-httpclient', 'libwww-perl',
];

function generateFingerprint(req) {
  const ip = req.ip || req.headers['x-forwarded-for'] || '127.0.0.1';
  const ua = req.headers['user-agent'] || '';
  const auth = req.headers['authorization'] || '';
  const uaLower = ua.toLowerCase();

  // For bot-like UAs: group by UA pattern (ignore IP)
  // This catches IP-rotating attackers using the same tool
  const isBotUA = BOT_UA_GROUP_PATTERNS.some(p => uaLower.includes(p));

  // Group key: for bots use just the UA; for humans use IP+UA+auth
  const raw = isBotUA ? ('bot:' + ua) : (ip + ua + auth);
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    hash = ((hash << 5) - hash) + raw.charCodeAt(i);
    hash = hash & hash;
  }
  return 'actor-' + Math.abs(hash).toString(36);
}

// Demo API routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', actorId: req.actorId });
});

app.post('/api/auth/login', (req, res) => {
  res.json({ success: false, message: 'Invalid credentials', actorId: req.actorId });
});

app.get('/api/users/:id', (req, res) => {
  res.json({ id: req.params.id, name: 'User ' + req.params.id, actorId: req.actorId });
});

app.get('/api/users/:id/profile', (req, res) => {
  res.json({ id: req.params.id, email: 'user' + req.params.id + '@example.com', bio: 'Sample bio', actorId: req.actorId });
});

app.get('/api/search', (req, res) => {
  res.json({ query: req.query.q || '', results: [{ id: 1, title: 'Result 1' }, { id: 2, title: 'Result 2' }], actorId: req.actorId });
});

app.get('/api/listings', (req, res) => {
  res.json({ page: req.query.page || 1, items: [{ id: 1, name: 'Item 1' }], actorId: req.actorId });
});

app.get('/api/products/:id', (req, res) => {
  res.json({ id: req.params.id, name: 'Product ' + req.params.id, price: 29.99, actorId: req.actorId });
});

// ADMIN / DASHBOARD API ROUTES

// Get recent events
app.get('/admin/events', async (req, res) => {
  const count = parseInt(req.query.count || '50', 10);
  const type = req.query.type || null;
  try {
    const result = await workerManager.getEvents({ count, type });
    res.json(result.events || []);
  } catch (e) {
    res.json([]);
  }
});

// Get actor history
app.get('/admin/actor/:actorId', (req, res) => {
  res.json(eventLog.getActorHistory(req.params.actorId));
});

// Natural language query
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
app.get('/admin/ml/status', async (req, res) => {
  try {
    const status = await workerManager.getMLStatus();
    res.json(status);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Blocked IPs list - uses pipeline worker
app.get('/admin/blocked-ips', async (req, res) => {
  try {
    const result = await workerManager.getBlockedIPs();
    res.json(result.ips || []);
  } catch (e) {
    res.json([]);
  }
});

// Block an IP manually
app.post('/admin/blocked-ips', async (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  
  try {
    const result = await workerManager.blockIP({ ip, reason, manualBlock: true });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Unblock an IP
app.delete('/admin/blocked-ips/:ip', async (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  try {
    const result = await workerManager.unblockIP({ ip });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Server control endpoints
app.get('/admin/server/status', (req, res) => {
  res.json({ running: pipelineActive, port: config.port });
});

app.post('/admin/server/start', async (req, res) => {
  if (pipelineActive) {
    return res.json({ success: true, message: 'Pipeline already active' });
  }
  
  try {
    await workerManager.startPipeline();
    pipelineActive = true;
    console.log('[Engine] Detection pipeline started');
    res.json({ success: true, message: 'Detection pipeline started' });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/admin/server/stop', async (req, res) => {
  if (!pipelineActive) {
    return res.json({ success: true, message: 'Pipeline already stopped' });
  }
  
  try {
    await workerManager.stopPipeline();
    pipelineActive = false;
    console.log('[Engine] Detection pipeline stopped');
    res.json({ success: true, message: 'Detection pipeline stopped' });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Config endpoints - uses dashboard worker
app.get('/admin/config', async (req, res) => {
  try {
    const result = await workerManager.getConfig();
    res.json(result.config || {});
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/admin/config', async (req, res) => {
  try {
    const newConfig = req.body;
    await workerManager.saveConfig(newConfig);
    await syncRuntimeConfigFromWorkers();
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

// Rules management
app.get('/admin/rules', async (req, res) => {
  try {
    const result = await workerManager.getRules();
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/admin/rules/add', async (req, res) => {
  const { rule } = req.body;
  if (!rule || !rule.pattern) {
    return res.status(400).json({ success: false, error: 'Rule pattern required' });
  }
  
  try {
    const result = await workerManager.addRule(rule);
    res.json(result);
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/admin/rules/:index', async (req, res) => {
  const idx = parseInt(req.params.index, 10);
  try {
    const result = await workerManager.deleteRule({ index: idx });
    res.json(result);
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/admin/rules/by-ip/:ip', async (req, res) => {
  try {
    const result = await workerManager.getRulesByIP(req.params.ip);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/admin/rules/approve-suggestion', async (req, res) => {
  const { index } = req.body;
  try {
    const result = await workerManager.approveSuggestion({ index });
    res.json(result);
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Ollama endpoints
app.get('/admin/ollama/status', async (req, res) => {
  try {
    const endpoint = config.ollamaEndpoint || 'http://localhost:11434';
    const response = await fetch(endpoint + '/api/tags');
    ollamaAvailable = response.ok;
    res.json({ available: ollamaAvailable, endpoint, model: config.ollamaModel });
  } catch (e) {
    ollamaAvailable = false;
    res.json({ available: false, endpoint: config.ollamaEndpoint, error: e.message });
  }
});

app.get('/admin/ollama/suggestions', async (req, res) => {
  try {
    const result = await workerManager.getSuggestions();
    res.json({ suggestions: result.suggestions || [] });
  } catch (e) {
    res.json({ suggestions: [] });
  }
});

app.post('/admin/ollama/analyze', async (req, res) => {
  try {
    const result = await workerManager.runAnalysis({});
    res.json(result);
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Training endpoints
app.get('/admin/training/status', async (req, res) => {
  try {
    const result = await workerManager.getTrainingStatus();
    res.json(result);
  } catch (e) {
    res.json({ status: { trainingStatus: 'idle' } });
  }
});

app.post('/admin/training/train', async (req, res) => {
  const { mode } = req.body;
  try {
    const result = await workerManager.trainModel(mode || 'full');
    res.json(result);
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/admin/training/schedule', async (req, res) => {
  const { training } = req.body;
  if (training) {
    try {
      await workerManager.saveConfig({ training });
      await syncRuntimeConfigFromWorkers();
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ success: false, error: e.message });
    }
  } else {
    res.status(400).json({ success: false, error: 'Training config required' });
  }
});

app.post('/admin/training/reset-stats', async (req, res) => {
  try {
    await workerManager.saveConfig({
      training: { rulesChangedSinceLastTrain: 0 }
    });
    await syncRuntimeConfigFromWorkers();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Analysis endpoints
app.get('/admin/analysis/status', async (req, res) => {
  try {
    const result = await workerManager.getTrainingStatus();
    res.json(result.status || {});
  } catch (e) {
    res.json({ analysisStatus: 'idle' });
  }
});

app.post('/admin/analysis/run', async (req, res) => {
  try {
    const result = await workerManager.runAnalysis({});
    res.json(result);
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Log endpoints
app.get('/admin/logs', async (req, res) => {
  try {
    const result = await workerManager.getLogFiles();
    res.json(result);
  } catch (e) {
    res.json({ files: [] });
  }
});

// Log config routes — MUST be before /admin/logs/:filename to avoid route conflict
app.get('/admin/logs/config', async (req, res) => {
  try {
    const result = await workerManager.getLogConfig();
    res.json(result.config || { maxDays: 7, maxSizeMB: 100, chunkSizeMB: 4 });
  } catch (e) {
    res.json({ maxDays: 7, maxSizeMB: 100, chunkSizeMB: 4 });
  }
});

app.post('/admin/logs/config', async (req, res) => {
  try {
    const result = await workerManager.setLogConfig(req.body);
    await syncRuntimeConfigFromWorkers();
    res.json(result);
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

// Read specific log file — after /config to prevent 'config' matching as :filename
app.get('/admin/logs/:filename', async (req, res) => {
  try {
    const { filename } = req.params;
    const lines = parseInt(req.query.lines || '100', 10);
    const result = await workerManager.readLogs({ filename, lines });
    res.json(result);
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});



// STARTUP
async function start() {
  console.log('');
  console.log('==================================================');
  console.log('  API Abuse Detection Engine v3.0');
  console.log('  Multi-Process Architecture');
  console.log('==================================================');
  console.log('');

  // Initialize workers
  console.log('[Workers] Starting worker processes...');
  await workerManager.initialize();
  console.log('[Workers] All workers initialized');
  console.log('');

  // Pre-load ML model on startup (before pipeline starts)
  console.log('[ML] Pre-loading model...');
  try {
    await workerManager.trainModel('full');
    console.log('[ML] Model ready');
  } catch (e) {
    console.log('[ML] Model not available yet, will train on demand');
  }

  // Load config from worker
  try {
    await syncRuntimeConfigFromWorkers();
  } catch (e) {
    console.log('[Config] Using default config');
  }

  console.log('[Config] Port:', config.port);
  console.log('[Config] Thresholds - Block:', config.enforcement?.blockScore || 85);
  if (config.rulesFilePath) {
    console.log('[Rules] File:', config.rulesFilePath);
  }
  console.log('[Ollama] Endpoint:', config.ollamaEndpoint);
  console.log('[Training] Enabled:', config.training?.enabled || false);
  console.log('[Logging] Max days:', config.logging?.maxDays || 7);
  console.log('');

  // Hindsight connection
  try {
    const alive = await hindsight.ping();
    if (alive) {
      console.log('[Memory] Hindsight connected');
      await setupMemoryBank();
    } else {
      console.log('[Memory] Hindsight not available');
    }
  } catch (e) {
    console.log('[Memory] Hindsight not available:', e.message);
  }

  // Ollama availability
  try {
    const response = await fetch(config.ollamaEndpoint + '/api/tags');
    ollamaAvailable = response.ok;
    console.log('[AI] Ollama', ollamaAvailable ? 'connected' : 'not available');
  } catch (e) {
    console.log('[AI] Ollama not available:', e.message);
  }

  // Start server with pipeline already active for immediate responsiveness
  server.listen(config.port, async () => {
    console.log('[Server] Running on http://localhost:' + config.port);
    console.log('[Server] Dashboard: http://localhost:' + config.port + '/dashboard');
    console.log('[Server] Pipeline: ACTIVE');
    console.log('');
    
    // Auto-start pipeline for immediate responsiveness
    try {
      console.log('[Engine] Auto-starting pipeline...');
      
      // Start pipeline directly in worker
      const result = await workerManager.startPipeline();
      console.log('[Engine] Pipeline start result:', JSON.stringify(result));
      
      // Ensure it's marked active
      pipelineActive = true;
      console.log('[Engine] Pipeline activated:', pipelineActive);
    } catch (e) {
      console.log('[Engine] Pipeline start deferred:', e.message);
    }
  });
}

start().catch((e) => {
  console.error('Fatal error:', e);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n[Server] Shutting down...');
  await workerManager.shutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n[Server] Shutting down...');
  await workerManager.shutdown();
  process.exit(0);
});
