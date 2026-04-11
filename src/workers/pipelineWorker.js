// src/workers/pipelineWorker.js
// Pipeline Worker - handles request filtering, IP blocking, rule updates
// ═══════════════════════════════════════════════════════════════
import { parentPort } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_DIR = path.join(__dirname, '../../config');
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MINUTES || '5', 10) * 60 * 1000;
const SESSION_BUFFER_THRESHOLD = parseInt(process.env.SESSION_BUFFER_THRESHOLD || '5', 10);

class PipelineWorker {
  constructor() {
    this.active = false;
    this.blockedIPs = new Map();
    this.sessionBuffer = new Map();
    this.assessmentCache = new Map();
    this.assessmentId = 0;
    this.pendingAssessments = new Map();
    this.requestTimestamps = new Map();  // Track by actorId
    this.ipRequestTimestamps = new Map(); // Track by IP for distributed attack detection
    this.init();
  }

  init() {
    this.loadBlockedIPs();
    this.setupHandlers();
    console.log('[PipelineWorker] Initialized');
  }

  loadBlockedIPs() {
    const blockedPath = path.join(CONFIG_DIR, 'blocked-ips.json');
    try {
      if (fs.existsSync(blockedPath)) {
        const data = JSON.parse(fs.readFileSync(blockedPath, 'utf8'));
        this.blockedIPs = new Map(Object.entries(data));
      }
    } catch (e) {
      console.log('[PipelineWorker] No existing blocked IPs');
    }
  }

  saveBlockedIPs() {
    const blockedPath = path.join(CONFIG_DIR, 'blocked-ips.json');
    const data = Object.fromEntries(this.blockedIPs);
    fs.writeFileSync(blockedPath, JSON.stringify(data, null, 2));
  }

  setupHandlers() {
    parentPort.on('message', async (msg) => {
      const { type, id, payload } = msg;
      let result;

      try {
        switch (type) {
          case 'PIPELINE_START':
            result = this.startPipeline();
            break;

          case 'PIPELINE_STOP':
            result = this.stopPipeline();
            break;

          case 'PIPELINE_GET_STATUS':
            result = this.getStatus();
            break;

          case 'PIPELINE_PROCESS_REQUEST':
            result = await this.processRequest(payload);
            break;

          case 'PIPELINE_BLOCK_IP':
            result = this.blockIP(payload);
            break;

          case 'PIPELINE_UNBLOCK_IP':
            result = await this.unblockIP(payload);
            break;

          case 'PIPELINE_GET_BLOCKED_IPS':
            result = this.getBlockedIPs();
            break;

          case 'PIPELINE_CHECK_IP':
            result = { blocked: this.isIPBlocked(payload.ip) };
            break;

          case 'RESPONSE_SUCCESS':
            // Handle ML assessment response
            if (this.pendingAssessments?.has(id)) {
              const pending = this.pendingAssessments.get(id);
              clearTimeout(pending.timeout);
              this.pendingAssessments.delete(id);
              pending.resolve(result);
            }
            break;

          case 'RESPONSE_ERROR':
            if (this.pendingAssessments?.has(id)) {
              const pending = this.pendingAssessments.get(id);
              clearTimeout(pending.timeout);
              this.pendingAssessments.delete(id);
              pending.reject(new Error(result.error || 'Assessment failed'));
            }
            break;
            // Handle ML assessment response
            if (id && this.pendingAssessments?.has(id)) {
              this.handleMLAssessment({ id, result });
              result = null;
            }
            break;

          default:
            result = { success: false, error: `Unknown type: ${type}` };
        }
      } catch (err) {
        console.error('[PipelineWorker] Error:', err.message);
        result = { success: false, error: err.message };
      }

      parentPort.postMessage({
        type: result.success !== false ? 'RESPONSE_SUCCESS' : 'RESPONSE_ERROR',
        id,
        result
      });
    });
  }

  startPipeline() {
    this.active = true;
    this.log('Pipeline started');
    return { success: true, active: true };
  }

  stopPipeline() {
    this.active = false;
    this.log('Pipeline stopped');
    return { success: true, active: false };
  }

  getStatus() {
    return {
      active: this.active,
      blockedIPCount: this.blockedIPs.size,
      activeSessions: this.sessionBuffer.size,
    };
  }

  async processRequest(reqData) {
    if (!this.active) {
      return { action: 'allow', reason: 'pipeline_inactive' };
    }

    const { ip, actorId, method, path: endpoint } = reqData;

    // Check if IP is blocked
    if (this.isIPBlocked(ip)) {
      const entry = this.blockedIPs.get(ip);
      return {
        action: 'block',
        reason: 'ip_blocked',
        blockedEntry: entry,
      };
    }

    // Rate-based blocking - count requests per actor in sliding window
    // Check assessment cache FIRST (before any rate counting)
    if (actorId) {
      const cached = this.assessmentCache.get(actorId);
      if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
        const score = cached.assessment.threat_score;
        const recommended = cached.assessment.recommended_action;
        
        // Block if high score or recommended action
        if (recommended === 'block' || score >= 85) {
          this.sendEvent({ type: 'enforcement', action: 'block', ip, actorId, reason: 'ml_blocked', score, timestamp: new Date().toISOString() });
          return { action: 'block', reason: 'ml_blocked', score };
        }
        // Throttle if medium score
        if (recommended === 'throttle' || score >= 70) {
          this.sendEvent({ type: 'enforcement', action: 'throttle', ip, actorId, reason: 'ml_throttled', score, timestamp: new Date().toISOString() });
          return { action: 'throttle', reason: 'ml_throttled', score };
        }
      }
    }

    // Rate limiting - only count after passing checks
    const now = Date.now();
    if (!this.requestTimestamps) this.requestTimestamps = new Map();
    
    if (!this.requestTimestamps.has(actorId)) {
      this.requestTimestamps.set(actorId, []);
    }
    const timestamps = this.requestTimestamps.get(actorId);
    timestamps.push(now);
    
    // Keep only last 10 seconds of timestamps
    while (timestamps.length > 0 && timestamps[0] < now - 10000) {
      timestamps.shift();
    }
    this.requestTimestamps.set(actorId, timestamps);
    
    // Block if more than 10 requests per second (fast bots)
    if (timestamps.length > 10) {
      this.sendEvent({ type: 'enforcement', action: 'block', ip, actorId, reason: 'rate_exceeded', score: 95, timestamp: new Date().toISOString() });
      return { action: 'block', reason: 'rate_exceeded', score: 95 };
    }
    // Throttle if more than 5 requests per second
    if (timestamps.length > 5) {
      this.sendEvent({ type: 'enforcement', action: 'throttle', ip, actorId, reason: 'rate_high', score: 75, timestamp: new Date().toISOString() });
      return { action: 'throttle', reason: 'rate_high', score: 75 };
    }

    // Distributed attack detection - track all IPs in last 10 seconds
    // Add current IP FIRST, then count
    if (!this.ipRequestTimestamps) this.ipRequestTimestamps = new Map();
    const tenSecAgo = now - 10000;
    
    // Clean up old entries and build current set
    const activeIPs = new Set();
    for (const [trackedIP, tsList] of this.ipRequestTimestamps) {
      const recent = tsList.filter(t => t > tenSecAgo);
      if (recent.length > 0) {
        this.ipRequestTimestamps.set(trackedIP, recent);
        activeIPs.add(trackedIP);
      } else {
        this.ipRequestTimestamps.delete(trackedIP);
      }
    }
    
    // Add current request's IP
    activeIPs.add(ip);
    this.ipRequestTimestamps.set(ip, [...(this.ipRequestTimestamps.get(ip) || []), now]);
    
    // Block if more than 5 unique IPs in 10 seconds (distributed attack)
    if (activeIPs.size > 5) {
      this.sendEvent({ type: 'enforcement', action: 'block', ip, actorId, reason: 'distributed_attack', score: 90, timestamp: new Date().toISOString() });
      return { action: 'block', reason: 'distributed_attack', score: 90 };
    }
    // Throttle if more than 3 unique IPs
    if (activeIPs.size > 3) {
      this.sendEvent({ type: 'enforcement', action: 'throttle', ip, actorId, reason: 'distributed_scan', score: 70, timestamp: new Date().toISOString() });
      return { action: 'throttle', reason: 'distributed_scan', score: 70 };
    }

// Buffer request for session analysis
    if (!this.sessionBuffer.has(actorId)) {
      this.sessionBuffer.set(actorId, {
        requests: [],
        startTime: Date.now(),
      });
    }

    const buffered = this.sessionBuffer.get(actorId);
    buffered.requests.push({
      method,
      endpoint,
      ip,
      time: Date.now(),
    });

    // Check if buffer threshold reached - trigger async session analysis
    if (buffered.requests.length >= SESSION_BUFFER_THRESHOLD) {
      // Trigger ML assessment in background
      this.assessWithML(actorId, buffered.requests, ip).then(result => {
        if (result.success && result.assessment) {
          const assessment = result.assessment;
          
          // Cache result for future requests
          this.assessmentCache.set(actorId, {
            timestamp: Date.now(),
            assessment: assessment.assessment || assessment,
          });

          // Send result to dashboard
          this.sendEvent({
            type: 'classification',
            ip,
            actorId,
            score: assessment.threat_score,
            classification: assessment.classification,
            confidence: assessment.confidence,
            recommended_action: assessment.recommended_action,
            timestamp: new Date().toISOString(),
          });
        }
      }).catch(e => {});

      // Clear buffer after triggering
      this.sessionBuffer.delete(actorId);
    }

    // Send allow event to dashboard (use request type for counter)
    this.sendEvent({ type: 'request', ip, actorId, method, endpoint, timestamp: new Date().toISOString() });
    return { action: 'allow', reason: 'request_allowed' };
  }

  blockIP({ ip, actorId, reason, score = 50, manualBlock = false }) {
    const isRange = this.isIPRange(ip);
    const existing = this.blockedIPs.get(ip);
    if (existing) {
      existing.score = Math.max(existing.score, score);
      existing.blockedAt = new Date().toISOString();
      existing.expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    } else {
      const entry = {
        ip,
        ipRange: isRange,
        rangeStart: isRange ? this.getIPRangeStart(ip) : null,
        rangeEnd: isRange ? this.getIPRangeEnd(ip) : null,
        rangeSize: isRange ? this.getIPRangeSize(ip) : 1,
        actorId: actorId || '',
        reason: reason || 'manual_block',
        score,
        blockedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
        manualBlock,
        rulePattern: ip,
      };
      this.blockedIPs.set(ip, entry);

      if (manualBlock) {
        this.analyzeAndCreatePatterns(ip);
      }

      if (actorId) {
        const ipMapPath = path.join(CONFIG_DIR, 'ip-actor-map.json');
        let ipMap = {};
        try {
          if (fs.existsSync(ipMapPath)) ipMap = JSON.parse(fs.readFileSync(ipMapPath, 'utf8'));
        } catch (e) {}
        ipMap[ip] = actorId;
        fs.writeFileSync(ipMapPath, JSON.stringify(ipMap, null, 2));

        const actorIPsPath = path.join(CONFIG_DIR, 'actor-ips.json');
        let actorIPs = {};
        try {
          if (fs.existsSync(actorIPsPath)) actorIPs = JSON.parse(fs.readFileSync(actorIPsPath, 'utf8'));
        } catch (e) {}
        if (!actorIPs[actorId]) actorIPs[actorId] = [];
        if (!actorIPs[actorId].includes(ip)) actorIPs[actorId].push(ip);
        fs.writeFileSync(actorIPsPath, JSON.stringify(actorIPs, null, 2));
      }
    }

    this.saveBlockedIPs();

    const type = isRange ? 'IP range' : 'IP';
    this.log(`${type} blocked: ${ip} (${entry.rangeSize} addresses, reason: ${reason}, manual: ${manualBlock})`);

    parentPort.postMessage({
      type: 'ML_BLOCK_IP',
      payload: { ip, actorId, reason, score, isRange }
    });

    return { success: true, ip, isRange, rangeSize: isRange ? this.getIPRangeSize(ip) : 1 };
  }

  isIPRange(ip) {
    return /\.(x|\*)$/.test(ip) || /\/\d+$/.test(ip);
  }

  parseIPToNumbers(ip) {
    if (/\/\d+$/.test(ip)) {
      const [base, bits] = ip.split('/');
      const parts = base.split('.').map(Number);
      const mask = parseInt(bits, 10);
      const start = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
      const end = start | ((1 << (32 - mask)) - 1);
      return { start, end, bits };
    }
    
    const parts = ip.replace(/\.x$/i, '.0').replace(/\.\*$/, '.0').split('.').map(p => parseInt(p, 10));
    if (parts.some(isNaN)) return null;
    return { 
      start: (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3],
      end: (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + 255,
      bits: 24
    };
  }

  getIPRangeStart(ip) {
    const parsed = this.parseIPToNumbers(ip);
    return parsed ? parsed.start : 0;
  }

  getIPRangeEnd(ip) {
    const parsed = this.parseIPToNumbers(ip);
    return parsed ? parsed.end : 0;
  }

  getIPRangeSize(ip) {
    if (!this.isIPRange(ip)) return 1;
    const parsed = this.parseIPToNumbers(ip);
    if (!parsed) return 1;
    return parsed.end - parsed.start + 1;
  }

  ipMatchesRange(ip, rangeEntry) {
    if (!rangeEntry.ipRange) return ip === rangeEntry.ip;
    
    const ipNum = this.parseIPToNumbers(ip + '/32');
    if (!ipNum) return false;
    
    return ipNum.start >= rangeEntry.rangeStart && ipNum.start <= rangeEntry.rangeEnd;
  }

  getAllIPsInRange(rangeEntry) {
    if (!rangeEntry.ipRange) return [rangeEntry.ip];
    
    const ips = [];
    for (let i = rangeEntry.rangeStart; i <= rangeEntry.rangeEnd; i++) {
      const ip = ((i >> 24) & 255) + '.' + ((i >> 16) & 255) + '.' + ((i >> 8) & 255) + '.' + (i & 255);
      ips.push(ip);
    }
    return ips;
  }

  analyzeAndCreatePatterns(ip) {
    const logsDir = path.join(CONFIG_DIR, 'logs');
    if (!fs.existsSync(logsDir)) return;

    const patterns = {
      userAgents: new Set(),
      endpoints: new Set(),
      methods: new Set(),
      headers: new Set(),
      paths: [],
    };

    const files = fs.readdirSync(logsDir).filter(f => f.endsWith('.log'));
    const targetIP = ip;

    for (const file of files.slice(-3)) {
      try {
        const content = fs.readFileSync(path.join(logsDir, file), 'utf8');
        const lines = content.split('\n').filter(l => l.includes(targetIP));
        
        for (const line of lines.slice(-200)) {
          const uaMatch = line.match(/User-Agent[":\s]+([^\n",]+)/i);
          if (uaMatch) patterns.userAgents.add(uaMatch[1].trim());

          const methodMatch = line.match(/\b(GET|POST|PUT|DELETE|PATCH)\b/i);
          if (methodMatch) patterns.methods.add(methodMatch[1].toUpperCase());

          const pathMatch = line.match(/\b\/api\/[^\s]*/i);
          if (pathMatch) {
            patterns.endpoints.add(pathMatch[0]);
            patterns.paths.push(pathMatch[0]);
          }
        }
      } catch (e) {}
    }

    const summary = {
      ip,
      blockedAt: new Date().toISOString(),
      userAgents: Array.from(patterns.userAgents).slice(0, 5),
      methods: Array.from(patterns.methods),
      endpoints: Array.from(patterns.endpoints).slice(0, 20),
      pathPatterns: this.extractPathPatterns(patterns.paths),
    };

    const patternsPath = path.join(CONFIG_DIR, 'manual-block-patterns.json');
    let existing = [];
    try {
      if (fs.existsSync(patternsPath)) existing = JSON.parse(fs.readFileSync(patternsPath, 'utf8'));
    } catch (e) {}
    
    existing = existing.filter(p => p.ip !== ip);
    existing.push(summary);
    fs.writeFileSync(patternsPath, JSON.stringify(existing, null, 2));

    this.log(`[ManualBlock] Created patterns for ${ip}: ${summary.endpoints.length} endpoints, ${summary.userAgents.length} UAs`);

    // Send to ML worker for fingerprint creation
    parentPort.postMessage({
      type: 'ML_CREATE_FINGERPRINT',
      payload: { ip, patterns: summary }
    });
  }

  extractPathPatterns(paths) {
    const patterns = new Set();
    for (const p of paths) {
      const parts = p.split('/');
      for (let i = 0; i < parts.length; i++) {
        if (/^\d+$/.test(parts[i])) parts[i] = ':id';
        else if (/^[a-f0-9-]{8,}$/.test(parts[i])) parts[i] = ':uuid';
      }
      patterns.add(parts.join('/'));
    }
    return Array.from(patterns).slice(0, 10);
  }

  async unblockIP({ ip }) {
    let entry = this.blockedIPs.get(ip);
    
    if (!entry) {
      for (const [blockedIP, rangeEntry] of this.blockedIPs) {
        if (rangeEntry.ipRange && this.ipMatchesRange(ip, rangeEntry)) {
          entry = rangeEntry;
          break;
        }
      }
    }

    if (!entry) {
      return { success: false, error: 'IP/range not found' };
    }

    const wasManualBlock = entry.manualBlock;
    const actorId = entry.actorId;
    const isRange = entry.ipRange;
    const allIPs = this.getAllIPsInRange(entry);
    const originalIP = ip;

    this.blockedIPs.delete(entry.ip);
    this.saveBlockedIPs();

    if (wasManualBlock) {
      this.cleanupManualBlockPatterns(entry.ip);
    }

    if (actorId) {
      await this.unlinkFingerprintFromIP(allIPs, actorId);
    }

    const type = isRange ? 'IP range' : 'IP';
    const count = allIPs.length;
    this.log(`${type} unblocked: ${entry.ip} (${count} addresses)`);

    parentPort.postMessage({
      type: 'ML_UNBLOCK_IP',
      payload: { ip: entry.ip, actorId, wasManualBlock, isRange, ips: allIPs }
    });

    return { success: true, ip: entry.ip, isRange, unblockedCount: count };
  }

  cleanupManualBlockPatterns(ipOrRange) {
    const patternsPath = path.join(CONFIG_DIR, 'manual-block-patterns.json');
    try {
      if (fs.existsSync(patternsPath)) {
        const existing = JSON.parse(fs.readFileSync(patternsPath, 'utf8'));
        const filtered = existing.filter(p => p.ip !== ipOrRange);
        fs.writeFileSync(patternsPath, JSON.stringify(filtered, null, 2));
        this.log(`[Unblock] Removed patterns for ${ipOrRange}`);
      }
    } catch (e) {
      this.log(`[Unblock] Failed to cleanup patterns: ${e.message}`);
    }
  }

  async unlinkFingerprintFromIP(ipsToUnlink, actorId) {
    const ips = Array.isArray(ipsToUnlink) ? ipsToUnlink : [ipsToUnlink];
    
    const ipMapPath = path.join(CONFIG_DIR, 'ip-actor-map.json');
    let ipMap = {};
    
    try {
      if (fs.existsSync(ipMapPath)) {
        ipMap = JSON.parse(fs.readFileSync(ipMapPath, 'utf8'));
      }
    } catch (e) {}

    for (const ip of ips) {
      if (ipMap[ip]) {
        delete ipMap[ip];
        this.log(`[Unlink] Unlinked IP ${ip} from actor map`);
      }
    }
    fs.writeFileSync(ipMapPath, JSON.stringify(ipMap, null, 2));

    const actorIPsPath = path.join(CONFIG_DIR, 'actor-ips.json');
    let actorIPs = {};
    
    try {
      if (fs.existsSync(actorIPsPath)) {
        actorIPs = JSON.parse(fs.readFileSync(actorIPsPath, 'utf8'));
      }
    } catch (e) {}

    const actorIPList = actorIPs[actorId] || [];
    const filteredIPs = actorIPList.filter(existingIP => !ips.includes(existingIP));
    
    if (filteredIPs.length === 0) {
      delete actorIPs[actorId];
      fs.writeFileSync(actorIPsPath, JSON.stringify(actorIPs, null, 2));
      
      parentPort.postMessage({
        type: 'ML_DELETE_ACTOR',
        payload: { actorId, reason: 'all_ips_unblocked' }
      });
      
      this.log(`[Unlink] Deleted actor ${actorId} - no remaining IPs`);
    } else {
      actorIPs[actorId] = filteredIPs;
      fs.writeFileSync(actorIPsPath, JSON.stringify(actorIPs, null, 2));
      this.log(`[Unlink] Updated actor ${actorId}, ${filteredIPs.length} IPs remaining`);
    }
  }

  isIPBlocked(ip) {
    const entry = this.blockedIPs.get(ip);
    if (entry) {
      if (new Date(entry.expiresAt) < new Date()) {
        this.blockedIPs.delete(ip);
        this.saveBlockedIPs();
        return false;
      }
      return true;
    }

    for (const [blockedIP, rangeEntry] of this.blockedIPs) {
      if (rangeEntry.ipRange && this.ipMatchesRange(ip, rangeEntry)) {
        if (new Date(rangeEntry.expiresAt) < new Date()) {
          this.blockedIPs.delete(blockedIP);
          this.saveBlockedIPs();
          return false;
        }
        return true;
      }
    }

    return false;
  }

  sendEvent(event) {
    // Events sent via workerManager routing
    parentPort.postMessage({
      type: 'PIPELINE_TO_DASHBOARD',
      payload: event
    });
  }

  // For ML assessment - use request/response through workerManager
  // The actual assessment happens async, this just triggers it
  // Results are handled in processRequest via cache
  triggerAssessment(actorId, requests, ip) {
    // Send to ML worker via workerManager routing
    parentPort.postMessage({
      type: 'ML_ASSESS_SESSION',
      payload: { actorId, requests, ip }
    });
  }

  // Called for cache-based blocking - real assessment happens async
  async assessWithML(actorId, requests, ip) {
    return new Promise((resolve, reject) => {
      const id = ++this.assessmentId || 1;
      
      const timeout = setTimeout(() => {
        reject(new Error('ML assessment timeout'));
      }, 15000);

      this.pendingAssessments = this.pendingAssessments || new Map();
      this.pendingAssessments.set(id, { resolve, reject, timeout });

      // Send via workerManager routing
      parentPort.postMessage({
        type: 'ML_ASSESS_SESSION',
        id,
        payload: { actorId, requests, ip }
      });
    });
  }

  handleMLAssessment(msg) {
    const { id, result } = msg;
    if (!this.pendingAssessments) return;

    const pending = this.pendingAssessments.get(id);
    if (!pending) return;

    clearTimeout(pending.timeout);
    this.pendingAssessments.delete(id);

    if (result.success) {
      pending.resolve(result);
    } else {
      pending.reject(new Error(result.error || 'Assessment failed'));
    }
  }

  getBlockedIPs() {
    const now = Date.now();
    const ips = [];

    for (const [ip, entry] of this.blockedIPs) {
      // Clean up expired
      if (new Date(entry.expiresAt) < new Date()) {
        this.blockedIPs.delete(ip);
        continue;
      }

      ips.push({
        ...entry,
        isExpired: false,
      });
    }

    if (ips.length !== this.blockedIPs.size) {
      this.saveBlockedIPs();
    }

    return { success: true, ips };
  }

  log(message) {
    parentPort.postMessage({
      type: 'PIPELINE_LOG',
      payload: { message, timestamp: new Date().toISOString() }
    });
  }
}

new PipelineWorker();