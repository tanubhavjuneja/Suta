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

          default:
            result = { success: false, error: `Unknown type: ${type}` };
        }
      } catch (err) {
        result = { success: false, error: err.message };
      }

      parentPort.postMessage({
        type: result.success ? 'RESPONSE_SUCCESS' : 'RESPONSE_ERROR',
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

    // Check assessment cache
    if (actorId) {
      const cached = this.assessmentCache.get(actorId);
      if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
        if (cached.assessment.threat_score >= 90) {
          return {
            action: cached.assessment.recommended_action || 'block',
            reason: 'cached_assessment',
            score: cached.assessment.threat_score,
          };
        }
      }
    }

    // Buffer request for session analysis
    if (!this.sessionBuffer.has(actorId)) {
      this.sessionBuffer.set(actorId, {
        requests: [],
        startTime: Date.now(),
      });
    }

    const session = this.sessionBuffer.get(actorId);
    session.requests.push({
      method,
      endpoint,
      ip,
      time: Date.now(),
    });

    // Check if buffer threshold reached
    if (session.requests.length >= SESSION_BUFFER_THRESHOLD) {
      // Session analysis would happen here - for now, pass through
      // ML model would be called via parentPort
    }

    // For now, return allow - actual ML scoring happens in main process
    return { action: 'allow', reason: 'no_threat_detected' };
  }

  blockIP({ ip, actorId, reason, score = 50, manualBlock = false }) {
    const existing = this.blockedIPs.get(ip);
    if (existing) {
      // Update existing
      existing.score = Math.max(existing.score, score);
      existing.blockedAt = new Date().toISOString();
      existing.expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    } else {
      // Add new block
      const entry = {
        ip,
        actorId: actorId || '',
        reason: reason || 'manual_block',
        score,
        blockedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
        manualBlock,
        rulePattern: ip,
      };
      this.blockedIPs.set(ip, entry);
    }

    this.saveBlockedIPs();

    this.log(`IP blocked: ${ip} (reason: ${reason}, score: ${score}, manual: ${manualBlock})`);

    // Notify ML worker about the block
    parentPort.postMessage({
      type: 'ML_BLOCK_IP',
      payload: { ip, actorId, reason, score }
    });

    return { success: true, ip };
  }

  async unblockIP({ ip }) {
    const entry = this.blockedIPs.get(ip);
    if (!entry) {
      return { success: false, error: 'IP not found' };
    }

    this.blockedIPs.delete(ip);
    this.saveBlockedIPs();

    this.log(`IP unblocked: ${ip}`);

    // Notify ML worker about the unblock (will handle rule weight adjustment)
    parentPort.postMessage({
      type: 'ML_UNBLOCK_IP',
      payload: { ip }
    });

    return { success: true, ip };
  }

  isIPBlocked(ip) {
    const entry = this.blockedIPs.get(ip);
    if (!entry) return false;

    // Check expiration
    if (new Date(entry.expiresAt) < new Date()) {
      this.blockedIPs.delete(ip);
      this.saveBlockedIPs();
      return false;
    }

    return true;
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