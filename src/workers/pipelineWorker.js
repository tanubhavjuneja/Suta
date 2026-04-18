// src/workers/pipelineWorker.js
// Pipeline Worker - handles request filtering, IP blocking, rule updates
// ═══════════════════════════════════════════════════════════════
// BEHAVIORAL SCORING: Deterministic, inline scoring layer that
// catches attacks in real-time using weighted behavioral signals.
// ML assessment runs async in background for refinement.
//
// INTELLIGENCE LAYER: Attack classification, reason building,
// evidence tracking, and explainability.
// ═══════════════════════════════════════════════════════════════
import { parentPort } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { classifyAttack, getAttackSeverity } from '../intelligence/attackClassifier.js';
import { buildReason } from '../intelligence/reasonBuilder.js';
import attackTracker from '../intelligence/attackTracker.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_DIR = path.join(__dirname, '../../config');
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MINUTES || '5', 10) * 60 * 1000;
const SESSION_BUFFER_THRESHOLD = parseInt(process.env.SESSION_BUFFER_THRESHOLD || '5', 10);

// ── Bot User-Agent patterns ─────────────────────────────────
const BOT_UA_PATTERNS = [
  'python-requests', 'python-urllib', 'python-httpx',
  'curl/', 'wget/', 'httpie/',
  'go-http-client', 'java/', 'okhttp/',
  'scrapy', 'selenium', 'puppeteer', 'playwright',
  'headlesschrome', 'phantomjs',
  'bot', 'crawler', 'spider', 'scraper',
  'apache-httpclient', 'libwww-perl',
];

// ── Browser-standard headers (missing = suspicious) ─────────
const BROWSER_HEADERS = [
  'accept-language', 'sec-ch-ua', 'sec-ch-ua-mobile',
  'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode',
  'sec-fetch-site', 'upgrade-insecure-requests', 'cache-control',
];

// ── Behavioral scoring weights ──────────────────────────────
const SCORE_WEIGHTS = {
  AUTH_ENDPOINT_REPETITION: 30,    // ≥5 POST /auth/login → credential stuffing
  BOT_USER_AGENT: 15,             // Non-browser User-Agent
  MISSING_BROWSER_HEADERS: 12,    // Missing standard browser headers
  SEQUENTIAL_ID_ACCESS: 22,       // Accessing /users/1, /users/2, /users/3...
  SINGLE_ENDPOINT_FOCUS: 18,      // >80% requests to same endpoint pattern
  LOW_TIMING_VARIANCE: 12,        // Machine-like consistency
  HIGH_REQUEST_VOLUME: 18,        // >15 requests in session
  IP_ROTATION: 12,                // Multiple IPs for same actor fingerprint
  HAS_VALID_AUTH: -20,            // Legitimate users usually have auth tokens
  DIVERSE_ENDPOINTS: -15,         // Natural browsing hits many different pages
};

// ── Enforcement thresholds ──────────────────────────────────
const BLOCK_THRESHOLD = 80;
const THROTTLE_THRESHOLD = 55;

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

    // ── NEW: Actor behavioral profiles ──────────────────────
    this.actorProfiles = new Map(); // actorId → ActorProfile
    this.init();
  }

  init() {
    this.loadBlockedIPs();
    this.setupHandlers();
    console.log('[PipelineWorker] Initialized with behavioral scoring');
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
    this.log('Pipeline started with behavioral scoring');
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
      trackedActors: this.actorProfiles.size,
    };
  }

  // ═══════════════════════════════════════════════════════════
  //  CORE: Process incoming request with behavioral scoring
  // ═══════════════════════════════════════════════════════════
  async processRequest(reqData) {
    if (!this.active) {
      return { action: 'allow', reason: 'pipeline_inactive' };
    }

    const { ip, actorId, method, path: endpoint, headers, userAgent, hasAuth } = reqData;

    // ── Step 1: Check if IP is blocked ──────────────────────
    if (this.isIPBlocked(ip)) {
      this.sendEvent({ type: 'enforcement', action: 'block', ip, actorId, reason: 'ip_blocked', score: 95, timestamp: new Date().toISOString() });
      return { action: 'block', reason: 'ip_blocked', score: 95 };
    }

    // ── Step 2: Update actor behavioral profile ─────────────
    const profile = this.getOrCreateProfile(actorId);
    this.updateProfile(profile, { ip, method, endpoint, headers, userAgent, hasAuth });

    // ── Step 3: Compute behavioral score ────────────────────
    const { score, signals } = this.computeBehavioralScore(profile);

    // ── Step 3b: Attack Intelligence Layer ──────────────────
    const classification = classifyAttack(
      { method, endpoint, ip, body: reqData.body, queryParams: reqData.queryParams, headers },
      profile, score
    );
    const trackerEntry = attackTracker.update(
      actorId, score,
      score >= BLOCK_THRESHOLD ? 'block' : score >= THROTTLE_THRESHOLD ? 'throttle' : 'allow',
      { method, endpoint, body: reqData.body }
    );

    // ── Step 4: Enforce based on score ──────────────────────
    if (score >= BLOCK_THRESHOLD) {
      const reason = buildReason({
        attackType: classification.attackType,
        confidence: classification.confidence,
        ruleMatched: classification.ruleMatched,
        score, signals, profile, tracker: trackerEntry,
      });
      const evidence = attackTracker.getEvidenceSummary(actorId);

      this.sendEvent({
        type: 'enforcement', action: 'block', ip, actorId,
        reason: `behavioral_block`, score,
        signals: signals.join(', '),
        attackType: classification.attackType,
        confidence: classification.confidence,
        ruleMatched: classification.ruleMatched,
        reasonDetail: reason,
        evidence,
        timestamp: new Date().toISOString()
      });

      // Also block the IP to catch future requests immediately
      this.blockIP({ ip, actorId, reason: signals.join(', '), score,
        attackType: classification.attackType,
        reasonDetail: reason,
        evidence,
      });

      return { action: 'block', reason: `behavioral_block: ${signals.join(', ')}`, score };
    }

    if (score >= THROTTLE_THRESHOLD) {
      const reason = buildReason({
        attackType: classification.attackType,
        confidence: classification.confidence,
        ruleMatched: classification.ruleMatched,
        score, signals, profile, tracker: trackerEntry,
      });

      this.sendEvent({
        type: 'enforcement', action: 'throttle', ip, actorId,
        reason: `behavioral_throttle`, score,
        signals: signals.join(', '),
        attackType: classification.attackType,
        confidence: classification.confidence,
        ruleMatched: classification.ruleMatched,
        reasonDetail: reason,
        timestamp: new Date().toISOString()
      });
      return { action: 'throttle', reason: `behavioral_throttle: ${signals.join(', ')}`, score };
    }

    // ── Step 5: Rate limiting (for very fast bursts) ────────
    const now = Date.now();
    if (!this.requestTimestamps.has(actorId)) {
      this.requestTimestamps.set(actorId, []);
    }
    const timestamps = this.requestTimestamps.get(actorId);
    timestamps.push(now);

    // Keep only last 3 seconds of timestamps
    while (timestamps.length > 0 && timestamps[0] < now - 3000) {
      timestamps.shift();
    }

    // Burst detection: 12+ req in 3 seconds = 4 req/s
    if (timestamps.length > 12) {
      this.sendEvent({ type: 'enforcement', action: 'throttle', ip, actorId, reason: 'rate_burst', score: 75, timestamp: new Date().toISOString() });
      return { action: 'throttle', reason: 'rate_burst', score: 75 };
    }

    // ── Step 6: Buffer for async ML assessment ──────────────
    if (!this.sessionBuffer.has(actorId)) {
      this.sessionBuffer.set(actorId, {
        requests: [],
        startTime: Date.now(),
      });
    }

    const buffered = this.sessionBuffer.get(actorId);
    buffered.requests.push({ method, endpoint, ip, time: Date.now() });

    // Trigger async ML assessment when buffer fills
    if (buffered.requests.length >= SESSION_BUFFER_THRESHOLD) {
      this.assessWithML(actorId, buffered.requests, ip).then(result => {
        if (result.success && result.assessment) {
          const assessment = result.assessment;
          this.assessmentCache.set(actorId, {
            timestamp: Date.now(),
            assessment: assessment.assessment || assessment,
          });
          this.sendEvent({
            type: 'classification', ip, actorId,
            score: assessment.threat_score,
            classification: assessment.classification,
            confidence: assessment.confidence,
            recommended_action: assessment.recommended_action,
            timestamp: new Date().toISOString(),
          });
        }
      }).catch(() => {});
      this.sessionBuffer.delete(actorId);
    }

    // ── Step 7: Allow the request ───────────────────────────
    this.sendEvent({ type: 'request', ip, actorId, method, endpoint, timestamp: new Date().toISOString() });
    return { action: 'allow', reason: 'request_allowed', score };
  }

  // ═══════════════════════════════════════════════════════════
  //  ACTOR PROFILING: Tracks behavioral signals per actor
  // ═══════════════════════════════════════════════════════════

  getOrCreateProfile(actorId) {
    if (!this.actorProfiles.has(actorId)) {
      this.actorProfiles.set(actorId, {
        actorId,
        firstSeen: Date.now(),
        requestCount: 0,
        endpoints: [],           // raw endpoint list
        endpointPatterns: [],     // normalized patterns (IDs replaced)
        methods: [],
        ips: new Set(),
        timestamps: [],
        userAgents: new Set(),
        hasAuth: false,
        authCount: 0,
        noAuthCount: 0,
        authEndpointCount: 0,    // hits to /auth/login etc
        sequentialIds: [],       // numeric IDs extracted from paths
        headerCounts: [],        // track header richness
        lastScore: 0,
      });
    }
    return this.actorProfiles.get(actorId);
  }

  updateProfile(profile, reqData) {
    const { ip, method, endpoint, headers, userAgent, hasAuth } = reqData;
    const now = Date.now();

    profile.requestCount++;
    profile.timestamps.push(now);
    profile.endpoints.push(endpoint);
    profile.methods.push(method);

    // Track IPs
    if (ip) profile.ips.add(ip);

    // Track User-Agent
    if (userAgent) profile.userAgents.add(userAgent);

    // Track auth presence
    if (hasAuth) {
      profile.hasAuth = true;
      profile.authCount++;
    } else {
      profile.noAuthCount++;
    }

    // Track auth endpoint hits (login, reset, verify)
    const epLower = (endpoint || '').toLowerCase();
    if ((epLower.includes('/auth/') || epLower.includes('/login')) && method === 'POST') {
      profile.authEndpointCount++;
    }

    // Extract numeric IDs from paths for sequential detection
    const idMatch = endpoint?.match(/\/(\d+)(?:\/|$|\?)/);
    if (idMatch) {
      profile.sequentialIds.push(parseInt(idMatch[1], 10));
    }

    // Normalize endpoint pattern (replace numeric IDs with :id)
    const pattern = (endpoint || '').replace(/\/\d+/g, '/:id').replace(/\?.*$/, '');
    profile.endpointPatterns.push(pattern);

    // Track header count from this request
    if (headers) {
      const headerCount = typeof headers === 'object' ? Object.keys(headers).length : 0;
      profile.headerCounts.push(headerCount);
    }

    // Trim old data to prevent memory growth (keep last 100 entries)
    if (profile.timestamps.length > 100) {
      profile.timestamps = profile.timestamps.slice(-100);
      profile.endpoints = profile.endpoints.slice(-100);
      profile.endpointPatterns = profile.endpointPatterns.slice(-100);
      profile.methods = profile.methods.slice(-100);
      profile.sequentialIds = profile.sequentialIds.slice(-100);
      profile.headerCounts = profile.headerCounts.slice(-100);
    }
  }

  // ═══════════════════════════════════════════════════════════
  //  BEHAVIORAL SCORING: Deterministic, weighted scoring
  // ═══════════════════════════════════════════════════════════

  computeBehavioralScore(profile) {
    let score = 0;
    const signals = [];

    // Need at least 3 requests to make meaningful assessments
    if (profile.requestCount < 3) {
      return { score: 0, signals: ['insufficient_data'] };
    }

    // ── Signal 1: Auth endpoint repetition ──────────────────
    // Repeated POST /auth/login = credential stuffing / brute force
    if (profile.authEndpointCount >= 3) {
      const authWeight = Math.min(profile.authEndpointCount / 3, 2.5); // scale up faster
      const points = Math.round(SCORE_WEIGHTS.AUTH_ENDPOINT_REPETITION * authWeight);
      score += points;
      signals.push(`auth_repetition(${profile.authEndpointCount}x→+${points})`);
    }

    // ── Signal 2: Bot User-Agent ────────────────────────────
    const isBotUA = this.isBotUserAgent(profile);
    if (isBotUA) {
      score += SCORE_WEIGHTS.BOT_USER_AGENT;
      signals.push(`bot_ua(+${SCORE_WEIGHTS.BOT_USER_AGENT})`);
    }

    // ── Signal 3: Missing browser headers ───────────────────
    // If average header count is very low, likely automation tool
    if (profile.headerCounts.length > 0) {
      const avgHeaders = profile.headerCounts.reduce((a, b) => a + b, 0) / profile.headerCounts.length;
      if (avgHeaders < 8) {
        score += SCORE_WEIGHTS.MISSING_BROWSER_HEADERS;
        signals.push(`sparse_headers(avg=${avgHeaders.toFixed(1)}→+${SCORE_WEIGHTS.MISSING_BROWSER_HEADERS})`);
      }
    }

    // ── Signal 4: Sequential ID access ──────────────────────
    // Accessing /users/1, /users/2, /users/3... is enumeration
    if (profile.sequentialIds.length >= 4) {
      const seqScore = this.computeSequentialScore(profile.sequentialIds);
      if (seqScore > 0.4) {
        const points = Math.round(SCORE_WEIGHTS.SEQUENTIAL_ID_ACCESS * seqScore);
        score += points;
        signals.push(`sequential_ids(${(seqScore * 100).toFixed(0)}%→+${points})`);
      }
    }

    // ── Signal 5: Single endpoint focus ─────────────────────
    // >75% of requests going to the same endpoint pattern = scraping
    if (profile.endpointPatterns.length >= 4) {
      const patternCounts = {};
      profile.endpointPatterns.forEach(p => { patternCounts[p] = (patternCounts[p] || 0) + 1; });
      const maxPatternCount = Math.max(...Object.values(patternCounts));
      const focusRatio = maxPatternCount / profile.endpointPatterns.length;
      if (focusRatio > 0.75) {
        score += SCORE_WEIGHTS.SINGLE_ENDPOINT_FOCUS;
        signals.push(`endpoint_focus(${(focusRatio * 100).toFixed(0)}%→+${SCORE_WEIGHTS.SINGLE_ENDPOINT_FOCUS})`);
      }
    }

    // ── Signal 6: Low timing variance (machine-like) ────────
    if (profile.timestamps.length >= 5) {
      const intervals = [];
      for (let i = 1; i < profile.timestamps.length; i++) {
        intervals.push(profile.timestamps[i] - profile.timestamps[i - 1]);
      }
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      if (mean > 0) {
        const variance = intervals.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / intervals.length;
        const stddev = Math.sqrt(variance);
        const cv = stddev / mean; // coefficient of variation
        // Very consistent timing (CV < 0.3) = likely automated
        if (cv < 0.3 && mean < 2000) {
          score += SCORE_WEIGHTS.LOW_TIMING_VARIANCE;
          signals.push(`low_variance(cv=${cv.toFixed(2)}→+${SCORE_WEIGHTS.LOW_TIMING_VARIANCE})`);
        }
      }
    }

    // ── Signal 7: High request volume ───────────────────────
    if (profile.requestCount >= 15) {
      const elapsed = (Date.now() - profile.firstSeen) / 1000; // seconds
      const rps = profile.requestCount / Math.max(elapsed, 1);
      // Only flag if sustained high volume (not just normal browsing over a long period)
      if (rps > 0.3 || profile.requestCount >= 25) {
        const volumeScale = Math.min(profile.requestCount / 20, 2.0);
        const points = Math.round(SCORE_WEIGHTS.HIGH_REQUEST_VOLUME * volumeScale);
        score += points;
        signals.push(`high_volume(${profile.requestCount}reqs→+${points})`);
      }
    }

    // ── Signal 8: IP rotation ───────────────────────────────
    // Multiple IPs but same actor fingerprint = distributed attack
    if (profile.ips.size >= 3) {
      const ipScale = Math.min(profile.ips.size / 5, 2.0);
      const points = Math.round(SCORE_WEIGHTS.IP_ROTATION * ipScale);
      score += points;
      signals.push(`ip_rotation(${profile.ips.size}ips→+${points})`);
    }

    // ── Signal 9: Has valid auth (BONUS — reduces score) ────
    if (profile.hasAuth && profile.authCount > profile.noAuthCount) {
      score += SCORE_WEIGHTS.HAS_VALID_AUTH; // negative weight
      signals.push(`has_auth(→${SCORE_WEIGHTS.HAS_VALID_AUTH})`);
    }

    // ── Signal 10: Diverse endpoints (BONUS — reduces score) ─
    if (profile.endpointPatterns.length >= 3) {
      const uniquePatterns = new Set(profile.endpointPatterns);
      const diversity = uniquePatterns.size / profile.endpointPatterns.length;
      if (diversity > 0.5 && uniquePatterns.size >= 3) {
        score += SCORE_WEIGHTS.DIVERSE_ENDPOINTS; // negative weight
        signals.push(`diverse_endpoints(${uniquePatterns.size}unique→${SCORE_WEIGHTS.DIVERSE_ENDPOINTS})`);
      }
    }

    // ── Signal 11: Credential stuffing amplifier ─────────────
    // Hitting auth endpoints repeatedly without ever having auth = stuffing
    // Real users authenticate once and then use tokens for subsequent requests
    if (profile.authEndpointCount >= 3 && !profile.hasAuth) {
      const stuffingRatio = profile.authEndpointCount / profile.requestCount;
      if (stuffingRatio > 0.6) {
        const points = 20; // strong signal
        score += points;
        signals.push(`cred_stuffing_noauth(${(stuffingRatio * 100).toFixed(0)}%→+${points})`);
      }
    }

    // Clamp to [0, 100]
    score = Math.max(0, Math.min(100, score));
    profile.lastScore = score;

    return { score, signals };
  }

  // ═══════════════════════════════════════════════════════════
  //  HELPER: Detect bot User-Agent
  // ═══════════════════════════════════════════════════════════
  isBotUserAgent(profile) {
    for (const ua of profile.userAgents) {
      const lower = (ua || '').toLowerCase();
      if (BOT_UA_PATTERNS.some(pattern => lower.includes(pattern))) {
        return true;
      }
    }
    return false;
  }

  // ═══════════════════════════════════════════════════════════
  //  HELPER: Detect sequential ID access pattern
  // ═══════════════════════════════════════════════════════════
  computeSequentialScore(ids) {
    if (ids.length < 4) return 0;

    let sequential = 0;
    for (let i = 1; i < ids.length; i++) {
      if (ids[i] === ids[i - 1] + 1) sequential++;
    }

    return sequential / (ids.length - 1);
  }

  // ═══════════════════════════════════════════════════════════
  //  IP BLOCKING
  // ═══════════════════════════════════════════════════════════

  blockIP({ ip, actorId, reason, score = 50, manualBlock = false, attackType, reasonDetail, evidence }) {
    const isRange = this.isIPRange(ip);
    const existing = this.blockedIPs.get(ip);
    const isNewBlock = !existing;
    let entry = existing;
    
    if (existing) {
      existing.score = Math.max(existing.score, score);
      existing.blockedAt = new Date().toISOString();
      existing.expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      // Update intelligence fields if provided
      if (attackType) existing.attackType = attackType;
      if (reasonDetail) existing.reasonDetail = reasonDetail;
      if (evidence) existing.evidence = evidence;
    } else {
      entry = {
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
        // Intelligence fields
        attackType: attackType || null,
        reasonDetail: reasonDetail || null,
        evidence: evidence || [],
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
    this.log(`${type} ${isNewBlock ? 'blocked' : 'updated'}: ${ip} (${entry.rangeSize || 1} addresses, reason: ${reason}, manual: ${manualBlock}${attackType ? ', attack: ' + attackType : ''})`);

    // Send enhanced ip_blocked event to dashboard with intelligence data
    this.sendEvent({
      type: 'ip_blocked',
      ip, actorId, score,
      attackType: attackType || null,
      confidence: reasonDetail?.confidence || null,
      ruleMatched: reasonDetail?.ruleMatched || null,
      reasonDetail: reasonDetail || null,
      evidence: evidence || [],
      timestamp: new Date().toISOString(),
    });

    parentPort.postMessage({
      type: 'ML_BLOCK_IP',
      payload: { ip, actorId, reason, score, isRange, attackType }
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
        const lines = content.split('\n').filter(l => 
          l.includes(`"ip":"${targetIP}"`) || 
          l.includes(`"ip":"${targetIP.replace(/\./g, '\\.')}"`) ||
          l.includes(`X-Forwarded-For`) && l.includes(targetIP)
        );
        
        for (const line of lines.slice(-200)) {
          let eventData = null;
          
          const jsonMatch = line.match(/\{.+\}$/);
          if (jsonMatch) {
            try {
              eventData = JSON.parse(jsonMatch[0]);
            } catch (e) {}
          }

          if (eventData) {
            if (eventData.userAgent) patterns.userAgents.add(eventData.userAgent);
            if (eventData.method) patterns.methods.add(eventData.method.toUpperCase());
            if (eventData.endpoint || eventData.path) {
              const ep = eventData.endpoint || eventData.path;
              patterns.endpoints.add(ep);
              patterns.paths.push(ep);
            }
          } else {
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
    parentPort.postMessage({
      type: 'PIPELINE_TO_DASHBOARD',
      payload: event
    });
  }

  triggerAssessment(actorId, requests, ip) {
    parentPort.postMessage({
      type: 'ML_ASSESS_SESSION',
      payload: { actorId, requests, ip }
    });
  }

  async assessWithML(actorId, requests, ip) {
    return new Promise((resolve, reject) => {
      const id = ++this.assessmentId || 1;
      
      const timeout = setTimeout(() => {
        this.pendingAssessments.delete(id);
        reject(new Error('ML assessment timeout'));
      }, 15000);

      this.pendingAssessments = this.pendingAssessments || new Map();
      this.pendingAssessments.set(id, { resolve, reject, timeout });

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