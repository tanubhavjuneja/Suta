// src/intelligence/attackClassifier.js
// ═══════════════════════════════════════════════════════════════
// Config-driven attack classification.
// Reads patterns from config/attack-intel.json and classifies
// each actor's behavior into a named attack type with confidence.
//
// This does NOT make enforcement decisions — it only labels
// what the behavioral scoring system has already flagged.
// ═══════════════════════════════════════════════════════════════
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const INTEL_PATH = path.join(__dirname, '../../config/attack-intel.json');

// ── Load attack intel config ────────────────────────────────
let attackIntel = {};

function loadIntel() {
  try {
    if (fs.existsSync(INTEL_PATH)) {
      attackIntel = JSON.parse(fs.readFileSync(INTEL_PATH, 'utf8'));
    }
  } catch (e) {
    console.error('[AttackClassifier] Failed to load attack-intel.json:', e.message);
  }
}

// Load on import, reload every 60s for hot-updates
loadIntel();
setInterval(loadIntel, 60_000);

// ── Bot UA patterns (same as pipelineWorker) ────────────────
const BOT_UA_PATTERNS = [
  'python-requests', 'python-urllib', 'python-httpx',
  'curl/', 'wget/', 'httpie/',
  'go-http-client', 'java/', 'okhttp/',
  'scrapy', 'selenium', 'puppeteer', 'playwright',
  'headlesschrome', 'phantomjs',
  'bot', 'crawler', 'spider', 'scraper',
  'apache-httpclient', 'libwww-perl',
];

/**
 * Classify an actor's behavior into an attack type.
 *
 * @param {object} reqData  - Current request { method, endpoint, ip, body, queryParams, headers }
 * @param {object} profile  - Actor behavioral profile from pipelineWorker
 * @param {number} score    - Current behavioral score (0-100)
 * @returns {{ attackType: string, confidence: number, ruleMatched: string|null }}
 */
export function classifyAttack(reqData, profile, score) {
  // No classification needed for low scores
  if (score < 30) {
    return { attackType: 'NORMAL', confidence: 0, ruleMatched: null };
  }

  const results = [];

  // ── Check payload-based attacks (SQLi, XSS, Path Traversal) ──
  const payloadResult = classifyPayloadAttack(reqData);
  if (payloadResult) results.push(payloadResult);

  // ── Check behavioral attacks ──────────────────────────────
  const bruteForce = checkBruteForce(profile);
  if (bruteForce) results.push(bruteForce);

  const credStuffing = checkCredentialStuffing(profile);
  if (credStuffing) results.push(credStuffing);

  const ddos = checkDDoS(profile);
  if (ddos) results.push(ddos);

  const scraping = checkScraping(profile);
  if (scraping) results.push(scraping);

  // ── Pick highest confidence match ─────────────────────────
  if (results.length === 0) {
    // High score but no specific signature → anomaly
    if (score >= 50) {
      return {
        attackType: 'ANOMALY',
        confidence: Math.min(score / 100, 0.85),
        ruleMatched: 'ANOMALY_BEHAVIORAL',
      };
    }
    return { attackType: 'NORMAL', confidence: 0, ruleMatched: null };
  }

  // Sort by confidence descending
  results.sort((a, b) => b.confidence - a.confidence);
  return results[0];
}

// ═══════════════════════════════════════════════════════════════
//  Payload-based classification (SQLi, XSS, Path Traversal)
// ═══════════════════════════════════════════════════════════════

function classifyPayloadAttack(reqData) {
  const { endpoint, body, queryParams } = reqData || {};

  // Build a searchable string from all request content
  const pathStr = (endpoint || '').toLowerCase();
  const bodyStr = typeof body === 'string' ? body.toLowerCase()
    : (body ? JSON.stringify(body).toLowerCase() : '');
  const queryStr = typeof queryParams === 'string' ? queryParams.toLowerCase()
    : (queryParams ? JSON.stringify(queryParams).toLowerCase() : '');
  const combined = `${pathStr} ${bodyStr} ${queryStr}`;

  if (!combined.trim()) return null;

  // Check each payload-based attack type
  const payloadTypes = ['SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL'];

  for (const type of payloadTypes) {
    const intel = attackIntel[type];
    if (!intel) continue;

    // Keyword check
    const keywordHits = (intel.keywords || []).filter(kw =>
      combined.includes(kw.toLowerCase())
    );

    // Regex pattern check
    let patternHits = 0;
    for (const pat of (intel.patterns || [])) {
      try {
        if (new RegExp(pat, 'i').test(combined)) patternHits++;
      } catch (e) { /* skip invalid patterns */ }
    }

    if (keywordHits.length > 0 || patternHits > 0) {
      const totalSignals = keywordHits.length + patternHits;
      const confidence = Math.min(0.5 + totalSignals * 0.15, 0.98);
      return {
        attackType: type,
        confidence,
        ruleMatched: `${type}_${keywordHits.length > 0 ? 'KEYWORD' : 'PATTERN'}_${String(totalSignals).padStart(3, '0')}`,
      };
    }
  }

  return null;
}

// ═══════════════════════════════════════════════════════════════
//  Behavioral classification
// ═══════════════════════════════════════════════════════════════

function checkBruteForce(profile) {
  const intel = attackIntel.BRUTE_FORCE;
  if (!intel) return null;

  const threshold = intel.authEndpointThreshold || 5;
  if ((profile.authEndpointCount || 0) >= threshold) {
    const ratio = profile.authEndpointCount / Math.max(profile.requestCount, 1);
    const confidence = Math.min(0.5 + ratio * 0.5, 0.95);
    return {
      attackType: 'BRUTE_FORCE',
      confidence,
      ruleMatched: `BRUTE_FORCE_${profile.authEndpointCount >= 10 ? 'HIGH' : 'MED'}`,
    };
  }
  return null;
}

function checkCredentialStuffing(profile) {
  const intel = attackIntel.CREDENTIAL_STUFFING;
  if (!intel) return null;

  const authHits = profile.authEndpointCount || 0;
  const hasAuth = profile.hasAuth;
  const threshold = intel.authHitsNoTokenThreshold || 3;
  const ratioThreshold = intel.authRatioThreshold || 0.6;

  if (authHits >= threshold && !hasAuth) {
    const ratio = authHits / Math.max(profile.requestCount, 1);
    if (ratio >= ratioThreshold) {
      return {
        attackType: 'CREDENTIAL_STUFFING',
        confidence: Math.min(0.6 + ratio * 0.3, 0.95),
        ruleMatched: `CRED_STUFF_NOAUTH_${Math.round(ratio * 100)}`,
      };
    }
  }
  return null;
}

function checkDDoS(profile) {
  const intel = attackIntel.DDOS;
  if (!intel) return null;

  const elapsed = (Date.now() - profile.firstSeen) / 1000;
  const rps = profile.requestCount / Math.max(elapsed, 1);

  if (rps >= (intel.rpsThreshold || 50)) {
    return {
      attackType: 'DDOS',
      confidence: Math.min(0.7 + (rps / 100) * 0.2, 0.98),
      ruleMatched: `DDOS_RPS_${Math.round(rps)}`,
    };
  }

  if (profile.requestCount >= (intel.requestCountThreshold || 25)) {
    return {
      attackType: 'DDOS',
      confidence: Math.min(0.5 + (profile.requestCount / 50) * 0.3, 0.90),
      ruleMatched: `DDOS_VOLUME_${profile.requestCount}`,
    };
  }

  return null;
}

function checkScraping(profile) {
  const intel = attackIntel.SCRAPING;
  if (!intel) return null;

  // Check sequential ID pattern
  const ids = profile.sequentialIds || [];
  if (ids.length >= 4) {
    let sequential = 0;
    for (let i = 1; i < ids.length; i++) {
      if (ids[i] === ids[i - 1] + 1) sequential++;
    }
    const seqRatio = sequential / (ids.length - 1);
    if (seqRatio >= (intel.sequentialIdThreshold || 0.4)) {
      return {
        attackType: 'SCRAPING',
        confidence: Math.min(0.5 + seqRatio * 0.4, 0.92),
        ruleMatched: `SCRAPING_SEQUENTIAL_${Math.round(seqRatio * 100)}`,
      };
    }
  }

  // Check single endpoint focus
  if ((profile.endpointPatterns || []).length >= 4) {
    const patternCounts = {};
    profile.endpointPatterns.forEach(p => { patternCounts[p] = (patternCounts[p] || 0) + 1; });
    const maxCount = Math.max(...Object.values(patternCounts));
    const focusRatio = maxCount / profile.endpointPatterns.length;
    if (focusRatio >= (intel.singleEndpointFocusRatio || 0.75)) {
      // Only if bot-like UA (if required)
      const isBotUA = isBotUserAgent(profile);
      if (!intel.botUARequired || isBotUA) {
        return {
          attackType: 'SCRAPING',
          confidence: Math.min(0.4 + focusRatio * 0.4, 0.88),
          ruleMatched: `SCRAPING_FOCUS_${Math.round(focusRatio * 100)}`,
        };
      }
    }
  }

  return null;
}

function isBotUserAgent(profile) {
  for (const ua of (profile.userAgents || [])) {
    const lower = (ua || '').toLowerCase();
    if (BOT_UA_PATTERNS.some(p => lower.includes(p))) return true;
  }
  return false;
}

/**
 * Get the severity level for an attack type from the config.
 */
export function getAttackSeverity(attackType) {
  return attackIntel[attackType]?.severity || 'medium';
}

/**
 * Get a human-readable label for an attack type.
 */
export function getAttackLabel(attackType) {
  const labels = {
    SQL_INJECTION: 'SQL Injection',
    XSS: 'Cross-Site Scripting',
    PATH_TRAVERSAL: 'Path Traversal',
    BRUTE_FORCE: 'Brute Force',
    CREDENTIAL_STUFFING: 'Credential Stuffing',
    DDOS: 'DDoS / Volumetric',
    SCRAPING: 'Web Scraping / Enumeration',
    ANOMALY: 'Anomalous Behavior',
    NORMAL: 'Normal Traffic',
  };
  return labels[attackType] || attackType;
}
