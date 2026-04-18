// src/ml/featureExtractor.js
// ═══════════════════════════════════════════════════════════════
// Converts raw request metadata into a numerical feature vector
// that the Transformer model consumes.
//
// Features are designed to capture bot-vs-human behavioral signals
// without encoding any attack rules — the model learns patterns.
// ═══════════════════════════════════════════════════════════════
import { BOT_UA_PATTERNS, BROWSER_HEADERS } from './constants.js';

// Feature indices (for documentation — the model just sees numbers)
export const FEATURE_NAMES = [
  'request_rate',           // 0: requests/second in current window
  'interval_mean',          // 1: mean ms between requests (normalized)
  'interval_stddev',        // 2: stddev of intervals (normalized)
  'interval_cv',            // 3: coefficient of variation (stddev/mean)
  'endpoint_diversity',     // 4: unique endpoints / total requests
  'is_single_endpoint',     // 5: 1 if only one endpoint hit
  'method_is_post',         // 6: ratio of POST requests
  'method_is_get',          // 7: ratio of GET requests
  'has_auth',               // 8: ratio of requests with auth
  'auth_type_count',        // 9: number of distinct auth types (normalized)
  'header_count',           // 10: normalized header count
  'missing_browser_headers',// 11: count of missing browser-standard headers (normalized)
  'has_user_agent',         // 12: 1 if User-Agent present
  'ua_is_bot_like',         // 13: 1 if UA suggests automation tool
  'body_shape_diversity',   // 14: unique body shapes / total requests
  'ip_count',               // 15: number of distinct IPs (normalized)
  'has_sequential_ids',     // 16: 1 if sequential numeric IDs detected in paths
  'query_param_diversity',  // 17: variety of query parameters
  'error_rate',             // 18: ratio of 4xx/5xx responses (if known)
  'burst_score',            // 19: how "bursty" the timing is
];

export const FEATURE_COUNT = FEATURE_NAMES.length;

// Known bot/automation User-Agent fragments
/**
 * Extract a numerical feature vector from a session analysis object.
 * Returns a Float32Array of length FEATURE_COUNT.
 *
 * This function does NOT make any classification decisions —
 * it just converts metadata into numbers for the model.
 */
export function extractFeatures(analysis) {
  const features = new Float32Array(FEATURE_COUNT);

  // 0: Request rate (requests/second)
  const durationSec = Math.max(analysis.durationMs / 1000, 0.1);
  features[0] = clamp(analysis.requestCount / durationSec, 0, 100) / 100;

  // 1: Mean interval (normalized to 0-1, where 0 = instant, 1 = 10s+)
  features[1] = clamp(analysis.avgIntervalMs / 10000, 0, 1);

  // 2: Stddev of intervals (normalized)
  features[2] = clamp(analysis.stdDevMs / 5000, 0, 1);

  // 3: Coefficient of variation (stddev/mean) — low = machine-like precision
  features[3] = analysis.avgIntervalMs > 0
    ? clamp(analysis.stdDevMs / analysis.avgIntervalMs, 0, 2) / 2
    : 0;

  // 4: Endpoint diversity
  features[4] = clamp(analysis.endpointDiversity || 0, 0, 1);

  // 5: Is single endpoint
  features[5] = (analysis.uniqueEndpoints?.length || 0) === 1 ? 1 : 0;

  // 6-7: Method distribution
  const endpoints = analysis.endpoints || [];
  const postCount = endpoints.filter((e) => e.startsWith('POST')).length;
  const getCount = endpoints.filter((e) => e.startsWith('GET')).length;
  const total = Math.max(endpoints.length, 1);
  features[6] = postCount / total;
  features[7] = getCount / total;

  // 8: Auth presence ratio
  features[8] = clamp(analysis.authPresenceRatio || 0, 0, 1);

  // 9: Auth type diversity
  const authPattern = analysis.authPattern || 'no_auth';
  features[9] = authPattern === 'mixed_auth_types' ? 1.0
    : authPattern === 'intermittent_auth' ? 0.5
    : 0.0;

  // 10: Header count (normalized, typical browser sends 10-15)
  const headerCount = analysis.headerSignature?.headerCount || 0;
  features[10] = clamp(headerCount / 20, 0, 1);

  // 11: Missing browser headers (normalized)
  const missingCount = analysis.headerSignature?.missingHeaders?.length || 0;
  features[11] = clamp(missingCount / BROWSER_HEADERS.length, 0, 1);

  // 12: Has User-Agent
  features[12] = (analysis.userAgent && analysis.userAgent !== 'missing') ? 1 : 0;

  // 13: Bot-like User-Agent
  const ua = (analysis.userAgent || '').toLowerCase();
  features[13] = BOT_UA_PATTERNS.some((p) => ua.includes(p)) ? 1 : 0;

  // 14: Body shape diversity
  const bodyShapes = analysis.bodyShapes || [];
  features[14] = bodyShapes.length > 0
    ? clamp(new Set(bodyShapes).size / Math.max(analysis.requestCount, 1), 0, 1)
    : 0;

  // 15: IP count (normalized — >1 could indicate rotation)
  features[15] = clamp((analysis.ipCount || 1) / 10, 0, 1);

  // 16: Sequential ID pattern detection
  features[16] = detectSequentialPattern(endpoints) ? 1 : 0;

  // 17: Query param diversity (computed in sessionBuffer)
  features[17] = analysis.queryParamDiversity || 0;

  // 18: Error rate (computed in sessionBuffer from response status codes)
  features[18] = analysis.errorRate || 0;

  // 19: Burst score — how concentrated are requests in small time windows
  features[19] = computeBurstScore(analysis.intervals || []);

  return features;
}

/**
 * Extract features from a minimal single-request parsed record.
 * Used for real-time per-request scoring before the session buffer fills.
 */
export function extractRequestFeatures(parsed, sessionHistory = []) {
  const features = new Float32Array(FEATURE_COUNT);

  // Compute timing from history
  if (sessionHistory.length > 1) {
    const intervals = [];
    for (let i = 1; i < sessionHistory.length; i++) {
      intervals.push(sessionHistory[i].timestamp - sessionHistory[i - 1].timestamp);
    }
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const stddev = Math.sqrt(
      intervals.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / intervals.length
    );

    const durationSec = Math.max((Date.now() - sessionHistory[0].timestamp) / 1000, 0.1);
    features[0] = clamp(sessionHistory.length / durationSec, 0, 100) / 100;
    features[1] = clamp(mean / 10000, 0, 1);
    features[2] = clamp(stddev / 5000, 0, 1);
    features[3] = mean > 0 ? clamp(stddev / mean, 0, 2) / 2 : 0;
    features[19] = computeBurstScore(intervals);

    // Feature 4: Endpoint diversity from history
    const endpoints = sessionHistory.map(r => r.path);
    const uniqueEndpoints = new Set(endpoints);
    features[4] = clamp(uniqueEndpoints.size / sessionHistory.length, 0, 1);

    // Feature 5: Is single endpoint (all same)
    features[5] = uniqueEndpoints.size === 1 ? 1 : 0;

    // Feature 14: Body shape diversity from history
    const bodyShapes = sessionHistory.map(r => r.bodyShape).filter(s => s);
    const uniqueBodyShapes = new Set(bodyShapes);
    features[14] = bodyShapes.length > 0 ? clamp(uniqueBodyShapes.size / bodyShapes.length, 0, 1) : 0;

    // Feature 15: IP count from history
    const ips = sessionHistory.map(r => r.ip).filter(ip => ip);
    const uniqueIPs = new Set(ips);
    features[15] = clamp(uniqueIPs.size / 10, 0, 1);

    // Feature 16: Sequential ID pattern from history
    features[16] = detectSequentialPattern(endpoints) ? 1 : 0;

    // Feature 17: Query param diversity from history
    const allQueryKeys = new Set();
    let totalParams = 0;
    for (const r of sessionHistory) {
      if (r.queryKeys && Array.isArray(r.queryKeys)) {
        r.queryKeys.forEach(k => allQueryKeys.add(k));
        totalParams += r.queryKeys.length;
      }
    }
    features[17] = totalParams > 0 ? clamp(allQueryKeys.size / totalParams, 0, 1) : 0;

    // Feature 18: Error rate (no history, default to 0)
    features[18] = 0;
  }

  // Method
  features[6] = parsed.method === 'POST' ? 1 : 0;
  features[7] = parsed.method === 'GET' ? 1 : 0;

  // Auth
  features[8] = parsed.authType !== 'none' ? 1 : 0;

  // Feature 9: Auth type count (default to 1 if has auth, 0 if none)
  features[9] = parsed.authType !== 'none' ? 1 : 0;

  // Headers
  features[10] = clamp((parsed.headerSignature?.headerCount || 0) / 20, 0, 1);
  features[11] = clamp((parsed.headerSignature?.missingHeaders?.length || 0) / BROWSER_HEADERS.length, 0, 1);
  features[12] = (parsed.userAgent && parsed.userAgent !== 'missing') ? 1 : 0;

  const ua = (parsed.userAgent || '').toLowerCase();
  features[13] = BOT_UA_PATTERNS.some((p) => ua.includes(p)) ? 1 : 0;

  return features;
}

// ── Helpers ───────────────────────────────────────────────────

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

function detectSequentialPattern(endpoints) {
  const ids = endpoints
    .map((ep) => {
      const match = ep.match(/\/(\d+)(?:\/|$|\?)/);
      return match ? parseInt(match[1], 10) : null;
    })
    .filter((id) => id !== null);

  if (ids.length < 3) return false;

  let sequential = 0;
  for (let i = 1; i < ids.length; i++) {
    if (ids[i] === ids[i - 1] + 1) sequential++;
  }
  return sequential / (ids.length - 1) > 0.5;
}

function computeBurstScore(intervals) {
  if (intervals.length < 2) return 0;

  // Count intervals under 100ms (burst threshold)
  const burstCount = intervals.filter((i) => i < 100).length;
  return clamp(burstCount / intervals.length, 0, 1);
}
