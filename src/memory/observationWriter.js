// src/memory/observationWriter.js
// ═══════════════════════════════════════════════════════════════
// Converts raw session analysis + ML output into natural language
// reports that Hindsight can understand, extract facts from,
// and build observations over time.
//
// This is the MOST IMPORTANT file for Hindsight quality.
// Good prose = good memories = good threat detection.
// ═══════════════════════════════════════════════════════════════

/**
 * Convert a single parsed request into a one-line observation.
 * Used for real-time per-request retain (lightweight).
 *
 * @param {string} actorId
 * @param {object} parsed - parsed request metadata
 * @param {object|null} mlResult - Transformer model output (optional)
 */
export function composeRequestObservation(actorId, parsed, mlResult = null) {
  const lines = [];

  lines.push(`Actor ${actorId} performed ${parsed.method} request to ${parsed.path}.`);

  if (parsed.userAgent !== 'missing') {
    lines.push(`User-Agent: ${parsed.userAgent}.`);
  } else {
    lines.push(`No User-Agent header present — possible bot or script.`);
  }

  if (parsed.authType === 'none') {
    lines.push(`No authentication token present.`);
  } else {
    lines.push(`Authentication type: ${parsed.authType}.`);
  }

  if (parsed.queryParams > 0) {
    lines.push(`Query parameters: ${parsed.queryKeys.join(', ')}.`);
  }

  if (parsed.bodyShape !== 'empty') {
    lines.push(`Request body shape: ${parsed.bodyShape}.`);
  }

  // ── ML Signal ─────────────────────────────────────────────
  if (mlResult && mlResult.model_ready) {
    lines.push(`Transformer model assigned a risk score of ${mlResult.ml_risk_score.toFixed(1)} indicating ${mlResult.attack_type} behavior (confidence: ${mlResult.confidence}%).`);
  }

  lines.push(`Source IP: ${parsed.ip}. Timestamp: ${parsed.isoTimestamp}.`);

  return lines.join(' ');
}

/**
 * Convert a full session analysis + ML output into a comprehensive threat report.
 * This is retained as a single document in Hindsight.
 *
 * @param {object} analysis - session analysis from SessionBuffer
 * @param {object|null} mlResult - Transformer model output (optional)
 */
export function composeSessionReport(analysis, mlResult = null) {
  const lines = [];

  // Header
  lines.push(`API Abuse Session Report`);
  lines.push(`Report generated: ${new Date().toISOString()}`);
  lines.push(``);

  // Actor identification
  lines.push(`Actor Fingerprint: ${analysis.actorId}`);
  lines.push(`Session ID: ${analysis.sessionId}`);
  lines.push(`Session window: ${analysis.startTime} to ${analysis.endTime}`);
  lines.push(`Total duration: ${analysis.durationMs}ms`);
  lines.push(`Total requests: ${analysis.requestCount}`);
  lines.push(``);

  // ── ML Intelligence Section ───────────────────────────────
  if (mlResult && mlResult.model_ready) {
    lines.push(`Machine Learning Analysis (Transformer Model):`);
    lines.push(`- Risk Score: ${mlResult.ml_risk_score.toFixed(1)}/100`);
    lines.push(`- Classification: ${mlResult.attack_type}`);
    lines.push(`- Confidence: ${mlResult.confidence}%`);

    // Probability breakdown
    if (mlResult.attack_probabilities) {
      const sorted = Object.entries(mlResult.attack_probabilities)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 3);
      lines.push(`- Top probabilities: ${sorted.map(([t, p]) => `${t} (${p}%)`).join(', ')}`);
    }

    if (mlResult.ml_risk_score >= 70) {
      lines.push(`- ML ALERT: High risk score detected by Transformer model.`);
    } else if (mlResult.ml_risk_score >= 40) {
      lines.push(`- ML WARNING: Elevated risk score from Transformer model.`);
    } else {
      lines.push(`- ML indicates normal behavior pattern.`);
    }
    lines.push(``);
  }

  // Network footprint
  lines.push(`Network Footprint:`);
  lines.push(`- Source IPs observed: ${analysis.ips.join(', ')} (${analysis.ipCount} unique)`);
  if (analysis.ipCount > 1) {
    lines.push(`- Multiple IPs detected — possible IP rotation or distributed infrastructure.`);
  }
  if (analysis.isUpdate) {
    lines.push(`- UPDATED: New IP addresses added to existing actor profile.`);
  }
  lines.push(``);

  // Endpoint analysis
  lines.push(`Endpoint Access Pattern:`);
  lines.push(`- Unique endpoints: ${analysis.uniqueEndpoints.join(', ')}`);
  lines.push(`- Endpoint diversity ratio: ${analysis.endpointDiversity.toFixed(2)} (${analysis.uniqueEndpoints.length} unique out of ${analysis.requestCount} requests)`);

  if (analysis.endpointDiversity < 0.2) {
    lines.push(`- Low diversity — actor is hammering a small number of endpoints repeatedly.`);
  } else if (analysis.endpointDiversity > 0.8) {
    lines.push(`- High diversity — actor is exploring many different endpoints (possible reconnaissance).`);
  }

  // Check for sequential patterns
  const sequentialEndpoints = detectSequentialPattern(analysis.endpoints);
  if (sequentialEndpoints) {
    lines.push(`- Sequential/enumeration pattern detected: ${sequentialEndpoints}`);
  }
  lines.push(``);

  // Timing analysis
  lines.push(`Timing Analysis:`);
  lines.push(`- Average interval between requests: ${analysis.avgIntervalMs}ms`);
  lines.push(`- Standard deviation: ${analysis.stdDevMs}ms`);
  lines.push(`- Min interval: ${analysis.minIntervalMs}ms, Max interval: ${analysis.maxIntervalMs}ms`);

  if (analysis.avgIntervalMs < 100 && analysis.stdDevMs < 20) {
    lines.push(`- MACHINE-LIKE PRECISION: Very low interval with very low variance. Strong bot indicator.`);
  } else if (analysis.avgIntervalMs < 200) {
    lines.push(`- Fast request rate — faster than typical human interaction.`);
  }

  if (analysis.stdDevMs < 15 && (analysis.intervals?.length || 0) > 3) {
    lines.push(`- Extremely consistent timing (σ < 15ms) — characteristic of automated tools.`);
  }
  lines.push(``);

  // Authentication analysis
  lines.push(`Authentication Pattern:`);
  lines.push(`- Auth pattern: ${analysis.authPattern}`);
  lines.push(`- Auth presence ratio: ${(analysis.authPresenceRatio * 100).toFixed(0)}% of requests`);
  if (analysis.authPattern === 'no_auth') {
    lines.push(`- No authentication across all requests — unauthenticated scanning/probing.`);
  } else if (analysis.authPattern === 'intermittent_auth') {
    lines.push(`- Inconsistent auth — some requests authenticated, some not. Possible credential testing.`);
  } else if (analysis.authPattern === 'mixed_auth_types') {
    lines.push(`- Multiple auth mechanisms used — possible credential type probing.`);
  }
  lines.push(``);

  // Request content
  if (analysis.bodyShapes?.length > 0) {
    lines.push(`Request Content Shapes:`);
    lines.push(`- Observed body shapes: ${analysis.bodyShapes.join(', ')}`);
    lines.push(``);
  }

  // Header signature
  if (analysis.headerSignature) {
    const sig = analysis.headerSignature;
    lines.push(`Header Profile:`);
    lines.push(`- Total headers: ${sig.headerCount}`);
    if (sig.missingHeaders?.length > 0) {
      lines.push(`- Missing expected headers: ${sig.missingHeaders.join(', ')}`);
    }
    lines.push(``);
  }

  // User agent
  lines.push(`Client Identity:`);
  lines.push(`- User-Agent: ${analysis.userAgent}`);
  lines.push(``);

  // Request samples
  const samples = analysis.sampleRequests || [];
  if (samples.length > 0) {
    lines.push(`Sample Requests (first ${samples.length}):`);
    for (const s of samples) {
      lines.push(`- ${s.method} ${s.path} [auth:${s.authType}] body:${s.bodyShape} at ${s.timestamp}`);
    }
  }

  return lines.join('\n');
}

/**
 * Detect sequential/enumeration access patterns.
 * e.g. GET /api/users/1, GET /api/users/2, GET /api/users/3 ...
 */
function detectSequentialPattern(endpoints) {
  // Extract numeric IDs from paths
  const ids = endpoints
    .map((ep) => {
      const match = ep.match(/\/(\d+)(?:\/|$|\?)/);
      return match ? parseInt(match[1], 10) : null;
    })
    .filter((id) => id !== null);

  if (ids.length < 3) return null;

  // Check if IDs are sequential
  let sequential = 0;
  for (let i = 1; i < ids.length; i++) {
    if (ids[i] === ids[i - 1] + 1) sequential++;
  }

  const ratio = sequential / (ids.length - 1);
  if (ratio > 0.6) {
    return `${ids.length} sequential IDs detected (${ids[0]} → ${ids[ids.length - 1]}), continuity ratio: ${ratio.toFixed(2)}`;
  }

  return null;
}
