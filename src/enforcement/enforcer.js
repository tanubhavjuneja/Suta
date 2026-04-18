// src/enforcement/enforcer.js
// ═══════════════════════════════════════════════════════════════
// Enforcement Layer
//
// RULE: The ONLY hardcoded logic in this file is score thresholds.
// All intelligence (score, classification, recommendation) comes
// from Hindsight reflect(). This module just acts on it.
// ═══════════════════════════════════════════════════════════════
import { config } from '../runtimeConfig.js';

const { blockScore, throttleScore, monitorScore } = config.enforcement;

/**
 * Make an enforcement decision based ONLY on Hindsight's output.
 *
 * @param {object|null} assessment - The structured_output from reflect()
 * @returns {{ action: string, statusCode: number, delay: number, reason: string }}
 */
export function enforce(assessment) {
  // No assessment available yet (buffer hasn't filled) → allow
  if (!assessment) {
    return {
      action: 'allow',
      statusCode: 200,
      delay: 0,
      reason: 'Insufficient data for assessment',
    };
  }

  const score = assessment.threat_score ?? 0;
  const recommended = assessment.recommended_action || 'allow';
  const classification = assessment.classification || 'unknown';
  const reasoning = assessment.reasoning || '';

  // ── Score-based enforcement (the ONLY allowed thresholds) ────

  if (score >= blockScore) {
    return {
      action: 'block',
      statusCode: 403,
      delay: 0,
      reason: `Blocked: threat_score=${score}, classification=${classification}. ${reasoning}`,
    };
  }

  if (score >= throttleScore) {
    return {
      action: 'throttle',
      statusCode: 429,
      delay: 3000, // 3 second delay
      reason: `Throttled: threat_score=${score}, classification=${classification}. ${reasoning}`,
    };
  }

  if (score >= monitorScore) {
    return {
      action: 'monitor',
      statusCode: 200,
      delay: 0,
      reason: `Monitoring: threat_score=${score}, classification=${classification}. ${reasoning}`,
    };
  }

  return {
    action: 'allow',
    statusCode: 200,
    delay: 0,
    reason: `Allowed: threat_score=${score}. ${reasoning}`,
  };
}

/**
 * Apply the enforcement decision to an Express response.
 * Returns true if the request was blocked (caller should stop pipeline).
 */
export async function applyEnforcement(res, decision) {
  // Add enforcement headers regardless of decision
  res.set('X-Threat-Score', String(decision.statusCode === 200 ? 0 : 1));
  res.set('X-Enforcement-Action', decision.action);

  if (decision.action === 'block') {
    res.status(403).json({
      error: 'Forbidden',
      message: 'Your request has been blocked due to suspicious activity.',
      action: decision.action,
    });
    return true;
  }

  if (decision.action === 'throttle') {
    // Apply delay
    await new Promise((r) => setTimeout(r, decision.delay));
    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Your requests are being rate limited.',
      retryAfter: Math.ceil(decision.delay / 1000),
      action: decision.action,
    });
    return true;
  }

  // 'monitor' and 'allow' both pass through
  return false;
}
