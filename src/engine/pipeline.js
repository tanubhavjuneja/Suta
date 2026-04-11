// src/engine/pipeline.js
// ═══════════════════════════════════════════════════════════════
// THE CORE PIPELINE — HYBRID ML + MEMORY ARCHITECTURE (v2)
//
// FALSE POSITIVE PREVENTION:
//   - ML score < 30 → ALLOW immediately (no Hindsight call)
//   - ML score 30-60 → recall only (check known actors)
//   - ML score > 60 → full pipeline (recall + reflect + enforce)
//   - Known actors from recall → always assess regardless of ML
//
// Pipeline: Ingest → ML Score → Gate → Recall → Buffer → Reflect → Enforce
// ═══════════════════════════════════════════════════════════════
import { generateFingerprint } from '../ingestion/fingerprintGenerator.js';
import { parseRequest } from '../ingestion/requestParser.js';
import sessionBuffer from '../ingestion/sessionBuffer.js';
import memoryLayer from '../memory/memoryLayer.js';
import { enforce, applyEnforcement } from '../enforcement/enforcer.js';
import ipBlocklist from '../enforcement/ipBlocklist.js';
import { extractFeatures, extractRequestFeatures } from '../ml/featureExtractor.js';
import trainingManager from '../ml/trainingManager.js';
import eventLog from './eventLog.js';

// ── Caches ───────────────────────────────────────────────────
const assessmentCache = new Map(); // actorId → { assessment, timestamp }
const CACHE_TTL = 5 * 60_000; // 5 minutes (was 1 min — too aggressive)

// Per-actor request history for ML
const actorRequestHistory = new Map();
const MAX_HISTORY = 30;

// Track which actors have already been retained to avoid duplicates
const retainedActors = new Set();

// ML risk thresholds — determines which pipeline stages to run
const ML_GATE = {
  ALLOW_FAST: 25,     // Below this → skip Hindsight entirely
  RECALL_ONLY: 55,    // Below this → recall but don't reflect
  FULL_PIPELINE: 55,  // Above this → full pipeline
};

/**
 * Express middleware — the beating heart of the engine.
 */
export async function abuseDetectionPipeline(req, res, next) {
  try {
    // ── Step 1: Parse + Fingerprint ──────────────────────────
    const parsed = parseRequest(req);
    const actorId = generateFingerprint(req);
    parsed.actorId = actorId;
    req.actorId = actorId;

    const clientIp = parsed.ip;
    eventLog.request(actorId, parsed.method, parsed.path, clientIp);

    // ── Step 2: Sandbox IP blocklist check ───────────────────
    if (ipBlocklist.isBlocked(clientIp)) {
      const entry = ipBlocklist.getEntry(clientIp);
      eventLog.enforcement(actorId, 'block', entry.score, 'ip-blocklist');
      res.status(403).json({
        error: 'BLOCKED',
        reason: 'IP is temporarily blocked',
        actor: actorId,
        expires: entry.expiresAt,
      });
      return;
    }

    // ── Step 3: Check assessment cache ───────────────────────
    const cached = assessmentCache.get(actorId);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      const decision = enforce(cached.assessment);
      if (decision.action === 'block') {
        eventLog.enforcement(actorId, 'block', cached.assessment.threat_score, 'cached');
        // Block the IP in sandbox
        ipBlocklist.block(clientIp, actorId, cached.assessment.classification, cached.assessment.threat_score);
        eventLog.log('ip_blocked', { ip: clientIp, actorId, score: cached.assessment.threat_score });
        const blocked = await applyEnforcement(res, decision);
        if (blocked) return;
      }
      // For throttle/monitor from cache — let it through but log
      if (decision.action === 'throttle') {
        eventLog.enforcement(actorId, 'throttle', cached.assessment.threat_score, 'cached');
      }
      // Don't block or throttle from cache alone (reduce false positives)
      // Only block if the score is VERY high (>= 90)
      if (decision.action === 'block' && cached.assessment.threat_score < 90) {
        // Downgrade to monitor for borderline cases
        next();
        return;
      }
    }

    // ── Step 4: ML Scoring ───────────────────────────────────
    if (!actorRequestHistory.has(actorId)) actorRequestHistory.set(actorId, []);
    const history = actorRequestHistory.get(actorId);
    history.push(parsed);
    if (history.length > MAX_HISTORY) history.shift();

    let mlResult = null;
    try {
      const features = extractRequestFeatures(parsed, history);
      mlResult = await trainingManager.predict(features);
      if (mlResult.model_ready) {
        eventLog.log('ml_score', {
          actorId,
          ml_risk_score: mlResult.ml_risk_score,
          attack_type: mlResult.attack_type,
          confidence: mlResult.confidence,
        });
      }
    } catch (e) {
      eventLog.error('ML scoring failed', e.message);
    }

    const mlScore = mlResult?.ml_risk_score || 0;

    // ── Step 5: ML Gate — FAST ALLOW for low-risk requests ───
    if (mlScore < ML_GATE.ALLOW_FAST && !cached) {
      // Low ML risk + no prior assessment = definitely not malicious
      // Buffer the request but don't call Hindsight
      sessionBuffer.add(actorId, parsed);
      next();
      return;
    }

    // ── Step 6: Buffer request ───────────────────────────────
    const analysis = sessionBuffer.add(actorId, parsed);

    if (!analysis) {
      // Buffer not full yet — let the request through
      next();
      return;
    }

    // ── Step 7: Session-level ML scoring ─────────────────────
    let sessionMlResult = mlResult;
    try {
      const sessionFeatures = extractFeatures(analysis);
      sessionMlResult = await trainingManager.predict(sessionFeatures);
      eventLog.log('ml_session_score', {
        actorId,
        ml_risk_score: sessionMlResult.ml_risk_score,
        attack_type: sessionMlResult.attack_type,
        confidence: sessionMlResult.confidence,
        requestCount: analysis.requestCount,
      });
    } catch (e) {
      eventLog.error('Session ML scoring failed', e.message);
    }

    const sessionMlScore = sessionMlResult?.ml_risk_score || 0;

    // ── Step 8: ML Gate on session score ─────────────────────
    if (sessionMlScore < ML_GATE.RECALL_ONLY) {
      // Session ML says low risk — skip Hindsight, allow through
      next();
      return;
    }

    // ── Step 9: Recall — is this a known bad actor? ──────────
    let recallResult = null;
    let isKnownActor = false;
    try {
      recallResult = await memoryLayer.recallActor(actorId);
      isKnownActor = recallResult?.results?.length > 0;
      eventLog.recall(actorId, isKnownActor, recallResult?.results?.length || 0);
    } catch (e) {
      eventLog.error('Recall failed', e.message);
    }

    // ── Step 10: Reflect — AI threat assessment (ML + Memory) ─
    // Only reflect if ML score is high enough OR actor is known
    if (sessionMlScore >= ML_GATE.FULL_PIPELINE || isKnownActor) {
      try {
        const assessment = await runThreatAssessment(actorId, analysis, recallResult, sessionMlResult);

        if (assessment) {
          const decision = enforce(assessment);
          eventLog.enforcement(actorId, decision.action, assessment.threat_score, 'full-analysis');

          // Retain session for future recall (only if not already retained for this actor)
          if (!retainedActors.has(actorId)) {
            retainedActors.add(actorId);
            memoryLayer.retainSession(analysis, sessionMlResult, recallResult).then(() => {
              eventLog.retained(actorId, analysis.sessionId, analysis.requestCount);
            }).catch((e) => eventLog.error('Retain failed', e.message));
          }

          // Apply enforcement
          if (decision.action === 'block') {
            ipBlocklist.block(clientIp, actorId, assessment.classification, assessment.threat_score);
            eventLog.log('ip_blocked', { ip: clientIp, actorId, score: assessment.threat_score });
          }

          const blocked = await applyEnforcement(res, decision);
          if (blocked) return;
        }
      } catch (e) {
        eventLog.error('Full analysis failed', e.message);
      }
    }

    // ── Step 11: Pass through ────────────────────────────────
    next();
  } catch (e) {
    eventLog.error('Pipeline error', e.message);
    next(); // Fail open — don't break the API
  }
}

// ── Helpers ───────────────────────────────────────────────────

async function runThreatAssessment(actorId, analysis, recallResult, mlResult = null) {
  try {
    const result = await memoryLayer.assessThreat(analysis, recallResult, mlResult);
    const assessment = result?.structured_output || result?.structuredOutput || null;

    if (assessment) {
      assessmentCache.set(actorId, { assessment, timestamp: Date.now() });
      eventLog.assessment(
        actorId,
        assessment.threat_score,
        assessment.classification,
        assessment.recommended_action,
        assessment.confidence
      );
    }

    return assessment;
  } catch (e) {
    eventLog.error('Threat assessment failed', e.message);
    return null;
  }
}
