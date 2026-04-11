// src/memory/memoryLayer.js
// ═══════════════════════════════════════════════════════════════
// Memory Layer — ALL intelligence flows through here.
// This module is the single interface between the engine and
// Hindsight. No other module talks to Hindsight directly.
//
// Updated: Now accepts ML output to weave into observations
// and reflect queries. The Transformer score enriches the
// context but the FINAL decision still comes from reflect().
// ═══════════════════════════════════════════════════════════════
import hindsight from './hindsightClient.js';
import { composeRequestObservation, composeSessionReport } from './observationWriter.js';

// ── Threat Assessment Schema ────────────────────────────────────
// Used with reflect() — Hindsight returns structured JSON matching this.
const THREAT_SCHEMA = {
  type: 'object',
  properties: {
    threat_score: {
      type: 'integer',
      description: 'Overall threat score from 0 (safe) to 100 (definitely malicious)',
    },
    classification: {
      type: 'string',
      enum: [
        'credential_stuffing',
        'data_scraping',
        'enumeration',
        'rate_limit_evasion',
        'api_fuzzing',
        'brute_force',
        'reconnaissance',
        'legitimate',
        'unknown',
      ],
      description: 'Primary attack classification',
    },
    confidence: {
      type: 'string',
      enum: ['low', 'medium', 'high'],
      description: 'Confidence in the classification',
    },
    is_known_actor: {
      type: 'boolean',
      description: 'Whether this actor has been seen in previous sessions',
    },
    previous_sessions_estimate: {
      type: 'integer',
      description: 'Estimated number of previous sessions from this actor',
    },
    recommended_action: {
      type: 'string',
      enum: ['allow', 'monitor', 'throttle', 'captcha', 'block', 'alert'],
      description: 'Recommended enforcement action',
    },
    reasoning: {
      type: 'string',
      description: 'Detailed explanation of the threat assessment reasoning, including how ML signals and behavioral memory were combined',
    },
    behavioral_indicators: {
      type: 'array',
      items: { type: 'string' },
      description: 'List of specific behavioral indicators that influenced the score',
    },
    ml_agreement: {
      type: 'string',
      enum: ['agrees', 'disagrees', 'no_ml_data'],
      description: 'Whether the ML model output agrees with the memory-based assessment',
    },
  },
  required: [
    'threat_score',
    'classification',
    'confidence',
    'recommended_action',
    'reasoning',
  ],
};

const memoryLayer = {
  // ════════════════════════════════════════════════════════════
  //  STORE — retain a session into Hindsight memory
  // ════════════════════════════════════════════════════════════

  /**
   * Store a single request observation (lightweight, per-request)
   * Now includes ML scoring in the prose.
   */
  async retainRequest(actorId, parsedRequest, mlResult = null) {
    const observation = composeRequestObservation(actorId, parsedRequest, mlResult);

    return hindsight.retain(observation, {
      context: 'api-request-observation',
      tags: [
        `actor:${actorId}`,
        `endpoint:${parsedRequest.method}:${parsedRequest.path}`,
      ],
      observationScopes: 'per_tag',
      entities: [
        { text: actorId, type: 'THREAT_ACTOR' },
      ],
      metadata: {
        source: 'per-request',
        ip: parsedRequest.ip,
        ml_risk_score: mlResult?.ml_risk_score?.toString() || 'n/a',
        ml_attack_type: mlResult?.attack_type || 'n/a',
      },
    });
  },

  /**
   * Store a full session analysis (heavyweight, after buffer threshold)
   * Now includes ML output in the report prose.
   * If actor already exists in Hindsight (passed via recallResult or checked),
   * update with new IP addresses instead of creating duplicate.
   */
  async retainSession(analysis, mlResult = null, existingRecallResult = null) {
    const report = composeSessionReport(analysis, mlResult);
    const actorId = analysis.actorId;
    const newIPs = analysis.ips || [];

    // Check if actor already exists - use passed recall result or query
    let existingIPs = [];
    let isUpdate = false;

    if (existingRecallResult?.results?.length > 0) {
      isUpdate = true;
      const existing = existingRecallResult.results[0];
      const metadataIP = existing.metadata?.ip_addresses;
      if (metadataIP) {
        if (typeof metadataIP === 'string') {
          existingIPs = metadataIP.split(',').map(ip => ip.trim()).filter(ip => ip);
        } else if (Array.isArray(metadataIP)) {
          existingIPs = metadataIP;
        }
      }
    } else {
      // No recall result passed - check directly
      try {
        const recallResult = await hindsight.recall(
          `Threat actor profile for ${actorId}`,
          {
            types: ['observation'],
            tags: [`actor:${actorId}`],
            tagsMatch: 'any_strict',
            budget: 'low',
          }
        );

        if (recallResult?.results?.length > 0) {
          isUpdate = true;
          const existing = recallResult.results[0];
          const metadataIP = existing.metadata?.ip_addresses;
          if (metadataIP) {
            if (typeof metadataIP === 'string') {
              existingIPs = metadataIP.split(',').map(ip => ip.trim()).filter(ip => ip);
            } else if (Array.isArray(metadataIP)) {
              existingIPs = metadataIP;
            }
          }
        }
      } catch (e) {
        // Continue with new retain if recall fails
      }
    }

    // Merge IPs - combine existing + new, remove duplicates
    const allIPs = [...new Set([...existingIPs, ...newIPs])];
    const ipListStr = allIPs.join(', ');

    // Mark in report if this is an update
    analysis.isUpdate = isUpdate;

    return hindsight.retain(report, {
      context: 'api-abuse-session-report',
      documentId: `actor-${actorId}`,
      tags: [
        `actor:${actorId}`,
      ],
      observationScopes: 'per_tag',
      entities: [
        { text: actorId, type: 'THREAT_ACTOR' },
        ...allIPs.map((ip) => ({ text: ip, type: 'IP_ADDRESS' })),
      ],
      metadata: {
        source: 'session-analysis',
        requestCount: String(analysis.requestCount),
        durationMs: String(analysis.durationMs),
        avgIntervalMs: String(analysis.avgIntervalMs),
        ml_risk_score: mlResult?.ml_risk_score?.toString() || 'n/a',
        ml_attack_type: mlResult?.attack_type || 'n/a',
        ip_addresses: ipListStr,
        existing_actor: isUpdate ? 'true' : 'false',
      },
    });
  },

  // ════════════════════════════════════════════════════════════
  //  RECALL — check if we know this actor
  // ════════════════════════════════════════════════════════════

  /**
   * Check for a consolidated observation (profile) for this actor.
   * Returns the actor's behavioral profile if Hindsight has built one.
   */
  async recallActor(actorId) {
    return hindsight.recall(
      `Threat actor profile, attack history, and behavioral patterns for actor ${actorId}`,
      {
        types: ['observation'],
        tags: [`actor:${actorId}`],
        tagsMatch: 'any_strict',
        budget: 'mid',
      }
    );
  },

  /**
   * Find sessions with similar behavioral patterns across all actors.
   */
  async recallSimilarBehavior(behaviorDescription) {
    return hindsight.recall(behaviorDescription, {
      types: ['observation', 'experience'],
      budget: 'mid',
    });
  },

  // ════════════════════════════════════════════════════════════
  //  REFLECT — generate structured threat assessment
  //  THIS IS WHERE ALL FINAL INTELLIGENCE COMES FROM
  //  ML provides signals. Memory provides context.
  //  Reflect() synthesizes both into the final decision.
  // ════════════════════════════════════════════════════════════

  /**
   * Generate a structured threat assessment for an actor session.
   * Combines ML Transformer output + behavioral memory into one query.
   * The ONLY source of threat scoring in the entire system.
   *
   * @param {object} analysis - session analysis
   * @param {object|null} recallResults - actor profile from recall()
   * @param {object|null} mlResult - Transformer model output
   */
  async assessThreat(analysis, recallResults, mlResult = null) {
    const hasHistory = recallResults && recallResults.results && recallResults.results.length > 0;
    const priorProfile = hasHistory ? recallResults.results[0].text : null;
    const hasML = mlResult && mlResult.model_ready;

    const query = `
Analyze the following API session and determine if the actor is malicious.
You have TWO signal sources: a real-time Transformer ML model and a behavioral memory system.
Synthesize both to produce a final assessment.

CURRENT SESSION:
- Actor fingerprint: ${analysis.actorId}
- Request count: ${analysis.requestCount} requests over ${analysis.durationMs}ms
- Endpoints accessed: ${analysis.uniqueEndpoints.join(', ')}
- Endpoint diversity: ${analysis.endpointDiversity.toFixed(2)}
- Average request interval: ${analysis.avgIntervalMs}ms (stddev: ${analysis.stdDevMs}ms)
- Authentication: ${analysis.authPattern} (${(analysis.authPresenceRatio * 100).toFixed(0)}% of requests)
- Source IPs: ${analysis.ips.join(', ')} (${analysis.ipCount} unique)
- User-Agent: ${analysis.userAgent}

${hasML ? `TRANSFORMER ML MODEL OUTPUT:
- Risk Score: ${mlResult.ml_risk_score.toFixed(1)}/100
- Classification: ${mlResult.attack_type}
- Confidence: ${mlResult.confidence}%
- Probability breakdown: ${Object.entries(mlResult.attack_probabilities || {}).sort(([,a],[,b]) => b - a).map(([t, p]) => `${t}: ${p}%`).join(', ')}
The ML model analyzed request features (timing, headers, endpoints, auth patterns) and produced this real-time score.` : 'ML model data not available for this session.'}

${hasHistory ? `PRIOR BEHAVIORAL HISTORY (from memory):
This actor has been observed before. Consolidated profile:
${priorProfile}` : 'No prior history found for this actor — first time seen.'}

Based on ALL available information, provide a threat assessment. Consider:
1. Does the ML model's classification align with the behavioral data?
2. Does the timing signature suggest a bot or human?
3. Are the endpoints consistent with a known attack technique?
4. If there is prior history, has behavior escalated?
5. If the ML score is high but no history exists, should we monitor or act immediately?
6. If the ML score is low but history shows prior abuse, the actor may be evading detection.
7. What enforcement action should be taken?
    `.trim();

    return hindsight.reflect(query, {
      budget: 'mid',
      responseSchema: THREAT_SCHEMA,
    });
  },

  /**
   * Natural language query against the full memory bank.
   * Used for dashboard queries like "which actors are most active?"
   */
  async query(question) {
    return hindsight.reflect(question, {
      budget: 'high',
    });
  },

  /**
   * Get the threat schema (for testing/inspection)
   */
  getThreatSchema() {
    return THREAT_SCHEMA;
  },
};

export default memoryLayer;
