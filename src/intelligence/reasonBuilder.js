// src/intelligence/reasonBuilder.js
// ═══════════════════════════════════════════════════════════════
// Builds structured reason objects explaining WHY an action
// was taken against an actor. Produces human-readable summaries
// and machine-parseable evidence objects.
//
// This is the "explainability engine" — it doesn't decide,
// it explains.
// ═══════════════════════════════════════════════════════════════

/**
 * Build a structured reason object for an enforcement action.
 *
 * @param {object} params
 * @param {string} params.attackType     - Classified attack type
 * @param {number} params.confidence     - Classification confidence (0-1)
 * @param {string} params.ruleMatched    - Rule ID that matched
 * @param {number} params.score          - Behavioral score (0-100)
 * @param {string[]} params.signals      - Behavioral signal descriptions
 * @param {object} params.profile        - Actor behavioral profile
 * @param {object} params.tracker        - Attack tracker data for this actor
 * @returns {object} Structured reason object
 */
export function buildReason({
  attackType,
  confidence,
  ruleMatched,
  score,
  signals,
  profile,
  tracker,
}) {
  const reasons = buildHumanReasons(attackType, signals, profile);
  const features = extractKeyFeatures(profile);
  const history = buildHistory(profile, tracker);

  return {
    attackType: attackType || 'ANOMALY',
    confidence: Math.round((confidence || 0) * 100) / 100,
    ruleMatched: ruleMatched || null,
    mlScore: score || 0,
    reasons,
    features,
    history,
  };
}

// ═══════════════════════════════════════════════════════════════
//  Human-readable reason strings
// ═══════════════════════════════════════════════════════════════

function buildHumanReasons(attackType, signals, profile) {
  const reasons = [];

  // Add attack-type-specific reasons
  switch (attackType) {
    case 'SQL_INJECTION':
      reasons.push('Suspicious SQL keywords detected in request payload');
      break;
    case 'XSS':
      reasons.push('Cross-site scripting patterns found in request');
      break;
    case 'PATH_TRAVERSAL':
      reasons.push('Directory traversal attempt detected');
      break;
    case 'BRUTE_FORCE':
      reasons.push(`${profile?.authEndpointCount || 'Multiple'} auth endpoint hits detected`);
      break;
    case 'CREDENTIAL_STUFFING':
      reasons.push('Repeated auth attempts without valid authentication');
      break;
    case 'DDOS': {
      const elapsed = profile ? (Date.now() - profile.firstSeen) / 1000 : 0;
      const rps = profile ? (profile.requestCount / Math.max(elapsed, 1)).toFixed(1) : '?';
      reasons.push(`High request volume: ${profile?.requestCount || '?'} requests (${rps} req/s)`);
      break;
    }
    case 'SCRAPING':
      reasons.push('Automated data harvesting pattern detected');
      if (profile?.sequentialIds?.length > 3) {
        reasons.push('Sequential ID enumeration pattern');
      }
      break;
    case 'ANOMALY':
      reasons.push('Unusual behavioral pattern detected');
      break;
  }

  // Add signal-derived reasons
  if (signals && signals.length > 0) {
    for (const signal of signals) {
      const readable = signalToReadable(signal);
      if (readable && !reasons.includes(readable)) {
        reasons.push(readable);
      }
    }
  }

  // Cap at 5 reasons
  return reasons.slice(0, 5);
}

/**
 * Convert a behavioral signal string to a human-readable reason.
 */
function signalToReadable(signal) {
  if (signal.startsWith('auth_repetition')) return 'Repeated authentication endpoint access';
  if (signal.startsWith('bot_ua')) return 'Non-browser User-Agent detected';
  if (signal.startsWith('sparse_headers')) return 'Missing standard browser headers';
  if (signal.startsWith('sequential_ids')) return 'Sequential resource ID enumeration';
  if (signal.startsWith('endpoint_focus')) return 'Excessive focus on single endpoint';
  if (signal.startsWith('low_variance')) return 'Machine-like request timing consistency';
  if (signal.startsWith('high_volume')) return 'High request volume in short timeframe';
  if (signal.startsWith('ip_rotation')) return 'Multiple source IPs for same fingerprint';
  if (signal.startsWith('cred_stuffing')) return 'Credential stuffing pattern (no auth token)';
  if (signal.startsWith('rate_burst')) return 'Request rate burst detected';
  if (signal === 'insufficient_data') return null;
  return null;
}

// ═══════════════════════════════════════════════════════════════
//  Key features snapshot
// ═══════════════════════════════════════════════════════════════

function extractKeyFeatures(profile) {
  if (!profile) return {};

  const elapsed = (Date.now() - profile.firstSeen) / 1000;

  return {
    requestCount: profile.requestCount || 0,
    authEndpointCount: profile.authEndpointCount || 0,
    uniqueIPs: profile.ips ? (profile.ips.size || 0) : 0,
    hasAuth: profile.hasAuth || false,
    requestsPerSecond: elapsed > 0
      ? Math.round((profile.requestCount / elapsed) * 100) / 100
      : 0,
    sequentialIdCount: profile.sequentialIds?.length || 0,
    endpointPatternCount: new Set(profile.endpointPatterns || []).size,
  };
}

// ═══════════════════════════════════════════════════════════════
//  History / timeline
// ═══════════════════════════════════════════════════════════════

function buildHistory(profile, tracker) {
  const history = {
    attempts: profile?.requestCount || 0,
    firstSeen: profile?.firstSeen
      ? new Date(profile.firstSeen).toISOString()
      : null,
    predictedBeforeBlock: tracker?.predicted || false,
  };

  if (tracker) {
    history.suspicionStage = tracker.suspicionStage || 'NONE';
    history.stageTransitions = tracker.transitions?.length || 0;
  }

  return history;
}
