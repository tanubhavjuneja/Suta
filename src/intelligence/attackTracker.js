// src/intelligence/attackTracker.js
// ═══════════════════════════════════════════════════════════════
// Per-actor attack timeline tracker.
// Tracks suspicion stage progression, stores evidence (last N
// suspicious requests), and records prediction state.
//
// Stages: NONE → LOW → MEDIUM → HIGH → BLOCKED
// ═══════════════════════════════════════════════════════════════

const STAGES = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'BLOCKED'];
const MAX_EVIDENCE = 5;
const MAX_TRACKED_ACTORS = 500; // Prevent memory growth

class AttackTracker {
  constructor() {
    this.actors = new Map(); // actorId → TrackerEntry
  }

  /**
   * Get or create a tracker entry for an actor.
   */
  _getEntry(actorId) {
    if (!this.actors.has(actorId)) {
      // Evict oldest if at capacity
      if (this.actors.size >= MAX_TRACKED_ACTORS) {
        const oldest = this.actors.keys().next().value;
        this.actors.delete(oldest);
      }

      this.actors.set(actorId, {
        actorId,
        suspicionStage: 'NONE',
        predicted: false,
        evidence: [],
        transitions: [],
        firstSeen: Date.now(),
        lastUpdated: Date.now(),
      });
    }
    return this.actors.get(actorId);
  }

  /**
   * Update an actor's tracking state based on their current score.
   *
   * @param {string} actorId
   * @param {number} score - Current behavioral score (0-100)
   * @param {string} action - Enforcement action ('allow', 'throttle', 'block')
   * @param {object} [requestSnapshot] - Optional { method, endpoint, body } to store as evidence
   * @returns {object} Current tracker entry
   */
  update(actorId, score, action, requestSnapshot = null) {
    const entry = this._getEntry(actorId);
    entry.lastUpdated = Date.now();

    // ── Determine new stage from score ──────────────────────
    const newStage = this._scoreToStage(score, action);

    // ── Record stage transition if changed ──────────────────
    if (newStage !== entry.suspicionStage) {
      const oldStage = entry.suspicionStage;
      entry.transitions.push({
        from: oldStage,
        to: newStage,
        timestamp: new Date().toISOString(),
        score,
      });
      // Keep only last 10 transitions
      if (entry.transitions.length > 10) {
        entry.transitions = entry.transitions.slice(-10);
      }
      entry.suspicionStage = newStage;
    }

    // ── Track prediction ────────────────────────────────────
    // If score is in warning range but not yet blocked, mark as predicted
    if (score >= 50 && action !== 'block' && !entry.predicted) {
      entry.predicted = true;
    }

    // ── Store evidence for suspicious requests ──────────────
    if (requestSnapshot && score >= 40) {
      entry.evidence.push({
        timestamp: new Date().toISOString(),
        method: requestSnapshot.method || '?',
        endpoint: requestSnapshot.endpoint || '?',
        score,
        ...(requestSnapshot.body ? { payload: truncate(stringify(requestSnapshot.body), 100) } : {}),
      });
      // Keep only last N
      if (entry.evidence.length > MAX_EVIDENCE) {
        entry.evidence = entry.evidence.slice(-MAX_EVIDENCE);
      }
    }

    return entry;
  }

  /**
   * Get the current tracker data for an actor.
   */
  get(actorId) {
    return this.actors.get(actorId) || null;
  }

  /**
   * Get a display-friendly timeline for an actor.
   */
  getTimeline(actorId) {
    const entry = this.actors.get(actorId);
    if (!entry) return null;

    return {
      actorId,
      suspicionStage: entry.suspicionStage,
      predicted: entry.predicted,
      evidenceCount: entry.evidence.length,
      evidence: entry.evidence,
      transitions: entry.transitions,
      firstSeen: new Date(entry.firstSeen).toISOString(),
      lastUpdated: new Date(entry.lastUpdated).toISOString(),
    };
  }

  /**
   * Get evidence strings for an actor (for event payloads).
   */
  getEvidenceSummary(actorId) {
    const entry = this.actors.get(actorId);
    if (!entry || entry.evidence.length === 0) return [];

    return entry.evidence.map(e => {
      let summary = `${e.method} ${e.endpoint}`;
      if (e.payload) summary += ` {${e.payload}}`;
      return summary;
    });
  }

  /**
   * Map score + action to a suspicion stage.
   */
  _scoreToStage(score, action) {
    if (action === 'block') return 'BLOCKED';
    if (score >= 70) return 'HIGH';
    if (score >= 50) return 'MEDIUM';
    if (score >= 30) return 'LOW';
    return 'NONE';
  }

  /**
   * Clean up expired entries (called periodically).
   */
  cleanup(maxAgeMs = 30 * 60_000) {
    const now = Date.now();
    for (const [actorId, entry] of this.actors) {
      if (now - entry.lastUpdated > maxAgeMs) {
        this.actors.delete(actorId);
      }
    }
  }
}

// ── Helpers ───────────────────────────────────────────────────

function stringify(val) {
  if (typeof val === 'string') return val;
  try { return JSON.stringify(val); }
  catch { return String(val); }
}

function truncate(str, len) {
  if (!str || str.length <= len) return str;
  return str.substring(0, len) + '…';
}

// Singleton — runs inside the pipelineWorker thread
const attackTracker = new AttackTracker();

// Periodic cleanup every 5 minutes
setInterval(() => attackTracker.cleanup(), 5 * 60_000);

export default attackTracker;
