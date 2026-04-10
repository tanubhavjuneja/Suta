// src/ingestion/sessionBuffer.js
// ═══════════════════════════════════════════════════════════════
// Buffers N requests per actor before triggering analysis.
// Computes timing statistics, detects patterns, builds the
// session object that gets converted into a threat report.
// ═══════════════════════════════════════════════════════════════
import config from '../config.js';

class SessionBuffer {
  constructor() {
    this.sessions = new Map(); // actorId → { requests[], startTime, timer }
  }

  /**
   * Add a parsed request to the actor's session buffer.
   * Returns a session analysis object if the threshold is reached, else null.
   */
  add(actorId, parsedRequest) {
    if (!this.sessions.has(actorId)) {
      this.sessions.set(actorId, {
        requests: [],
        startTime: Date.now(),
        timer: setTimeout(() => this._expire(actorId), config.session.timeoutMs),
      });
    }

    const session = this.sessions.get(actorId);
    session.requests.push(parsedRequest);

    // Reached threshold → build analysis
    if (session.requests.length >= config.session.bufferThreshold) {
      return this._buildAnalysis(actorId);
    }

    return null;
  }

  /**
   * Force an analysis for an actor (e.g. when the fast-path recall detects a known actor)
   */
  forceAnalysis(actorId) {
    if (!this.sessions.has(actorId)) return null;
    return this._buildAnalysis(actorId);
  }

  /**
   * Get the current request count for an actor
   */
  getRequestCount(actorId) {
    const session = this.sessions.get(actorId);
    return session ? session.requests.length : 0;
  }

  // ── Internal ──────────────────────────────────────────────────

  _buildAnalysis(actorId) {
    const session = this.sessions.get(actorId);
    if (!session || session.requests.length === 0) return null;

    const requests = session.requests;
    const now = Date.now();

    // Compute timing intervals between consecutive requests
    const intervals = [];
    for (let i = 1; i < requests.length; i++) {
      intervals.push(requests[i].timestamp - requests[i - 1].timestamp);
    }

    // Unique endpoints hit
    const endpointList = requests.map((r) => `${r.method} ${r.path}`);
    const uniqueEndpoints = [...new Set(endpointList)];

    // Auth pattern analysis
    const authTypes = requests.map((r) => r.authType);
    const uniqueAuthTypes = [...new Set(authTypes)];
    const hasAuth = authTypes.filter((a) => a !== 'none').length;

    // IP tracking (even though fingerprint is IP-independent)
    const ips = [...new Set(requests.map((r) => r.ip))];

    // Body shape diversity
    const bodyShapes = [...new Set(requests.map((r) => r.bodyShape))];

    const analysis = {
      actorId,
      sessionId: `${actorId}-${session.startTime}`,
      startTime: new Date(session.startTime).toISOString(),
      endTime: new Date(now).toISOString(),
      durationMs: now - session.startTime,
      requestCount: requests.length,

      // Endpoint patterns
      endpoints: endpointList,
      uniqueEndpoints,
      endpointDiversity: uniqueEndpoints.length / requests.length,

      // Timing
      intervals,
      avgIntervalMs: intervals.length > 0
        ? Math.round(intervals.reduce((a, b) => a + b, 0) / intervals.length)
        : 0,
      stdDevMs: this._stddev(intervals),
      minIntervalMs: intervals.length > 0 ? Math.min(...intervals) : 0,
      maxIntervalMs: intervals.length > 0 ? Math.max(...intervals) : 0,

      // Auth
      authPattern: this._describeAuthPattern(authTypes, uniqueAuthTypes, hasAuth, requests.length),
      authPresenceRatio: hasAuth / requests.length,

      // Network
      ips,
      ipCount: ips.length,

      // Content
      bodyShapes,
      userAgent: requests[0]?.userAgent || 'unknown',

      // Header analysis
      headerSignature: requests[0]?.headerSignature || null,

      // Samples (first 5 for the observation report)
      sampleRequests: requests.slice(0, 5).map((r) => ({
        method: r.method,
        path: r.path,
        timestamp: r.isoTimestamp,
        authType: r.authType,
        bodyShape: r.bodyShape,
        queryParams: r.queryParams,
      })),
    };

    // Clear the session after analysis
    this._expire(actorId);

    return analysis;
  }

  _describeAuthPattern(authTypes, uniqueAuthTypes, hasAuth, total) {
    if (hasAuth === 0) return 'no_auth';
    if (hasAuth === total && uniqueAuthTypes.length === 1) return `consistent_${uniqueAuthTypes[0]}`;
    if (hasAuth < total) return 'intermittent_auth';
    if (uniqueAuthTypes.length > 1) return 'mixed_auth_types';
    return 'authenticated';
  }

  _stddev(arr) {
    if (arr.length < 2) return 0;
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const variance = arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
    return Math.round(Math.sqrt(variance));
  }

  _expire(actorId) {
    const session = this.sessions.get(actorId);
    if (session?.timer) clearTimeout(session.timer);
    this.sessions.delete(actorId);
  }
}

// Singleton
const sessionBuffer = new SessionBuffer();
export default sessionBuffer;
