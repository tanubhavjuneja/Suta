// src/engine/eventLog.js
// ═══════════════════════════════════════════════════════════════
// Central event log — records everything that happens in the
// engine for the dashboard, demo output, and debugging.
// ═══════════════════════════════════════════════════════════════
import { EventEmitter } from 'events';

class EngineEventLog extends EventEmitter {
  constructor() {
    super();
    this.events = [];
    this.maxEvents = 1000;
  }

  /**
   * Log an event. All events are timestamped and typed.
   */
  log(type, data) {
    const event = {
      id: this.events.length + 1,
      timestamp: new Date().toISOString(),
      type,
      ...data,
    };

    this.events.push(event);
    if (this.events.length > this.maxEvents) {
      this.events.shift();
    }

    // Emit for real-time consumers (WebSocket dashboard)
    this.emit('event', event);

    // Console output with color coding
    this._logToConsole(event);

    return event;
  }

  // Convenience methods
  request(actorId, method, path, ip) {
    return this.log('request', { actorId, method, path, ip });
  }

  fingerprint(actorId, ip, isNew) {
    return this.log('fingerprint', { actorId, ip, isNew });
  }

  recall(actorId, found, resultCount) {
    return this.log('recall', { actorId, found, resultCount });
  }

  assessment(actorId, score, classification, action, confidence) {
    return this.log('assessment', { actorId, score, classification, action, confidence });
  }

  enforcement(actorId, action, score, reason) {
    return this.log('enforcement', { actorId, action, score, reason });
  }

  retained(actorId, sessionId, requestCount) {
    return this.log('retained', { actorId, sessionId, requestCount });
  }

  error(message, details) {
    return this.log('error', { message, details });
  }

  /**
   * Get recent events, optionally filtered by type
   */
  getRecent(count = 50, type = null) {
    let filtered = this.events;
    if (type) filtered = filtered.filter((e) => e.type === type);
    return filtered.slice(-count);
  }

  /**
   * Get all events for a specific actor
   */
  getActorHistory(actorId) {
    return this.events.filter((e) => e.actorId === actorId);
  }

  // ── Console output ────────────────────────────────────────────
  _logToConsole(event) {
    const ts = event.timestamp.split('T')[1].split('.')[0]; // HH:MM:SS
    const prefix = `[${ts}]`;

    switch (event.type) {
      case 'request':
        console.log(`${prefix} 📡 ${event.method} ${event.path} ← actor:${event.actorId} (${event.ip})`);
        break;
      case 'fingerprint':
        console.log(`${prefix} 🔑 Fingerprint: ${event.actorId} ${event.isNew ? '(NEW)' : '(seen)'}`);
        break;
      case 'recall':
        if (event.found) {
          console.log(`${prefix} 🧠 KNOWN ACTOR: ${event.actorId} (${event.resultCount} memories)`);
        } else {
          console.log(`${prefix} 🔍 No prior history for ${event.actorId}`);
        }
        break;
      case 'assessment':
        const scoreColor = event.score >= 85 ? '🔴' : event.score >= 70 ? '🟠' : event.score >= 40 ? '🟡' : '🟢';
        console.log(`${prefix} ${scoreColor} Score: ${event.score}/100 | ${event.classification} | confidence: ${event.confidence} | → ${event.action}`);
        break;
      case 'enforcement':
        const actionIcon = { block: '🚫', throttle: '⏳', monitor: '👁️', allow: '✅' }[event.action] || '❓';
        console.log(`${prefix} ${actionIcon} ENFORCE: ${event.action.toUpperCase()} actor:${event.actorId} (score: ${event.score})`);
        break;
      case 'retained':
        console.log(`${prefix} 💾 Retained session ${event.sessionId} (${event.requestCount} requests)`);
        break;
      case 'ml_score': {
        const mlIcon = event.ml_risk_score >= 70 ? '🔴' : event.ml_risk_score >= 40 ? '🟡' : '🟢';
        console.log(`${prefix} 🤖${mlIcon} ML: ${event.ml_risk_score.toFixed(1)}/100 → ${event.attack_type} (${event.confidence}%) actor:${event.actorId}`);
        break;
      }
      case 'ml_session_score': {
        const mlsIcon = event.ml_risk_score >= 70 ? '🔴' : event.ml_risk_score >= 40 ? '🟡' : '🟢';
        console.log(`${prefix} 🤖${mlsIcon} ML SESSION: ${event.ml_risk_score.toFixed(1)}/100 → ${event.attack_type} (${event.confidence}%) [${event.requestCount} reqs] actor:${event.actorId}`);
        break;
      }
      case 'ip_blocked':
        console.log(`${prefix} 🔒 IP BLOCKED: ${event.ip} (actor:${event.actorId} score:${event.score})`);
        break;
      case 'error':
        console.error(`${prefix} ❌ ERROR: ${event.message}`);
        break;
    }
  }
}

// Singleton
const eventLog = new EngineEventLog();
export default eventLog;
