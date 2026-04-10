// src/ingestion/requestParser.js
// ═══════════════════════════════════════════════════════════════
// Extracts all security-relevant metadata from a raw request
// ═══════════════════════════════════════════════════════════════
import { getHeaderSignature } from './fingerprintGenerator.js';

/**
 * Parse a raw Express request into a normalized record
 * for observation generation and session buffering.
 */
export function parseRequest(req) {
  const now = Date.now();
  const headerSig = getHeaderSignature(req);

  return {
    timestamp: now,
    isoTimestamp: new Date(now).toISOString(),

    // Network
    ip: req.ip || req.socket?.remoteAddress || 'unknown',
    protocol: req.protocol || 'http',

    // HTTP
    method: req.method,
    path: req.path,
    fullUrl: req.originalUrl,
    queryParams: Object.keys(req.query || {}).length,
    queryKeys: Object.keys(req.query || {}),

    // Headers
    userAgent: req.headers['user-agent'] || 'missing',
    contentType: req.headers['content-type'] || 'none',
    authorization: req.headers['authorization'] ? 'present' : 'absent',
    authType: extractAuthType(req.headers['authorization']),
    headerSignature: headerSig,

    // Body shape (not content — privacy)
    bodySize: req.headers['content-length'] ? parseInt(req.headers['content-length'], 10) : 0,
    bodyShape: getBodyShape(req.body),

    // Response (filled after response completes)
    status: null,
    responseTimeMs: null,
  };
}

/**
 * Determine the auth mechanism without exposing credentials
 */
function extractAuthType(authHeader) {
  if (!authHeader) return 'none';
  if (authHeader.startsWith('Bearer ')) return 'bearer';
  if (authHeader.startsWith('Basic ')) return 'basic';
  if (authHeader.startsWith('ApiKey ')) return 'apikey';
  return 'custom';
}

/**
 * Describe the shape of a JSON body without capturing values.
 * e.g. { "username": "...", "password": "..." } → "{ username, password }"
 */
function getBodyShape(body) {
  if (!body || typeof body !== 'object') return 'empty';
  try {
    const keys = Object.keys(body);
    if (keys.length === 0) return 'empty-object';
    return `{ ${keys.join(', ')} }`;
  } catch {
    return 'unparseable';
  }
}
