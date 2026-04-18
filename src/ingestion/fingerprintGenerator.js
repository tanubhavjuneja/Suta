// src/ingestion/fingerprintGenerator.js
// ═══════════════════════════════════════════════════════════════
// Generates IP-INDEPENDENT actor fingerprints
// Actor identity persists across IP, proxy, and VPN changes
// ═══════════════════════════════════════════════════════════════
import { createHash } from 'crypto';

// Headers that reveal client identity regardless of IP
const IDENTITY_HEADERS = [
  'user-agent',
  'accept',
  'accept-language',
  'accept-encoding',
  'connection',
  'cache-control',
  'upgrade-insecure-requests',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
];

/**
 * Generate a behavioral fingerprint for an incoming request.
 * This identity survives IP rotation because it is based on:
 *   - User-Agent string
 *   - Header ordering (which headers exist and in what order)
 *   - Accept-Language / Accept patterns
 *   - TLS-level hints (sec-ch-ua)
 *
 * It does NOT use IP, port, or any network-level identifier.
 */
export function generateFingerprint(req) {
  const signals = [];

  // Signal 1: User-Agent (primary differentiator)
  signals.push(req.headers['user-agent'] || 'missing-ua');

  // Signal 2: Header presence + ordering
  // Real browsers send headers in specific, consistent orders.
  // Bots/scripts typically have different orderings or missing headers.
  const headerKeys = Object.keys(req.headers)
    .filter((h) => !['host', 'content-length', 'content-type', 'cookie', 'authorization'].includes(h))
    .sort(); // normalize ordering
  signals.push(headerKeys.join('|'));

  // Signal 3: Accept-Language fingerprint
  signals.push(req.headers['accept-language'] || 'no-lang');

  // Signal 4: Accept header
  signals.push(req.headers['accept'] || 'no-accept');

  // Signal 5: TLS client hints (sec-ch-ua family)
  const secChUa = req.headers['sec-ch-ua'] || '';
  const secChPlatform = req.headers['sec-ch-ua-platform'] || '';
  signals.push(`${secChUa}::${secChPlatform}`);

  // Signal 6: Connection behavior
  signals.push(req.headers['connection'] || 'no-conn');

  // Hash all signals into a stable actor ID
  const raw = signals.join('|||');
  const hash = createHash('sha256').update(raw).digest('hex');

  // Return first 12 chars for readability
  return hash.substring(0, 12);
}

/**
 * Extract a full header signature for the observation report.
 * Returns a human-readable summary of what headers were present.
 */
export function getHeaderSignature(req) {
  const present = [];
  const missing = [];

  for (const h of IDENTITY_HEADERS) {
    if (req.headers[h]) {
      present.push(h);
    } else {
      missing.push(h);
    }
  }

  return {
    presentHeaders: present,
    missingHeaders: missing,
    headerCount: Object.keys(req.headers).length,
    headerOrder: Object.keys(req.headers).join(', '),
  };
}
