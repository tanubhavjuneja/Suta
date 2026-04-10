// src/config.js
// Central configuration — all tuning knobs in one place
import 'dotenv/config';

const config = {
  // Hindsight
  hindsight: {
    baseUrl: process.env.HINDSIGHT_BASE_URL || 'http://localhost:8888',
    apiKey: process.env.HINDSIGHT_API_KEY || '',
    bankId: process.env.HINDSIGHT_BANK_ID || 'api-abuse-engine',
  },

  // Server
  port: parseInt(process.env.PORT || '3000', 10),

  // Session buffering
  session: {
    bufferThreshold: parseInt(process.env.SESSION_BUFFER_THRESHOLD || '5', 10),
    timeoutMs: parseInt(process.env.SESSION_TIMEOUT_MS || '30000', 10),
  },

  // Enforcement thresholds — the ONLY hardcoded logic allowed
  enforcement: {
    blockScore: parseInt(process.env.BLOCK_SCORE || '85', 10),
    throttleScore: parseInt(process.env.THROTTLE_SCORE || '70', 10),
    monitorScore: parseInt(process.env.MONITOR_SCORE || '40', 10),
  },

  // Bank configuration for Hindsight
  bankConfig: {
    retainMission: `
      This memory bank stores API abuse detection data.
      Focus extraction on:
      - Attack patterns, techniques, and behavioral signatures
      - Actor fingerprints and infrastructure indicators (IPs, ASNs, hosting)
      - Temporal patterns: timing intervals, burst frequency, active hours
      - Endpoint access sequences and data exfiltration indicators
      - Authentication anomalies: credential rotation, token reuse, missing auth
      - Request structure anomalies: unusual headers, body shapes, encoding tricks
      Ignore: Normal API usage, successful legitimate requests, health checks, static assets.
    `.trim(),

    observationsMission: `
      Synthesize consolidated threat actor profiles.
      For each actor tag, produce an observation covering:
      - Dominant attack technique and confidence level
      - Infrastructure footprint (IP ranges, ASNs, geo, hosting providers)
      - Behavioral timing signature (mean interval, variance, burst patterns)
      - Historical session count and date range
      - Escalation trajectory (are attacks getting more sophisticated?)
      - Key distinguishing signals versus other actors
    `.trim(),

    reflectMission: `
      You are an API security analyst specializing in automated threat detection.
      Ground all analysis in stored attack patterns and actor observations.
      Be precise about confidence — distinguish confirmed repeat offenders from 
      possible false positives. When similar behavioral patterns exist across 
      different actors, note potential coordination. Always recommend specific 
      enforcement actions with clear justification.
    `.trim(),
  },
};

export default config;
