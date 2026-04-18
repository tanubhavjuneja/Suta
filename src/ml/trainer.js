// src/ml/trainer.js
// ═══════════════════════════════════════════════════════════════
// Generates training data from attack pattern definitions
// and trains the Transformer model.
//
// Patterns are loaded from external config file (config/training-patterns.json)
// The model learns to distinguish them through gradient descent.
// ═══════════════════════════════════════════════════════════════
import { extractFeatures, FEATURE_COUNT } from './featureExtractor.js';
import detector, { ATTACK_TYPES, NUM_CLASSES, BODY_SHAPES, pick } from './constants.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const patternsPath = join(__dirname, '../../config/training-patterns.json');

// Load patterns from external file
let patterns = [];

function loadPatterns() {
  try {
    if (fs.existsSync(patternsPath)) {
      const data = JSON.parse(fs.readFileSync(patternsPath, 'utf8'));
      if (data.patterns && Array.isArray(data.patterns)) {
        patterns = data.patterns;
        console.log('[Patterns] Loaded', patterns.length, 'patterns from file');
        return;
      }
    }
  } catch (e) {
    console.log('[Patterns] Failed to load:', e.message);
  }
  
  // Fallback minimal patterns
  patterns = [
    { label: 'normal', riskRange: [0, 20], count: 120 },
    { label: 'credential_stuffing', riskRange: [70, 98], count: 80 },
    { label: 'data_scraping', riskRange: [55, 90], count: 80 },
    { label: 'enumeration', riskRange: [50, 85], count: 80 },
    { label: 'rate_limit_evasion', riskRange: [45, 80], count: 80 },
    { label: 'brute_force', riskRange: [75, 99], count: 60 },
  ];
  console.log('[Patterns] Using fallback patterns');
}

loadPatterns();

// Helper functions
function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randFloat(min, max) {
  return Math.random() * (max - min) + min;
}

function generateMixedEndpoints(count, pool = null) {
  const defaults = [
    'GET /api/health', 'GET /api/users/1', 'GET /api/users/2/profile',
    'GET /api/products/5', 'GET /api/search', 'GET /api/listings',
    'POST /api/auth/login', 'GET /api/users/10',
  ];
  const endpoints = pool || defaults;
  return Array.from({ length: count }, () => pick(endpoints));
}

// Generate session from pattern config
function generateSession(pattern) {
  const gen = pattern.generator || {};
  const isNormal = pattern.label === 'normal';
  
  const session = {
    requestCount: gen.requestCount ? randInt(gen.requestCount.min, gen.requestCount.max) : randInt(2, isNormal ? 15 : 100),
    durationMs: gen.durationMs ? randInt(gen.durationMs.min, gen.durationMs.max) : randInt(15000, 120000),
    avgIntervalMs: gen.avgIntervalMs ? randInt(gen.avgIntervalMs.min, gen.avgIntervalMs.max) : randInt(2000, 15000),
    stdDevMs: gen.stdDevMs ? randInt(gen.stdDevMs.min, gen.stdDevMs.max) : randInt(500, 4000),
    ipCount: gen.ipCount ? randInt(gen.ipCount.min, gen.ipCount.max) : 1,
    authPattern: gen.authPattern ? pick(gen.authPattern) : pick(['consistent_bearer', 'no_auth']),
    authPresenceRatio: isNormal ? (Math.random() > 0.3 ? 1.0 : 0.0) : (gen.authPattern?.includes('no_auth') ? 0 : Math.random() * 0.3),
    userAgent: gen.userAgents ? pick(gen.userAgents) : 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0',
    headerSignature: { 
      headerCount: gen.headerCount ? randInt(gen.headerCount.min, gen.headerCount.max) : randInt(10, 16),
      missingHeaders: gen.missingHeaders || [] 
    },
    bodyShapes: BODY_SHAPES[pattern.label] || BODY_SHAPES.normal,
  };
  
  // Generate endpoints
  if (gen.endpointPattern) {
    session.endpoints = Array.from({ length: session.requestCount }, () => gen.endpointPattern.replace('{id}', randInt(1, 1000)));
  } else if (gen.endpoints) {
    session.endpoints = Array.from({ length: session.requestCount }, () => pick(gen.endpoints));
  } else {
    session.endpoints = generateMixedEndpoints(session.requestCount);
  }
  
  return session;
}

/**
 * Generate labeled training data from patterns.
 */
export function generateTrainingData() {
  const features = [];
  const riskScores = [];
  const attackLabels = [];

  for (const pattern of patterns) {
    const labelIndex = ATTACK_TYPES.indexOf(pattern.label);
    if (labelIndex === -1) {
      console.warn('[Patterns] Skipping unknown label:', pattern.label);
      continue;
    }

    const count = pattern.count || 100;
    for (let i = 0; i < count; i++) {
      const session = generateSession(pattern);

      // Compute derived fields
      session.uniqueEndpoints = [...new Set(session.endpoints)];
      session.endpointDiversity = session.uniqueEndpoints.length / Math.max(session.requestCount, 1);
      session.ips = Array.from({ length: session.ipCount }, (_, j) => `10.0.${j}.${randInt(1, 254)}`);

      // Compute intervals
      session.intervals = Array.from({ length: Math.max(session.requestCount - 1, 1) }, () =>
        Math.max(1, session.avgIntervalMs + (Math.random() - 0.5) * 2 * session.stdDevMs)
      );
      session.minIntervalMs = Math.min(...session.intervals);
      session.maxIntervalMs = Math.max(...session.intervals);

      // Extract features
      const featureVec = extractFeatures(session);
      features.push(Array.from(featureVec));

      // Risk score
      const risk = randFloat(pattern.riskRange[0], pattern.riskRange[1]);
      riskScores.push(risk);

      // One-hot label
      const oneHot = new Array(NUM_CLASSES).fill(0);
      oneHot[labelIndex] = 1;
      attackLabels.push(oneHot);
    }
  }

  console.log('[Patterns] Generated', features.length, 'samples');
  for (const p of patterns) {
    console.log('   -', p.label, ':', p.count, 'samples');
  }

  return { features, riskScores, attackLabels };
}

/**
 * Full training pipeline: generate data -> build model -> train
 */
export async function trainModel(epochs = 50) {
  console.log('\n[ML] Transformer Training');
  const data = generateTrainingData();
  detector.build();
  await detector.train(data, epochs);
  return detector;
}