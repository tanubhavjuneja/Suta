// src/ml/trainer.js
// ═══════════════════════════════════════════════════════════════
// Generates training data from attack pattern definitions
// and trains the Transformer model.
//
// Patterns are statistical distributions, NOT hardcoded rules.
// The model learns to distinguish them through gradient descent.
// ═══════════════════════════════════════════════════════════════
import { extractFeatures, FEATURE_COUNT } from './featureExtractor.js';
import detector, { ATTACK_TYPES, NUM_CLASSES } from './model.js';

/**
 * Statistical pattern definitions for training data generation.
 * Each pattern defines DISTRIBUTIONS, not thresholds.
 * The model learns the decision boundaries from data.
 */
const TRAINING_PATTERNS = [
  // ── Normal users ──────────────────────────────────────────
  {
    label: 'normal',
    riskRange: [0, 20],
    count: 120,
    generator: () => ({
      requestCount: randInt(2, 15),
      durationMs: randInt(15000, 120000),
      endpoints: generateMixedEndpoints(randInt(2, 15)),
      avgIntervalMs: randInt(2000, 15000),
      stdDevMs: randInt(500, 4000),
      authPattern: pick(['consistent_bearer', 'consistent_bearer', 'consistent_bearer', 'no_auth']),
      authPresenceRatio: Math.random() > 0.3 ? 1.0 : 0.0,
      ipCount: 1,
      userAgent: pick([
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2',
        'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
      ]),
      headerSignature: { headerCount: randInt(10, 16), missingHeaders: [] },
      bodyShapes: pick([['empty'], ['{ name, email }'], ['{ query }']]),
    }),
  },

  // ── Credential stuffing ───────────────────────────────────
  {
    label: 'credential_stuffing',
    riskRange: [70, 98],
    count: 80,
    generator: () => ({
      requestCount: randInt(100, 800),
      durationMs: randInt(3000, 30000),
      endpoints: Array(randInt(100, 800)).fill('POST /api/auth/login'),
      avgIntervalMs: randInt(20, 80),
      stdDevMs: randInt(3, 15),
      authPattern: pick(['intermittent_auth', 'no_auth']),
      authPresenceRatio: Math.random() * 0.3,
      ipCount: randInt(1, 3),
      userAgent: pick([
        'python-requests/2.31.0',
        'python-requests/2.28.0',
        'python-httpx/0.25.0',
        'Go-http-client/2.0',
      ]),
      headerSignature: { headerCount: randInt(3, 6), missingHeaders: ['accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode'] },
      bodyShapes: ['{ username, password }'],
    }),
  },

  // ── Data scraping ─────────────────────────────────────────
  {
    label: 'data_scraping',
    riskRange: [55, 90],
    count: 80,
    generator: () => {
      const count = randInt(200, 2000);
      return {
        requestCount: count,
        durationMs: count * randInt(80, 200),
        endpoints: Array.from({ length: count }, (_, i) => `GET /api/users/${i + 1}/profile`),
        avgIntervalMs: randInt(80, 200),
        stdDevMs: randInt(10, 30),
        authPattern: 'consistent_bearer',
        authPresenceRatio: 1.0,
        ipCount: randInt(1, 2),
        userAgent: pick([
          'Mozilla/5.0 (compatible; DataBot/1.0)',
          'python-requests/2.31.0',
          'Scrapy/2.11.0',
        ]),
        headerSignature: { headerCount: randInt(4, 8), missingHeaders: ['sec-ch-ua', 'sec-fetch-mode', 'upgrade-insecure-requests'] },
        bodyShapes: ['empty'],
      };
    },
  },

  // ── Enumeration ───────────────────────────────────────────
  {
    label: 'enumeration',
    riskRange: [50, 85],
    count: 80,
    generator: () => {
      const count = randInt(100, 1000);
      return {
        requestCount: count,
        durationMs: count * randInt(150, 300),
        endpoints: Array.from({ length: count }, (_, i) => `GET /api/users/${i + 1}`),
        avgIntervalMs: randInt(150, 300),
        stdDevMs: randInt(20, 50),
        authPattern: 'no_auth',
        authPresenceRatio: 0,
        ipCount: randInt(1, 4),
        userAgent: pick(['curl/8.4.0', 'wget/1.21', 'python-requests/2.31.0']),
        headerSignature: { headerCount: randInt(2, 5), missingHeaders: ['accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'upgrade-insecure-requests', 'cache-control'] },
        bodyShapes: ['empty'],
      };
    },
  },

  // ── Rate limit evasion ────────────────────────────────────
  {
    label: 'rate_limit_evasion',
    riskRange: [45, 80],
    count: 80,
    generator: () => ({
      requestCount: randInt(200, 500),
      durationMs: randInt(200000, 500000),
      endpoints: generateMixedEndpoints(randInt(200, 500), ['GET /api/search', 'GET /api/listings']),
      avgIntervalMs: randInt(980, 1100), // Just under typical 1s rate limits
      stdDevMs: randInt(20, 60),
      authPattern: 'mixed_auth_types',
      authPresenceRatio: randFloat(0.7, 0.95),
      ipCount: randInt(2, 6),
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
      headerSignature: { headerCount: randInt(10, 14), missingHeaders: [] },
      bodyShapes: ['empty'],
    }),
  },

  // ── Brute force ───────────────────────────────────────────
  {
    label: 'brute_force',
    riskRange: [75, 99],
    count: 60,
    generator: () => ({
      requestCount: randInt(500, 2000),
      durationMs: randInt(5000, 30000),
      endpoints: Array(randInt(500, 2000)).fill(pick(['POST /api/auth/login', 'POST /api/auth/reset', 'POST /api/auth/verify'])),
      avgIntervalMs: randInt(10, 50),
      stdDevMs: randInt(2, 10),
      authPattern: 'no_auth',
      authPresenceRatio: 0,
      ipCount: 1,
      userAgent: pick(['python-requests/2.31.0', 'Go-http-client/2.0', 'curl/8.4.0']),
      headerSignature: { headerCount: randInt(3, 5), missingHeaders: ['accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-fetch-dest'] },
      bodyShapes: ['{ password }', '{ username, password }'],
    }),
  },
];

/**
 * Generate labeled training data from statistical patterns.
 */
export function generateTrainingData() {
  const features = [];
  const riskScores = [];
  const attackLabels = [];

  for (const pattern of TRAINING_PATTERNS) {
    const labelIndex = ATTACK_TYPES.indexOf(pattern.label);
    if (labelIndex === -1) throw new Error(`Unknown label: ${pattern.label}`);

    for (let i = 0; i < pattern.count; i++) {
      const session = pattern.generator();

      // Compute derived fields needed by feature extractor
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

      // Risk score (sampled from pattern's range, with noise)
      const risk = randFloat(pattern.riskRange[0], pattern.riskRange[1]);
      riskScores.push(risk);

      // One-hot attack label
      const oneHot = new Array(NUM_CLASSES).fill(0);
      oneHot[labelIndex] = 1;
      attackLabels.push(oneHot);
    }
  }

  console.log(`📊 Generated ${features.length} training samples across ${ATTACK_TYPES.length} classes`);
  for (const p of TRAINING_PATTERNS) {
    console.log(`   ${p.label}: ${p.count} samples (risk: ${p.riskRange[0]}-${p.riskRange[1]})`);
  }

  return { features, riskScores, attackLabels };
}

/**
 * Full training pipeline: generate data → build model → train
 */
export async function trainModel(epochs = 50) {
  console.log('\n🧠 Transformer Training Pipeline');
  console.log('─────────────────────────────────\n');

  const data = generateTrainingData();
  detector.build();
  await detector.train(data, epochs);

  return detector;
}

// ── Helpers ───────────────────────────────────────────────────

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randFloat(min, max) {
  return Math.random() * (max - min) + min;
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
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
