// scripts/seedAttackers.js
// ═══════════════════════════════════════════════════════════════
// Pre-seeds 4 synthetic attacker profiles into Hindsight.
// Run this BEFORE the demo to build up actor observations.
//
// Usage: npm run seed
// ═══════════════════════════════════════════════════════════════
import 'dotenv/config';
import hindsight from '../src/memory/hindsightClient.js';
import { setupMemoryBank } from '../src/memory/bankSetup.js';
import { composeSessionReport } from '../src/memory/observationWriter.js';
import { trainModel } from '../src/ml/trainer.js';
import detector from '../src/ml/model.js';
import { extractFeatures } from '../src/ml/featureExtractor.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Synthetic Actor Definitions ─────────────────────────────
const ACTORS = [
  {
    id: 'actor-credstuff',
    name: 'The Credential Stuffer',
    sessions: [
      {
        requestCount: 234,
        durationMs: 11000,
        endpoints: Array(234).fill('POST /api/auth/login'),
        uniqueEndpoints: ['POST /api/auth/login'],
        endpointDiversity: 0.004,
        avgIntervalMs: 47,
        stdDevMs: 8,
        minIntervalMs: 35,
        maxIntervalMs: 62,
        authPattern: 'intermittent_auth',
        authPresenceRatio: 1.0,
        ips: ['198.51.100.10'],
        ipCount: 1,
        bodyShapes: ['{ username, password }'],
        userAgent: 'python-requests/2.31.0',
        headerSignature: { headerCount: 5, missingHeaders: ['accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'upgrade-insecure-requests'], presentHeaders: ['user-agent', 'accept', 'accept-encoding', 'connection'] },
      },
      {
        requestCount: 456,
        durationMs: 21000,
        endpoints: Array(456).fill('POST /api/auth/login'),
        uniqueEndpoints: ['POST /api/auth/login'],
        endpointDiversity: 0.002,
        avgIntervalMs: 46,
        stdDevMs: 9,
        minIntervalMs: 32,
        maxIntervalMs: 68,
        authPattern: 'intermittent_auth',
        authPresenceRatio: 1.0,
        ips: ['198.51.100.22'],
        ipCount: 1,
        bodyShapes: ['{ username, password }'],
        userAgent: 'python-requests/2.31.0',
        headerSignature: { headerCount: 5, missingHeaders: ['accept-language', 'sec-ch-ua', 'sec-ch-ua-platform'], presentHeaders: ['user-agent', 'accept', 'accept-encoding', 'connection'] },
      },
      {
        requestCount: 389,
        durationMs: 18000,
        endpoints: Array(389).fill('POST /api/auth/login'),
        uniqueEndpoints: ['POST /api/auth/login'],
        endpointDiversity: 0.003,
        avgIntervalMs: 46,
        stdDevMs: 7,
        minIntervalMs: 36,
        maxIntervalMs: 58,
        authPattern: 'intermittent_auth',
        authPresenceRatio: 1.0,
        ips: ['198.51.100.35'],
        ipCount: 1,
        bodyShapes: ['{ username, password }'],
        userAgent: 'python-requests/2.31.0',
        headerSignature: { headerCount: 5, missingHeaders: ['accept-language', 'sec-ch-ua'], presentHeaders: ['user-agent', 'accept', 'accept-encoding', 'connection'] },
      },
    ],
  },
  {
    id: 'actor-scraper',
    name: 'The Data Scraper',
    sessions: [
      {
        requestCount: 1200,
        durationMs: 144000,
        endpoints: Array.from({ length: 1200 }, (_, i) => `GET /api/users/${i + 1}/profile`),
        uniqueEndpoints: ['GET /api/users/:id/profile'],
        endpointDiversity: 1.0,
        avgIntervalMs: 120,
        stdDevMs: 15,
        minIntervalMs: 95,
        maxIntervalMs: 150,
        authPattern: 'consistent_bearer',
        authPresenceRatio: 1.0,
        ips: ['203.0.113.50'],
        ipCount: 1,
        bodyShapes: ['empty'],
        userAgent: 'Mozilla/5.0 (compatible; DataBot/1.0)',
        headerSignature: { headerCount: 6, missingHeaders: ['sec-ch-ua', 'sec-fetch-mode', 'upgrade-insecure-requests'], presentHeaders: ['user-agent', 'accept', 'accept-encoding', 'connection', 'authorization'] },
      },
      {
        requestCount: 980,
        durationMs: 117600,
        endpoints: Array.from({ length: 980 }, (_, i) => `GET /api/users/${1200 + i + 1}/profile`),
        uniqueEndpoints: ['GET /api/users/:id/profile'],
        endpointDiversity: 1.0,
        avgIntervalMs: 120,
        stdDevMs: 14,
        minIntervalMs: 100,
        maxIntervalMs: 148,
        authPattern: 'consistent_bearer',
        authPresenceRatio: 1.0,
        ips: ['203.0.113.51'],
        ipCount: 1,
        bodyShapes: ['empty'],
        userAgent: 'Mozilla/5.0 (compatible; DataBot/1.0)',
        headerSignature: { headerCount: 6, missingHeaders: ['sec-ch-ua', 'sec-fetch-mode'], presentHeaders: ['user-agent', 'accept', 'accept-encoding', 'connection', 'authorization'] },
      },
      {
        requestCount: 1450,
        durationMs: 174000,
        endpoints: Array.from({ length: 1450 }, (_, i) => `GET /api/users/${2180 + i + 1}/profile`),
        uniqueEndpoints: ['GET /api/users/:id/profile'],
        endpointDiversity: 1.0,
        avgIntervalMs: 120,
        stdDevMs: 13,
        minIntervalMs: 98,
        maxIntervalMs: 145,
        authPattern: 'consistent_bearer',
        authPresenceRatio: 1.0,
        ips: ['203.0.113.52'],
        ipCount: 1,
        bodyShapes: ['empty'],
        userAgent: 'Mozilla/5.0 (compatible; DataBot/1.0)',
        headerSignature: { headerCount: 6, missingHeaders: ['sec-ch-ua', 'sec-fetch-mode'], presentHeaders: ['user-agent', 'accept', 'accept-encoding', 'connection', 'authorization'] },
      },
    ],
  },
  {
    id: 'actor-enumerator',
    name: 'The Enumerator',
    sessions: [
      {
        requestCount: 500,
        durationMs: 100000,
        endpoints: Array.from({ length: 500 }, (_, i) => `GET /api/users/${i + 1}`),
        uniqueEndpoints: ['GET /api/users/:id'],
        endpointDiversity: 1.0,
        avgIntervalMs: 200,
        stdDevMs: 30,
        minIntervalMs: 150,
        maxIntervalMs: 280,
        authPattern: 'no_auth',
        authPresenceRatio: 0,
        ips: ['192.0.2.100', '192.0.2.101'],
        ipCount: 2,
        bodyShapes: ['empty'],
        userAgent: 'curl/8.4.0',
        headerSignature: { headerCount: 3, missingHeaders: ['accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'upgrade-insecure-requests', 'cache-control', 'sec-ch-ua-mobile'], presentHeaders: ['user-agent', 'accept'] },
      },
      {
        requestCount: 650,
        durationMs: 130000,
        endpoints: Array.from({ length: 650 }, (_, i) => `GET /api/products/${i + 1}`),
        uniqueEndpoints: ['GET /api/products/:id'],
        endpointDiversity: 1.0,
        avgIntervalMs: 200,
        stdDevMs: 28,
        minIntervalMs: 155,
        maxIntervalMs: 270,
        authPattern: 'no_auth',
        authPresenceRatio: 0,
        ips: ['192.0.2.102', '192.0.2.103'],
        ipCount: 2,
        bodyShapes: ['empty'],
        userAgent: 'curl/8.4.0',
        headerSignature: { headerCount: 3, missingHeaders: ['accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'upgrade-insecure-requests'], presentHeaders: ['user-agent', 'accept'] },
      },
    ],
  },
  {
    id: 'actor-ratelimiter',
    name: 'The Rate Limit Evader',
    sessions: [
      {
        requestCount: 350,
        durationMs: 367500,
        endpoints: Array.from({ length: 350 }, (_, i) => i % 2 === 0 ? 'GET /api/search' : 'GET /api/listings'),
        uniqueEndpoints: ['GET /api/search', 'GET /api/listings'],
        endpointDiversity: 0.006,
        avgIntervalMs: 1050,
        stdDevMs: 45,
        minIntervalMs: 980,
        maxIntervalMs: 1100,
        authPattern: 'mixed_auth_types',
        authPresenceRatio: 0.85,
        ips: ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
        ipCount: 3,
        bodyShapes: ['empty'],
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        headerSignature: { headerCount: 12, missingHeaders: [], presentHeaders: ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'connection', 'cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'] },
      },
      {
        requestCount: 290,
        durationMs: 304500,
        endpoints: Array.from({ length: 290 }, (_, i) => i % 2 === 0 ? 'GET /api/search' : 'GET /api/listings'),
        uniqueEndpoints: ['GET /api/search', 'GET /api/listings'],
        endpointDiversity: 0.007,
        avgIntervalMs: 1050,
        stdDevMs: 42,
        minIntervalMs: 985,
        maxIntervalMs: 1095,
        authPattern: 'mixed_auth_types',
        authPresenceRatio: 0.88,
        ips: ['10.0.0.4', '10.0.0.5', '10.0.0.6'],
        ipCount: 3,
        bodyShapes: ['empty'],
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        headerSignature: { headerCount: 12, missingHeaders: [], presentHeaders: ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'connection', 'cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'] },
      },
    ],
  },
];

// ── Main Seeding Logic ────────────────────────────────────────
async function seed() {
  console.log('');
  console.log('═══════════════════════════════════════════════════');
  console.log('  Seeding Synthetic Attackers into Hindsight');
  console.log('═══════════════════════════════════════════════════');
  console.log('');

  // Verify Hindsight is reachable
  const alive = await hindsight.ping();
  if (!alive) {
    console.error('❌ Cannot reach Hindsight. Check HINDSIGHT_BASE_URL in .env');
    process.exit(1);
  }
  console.log('✅ Hindsight connected\n');

  // Train ML model for enriching reports
  console.log('🤖 Training Transformer model...');
  await trainModel(30);
  console.log(`✅ Model ready (${detector.getSummary().params} params)\n`);

  // Set up bank
  await setupMemoryBank();

  // Seed each actor
  for (const actor of ACTORS) {
    console.log(`\n🔵 Seeding: ${actor.name} (${actor.id})`);
    console.log(`   Sessions to retain: ${actor.sessions.length}`);

    for (let i = 0; i < actor.sessions.length; i++) {
      const sessionData = actor.sessions[i];
      const analysis = {
        actorId: actor.id,
        sessionId: `${actor.id}-seed-${i}`,
        startTime: new Date(Date.now() - (actor.sessions.length - i) * 3600000).toISOString(),
        endTime: new Date(Date.now() - (actor.sessions.length - i) * 3600000 + sessionData.durationMs).toISOString(),
        ...sessionData,
        sampleRequests: sessionData.endpoints.slice(0, 5).map((ep) => {
          const [method, path] = ep.split(' ');
          return {
            method,
            path,
            timestamp: new Date().toISOString(),
            authType: sessionData.authPattern === 'no_auth' ? 'none' : 'bearer',
            bodyShape: sessionData.bodyShapes[0],
            queryParams: 0,
          };
        }),
      };

      // Run ML scoring on this session
      let mlResult = null;
      try {
        const features = extractFeatures(analysis);
        mlResult = await detector.predict(features);
        console.log(`   🤖 ML: ${mlResult.ml_risk_score.toFixed(1)} → ${mlResult.attack_type}`);
      } catch (e) { /* ML optional for seeding */ }

      const report = composeSessionReport(analysis, mlResult);

      try {
        await hindsight.retain(report, {
          context: 'api-abuse-session-report',
          documentId: `seed-${analysis.sessionId}`,
          tags: [`actor:${actor.id}`],
          observationScopes: 'per_tag',
          entities: [
            { text: actor.id, type: 'THREAT_ACTOR' },
            ...sessionData.ips.map((ip) => ({ text: ip, type: 'IP_ADDRESS' })),
          ],
          metadata: {
            source: 'synthetic-seed',
            sessionIndex: String(i),
            requestCount: String(sessionData.requestCount),
          },
        });

        console.log(`   ✓ Session ${i + 1}/${actor.sessions.length} retained (${sessionData.requestCount} requests)`);
      } catch (e) {
        console.error(`   ✗ Session ${i + 1} failed: ${e.message}`);
      }

      // Wait between retains for observation consolidation
      if (i < actor.sessions.length - 1) {
        console.log(`   ⏳ Waiting 4s for consolidation...`);
        await sleep(4000);
      }
    }

    // Verify observation was created
    console.log(`   🔍 Verifying observation...`);
    await sleep(5000); // Give consolidation time

    try {
      const result = await hindsight.recall(
        `Threat actor profile for ${actor.id}`,
        {
          types: ['observation'],
          tags: [`actor:${actor.id}`],
          tagsMatch: 'any_strict',
          budget: 'mid',
        }
      );

      if (result.results && result.results.length > 0) {
        console.log(`   ✅ Observation created!`);
        console.log(`   📝 Preview: ${result.results[0].text.substring(0, 150)}...`);
      } else {
        console.log(`   ⚠️  No observation yet — consolidation may still be running.`);
        console.log(`      This is normal. Run the demo after a few minutes.`);
      }
    } catch (e) {
      console.log(`   ⚠️  Verification failed: ${e.message}`);
    }
  }

  console.log('\n');
  console.log('═══════════════════════════════════════════════════');
  console.log('  Seeding Complete!');
  console.log('  Run `npm run demo` to test actor recognition.');
  console.log('═══════════════════════════════════════════════════');
  console.log('');
}

seed().catch((e) => {
  console.error('Seeding failed:', e);
  process.exit(1);
});
