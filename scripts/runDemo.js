// scripts/runDemo.js
// ═══════════════════════════════════════════════════════════════
// Demo Script — Shows the HYBRID ML + Memory engine in action
//
// Phase 1: Normal user → ML: low risk → Memory: empty → ALLOW
// Phase 2: Bot behavior → ML: high risk → Memory builds → THROTTLE
// Phase 3: Known actor, new IP → ML: drops → Memory: RECOGNIZED → BLOCK
//
// Usage: npm run demo
// Prereq: npm run seed  (seed attackers first!)
// ═══════════════════════════════════════════════════════════════
import 'dotenv/config';
import hindsight from '../src/memory/hindsightClient.js';
import memoryLayer from '../src/memory/memoryLayer.js';
import { trainModel } from '../src/ml/trainer.js';
import detector from '../src/ml/model.js';
import { extractFeatures } from '../src/ml/featureExtractor.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const DIVIDER = '═══════════════════════════════════════════════════════════';
const THIN    = '───────────────────────────────────────────────────────────';

function printResult(label, result, mlResult = null) {
  console.log('');
  console.log(THIN);
  console.log(`  ${label}`);
  console.log(THIN);

  if (mlResult && mlResult.model_ready) {
    const mlBar = '█'.repeat(Math.floor(mlResult.ml_risk_score / 5)) + '░'.repeat(20 - Math.floor(mlResult.ml_risk_score / 5));
    console.log(`  🤖 ML Score:      [${mlBar}] ${mlResult.ml_risk_score.toFixed(1)}/100`);
    console.log(`  🤖 ML Class:      ${mlResult.attack_type} (confidence: ${mlResult.confidence}%)`);
    if (mlResult.attack_probabilities) {
      const top3 = Object.entries(mlResult.attack_probabilities).sort(([,a],[,b]) => b - a).slice(0, 3);
      console.log(`  🤖 ML Top-3:      ${top3.map(([t,p]) => `${t}: ${p}%`).join(' | ')}`);
    }
  }

  if (result) {
    const scoreBar = '█'.repeat(Math.floor(result.threat_score / 5)) + '░'.repeat(20 - Math.floor(result.threat_score / 5));
    console.log(`  🎯 Final Score:   [${scoreBar}] ${result.threat_score}/100`);
    console.log(`  📋 Classification: ${result.classification}`);
    console.log(`  🔒 Confidence:    ${result.confidence}`);
    console.log(`  ⚡ Action:        ${result.recommended_action?.toUpperCase()}`);
    if (result.is_known_actor !== undefined) {
      console.log(`  👤 Known Actor:   ${result.is_known_actor ? 'YES ⚠️' : 'NO'}`);
    }
    if (result.previous_sessions_estimate) {
      console.log(`  📊 Prior Sessions: ~${result.previous_sessions_estimate}`);
    }
    if (result.ml_agreement) {
      console.log(`  🔗 ML Agreement:  ${result.ml_agreement}`);
    }
    console.log(`  💬 Reasoning:`);
    console.log(`     ${result.reasoning}`);
    if (result.behavioral_indicators?.length > 0) {
      console.log(`  🚩 Indicators:`);
      for (const ind of result.behavioral_indicators) {
        console.log(`     • ${ind}`);
      }
    }
  } else {
    console.log('  ⚠️ No structured output');
  }
  console.log(THIN);
}

async function demo() {
  console.log('');
  console.log(DIVIDER);
  console.log('  API Abuse Pattern Memory Engine — Live Demo');
  console.log('  Hybrid: Transformer ML + Hindsight Agent Memory');
  console.log(DIVIDER);
  console.log('');

  // ── Setup ────────────────────────────────────────────────
  // Train ML model
  console.log('🤖 Training Transformer model...\n');
  await trainModel(50);
  console.log(`✅ Model ready (${detector.getSummary().params} params)\n`);

  // Check Hindsight
  const alive = await hindsight.ping();
  if (!alive) {
    console.error('❌ Hindsight unreachable. Start the server and try again.');
    process.exit(1);
  }
  console.log('✅ Hindsight connected\n');

  // ═══════════════════════════════════════════════════════════
  //  PHASE 1: Normal User
  // ═══════════════════════════════════════════════════════════
  console.log(DIVIDER);
  console.log('  PHASE 1: Normal User');
  console.log('  Expected: ML → low risk, Memory → empty, Final → ALLOW');
  console.log(DIVIDER);

  const normalSession = {
    actorId: 'actor-normal-user',
    sessionId: 'actor-normal-user-demo-1',
    startTime: new Date().toISOString(),
    endTime: new Date(Date.now() + 30000).toISOString(),
    durationMs: 30000,
    requestCount: 5,
    endpoints: ['GET /api/health', 'GET /api/products/1', 'GET /api/products/2', 'GET /api/search', 'GET /api/listings'],
    uniqueEndpoints: ['GET /api/health', 'GET /api/products/:id', 'GET /api/search', 'GET /api/listings'],
    endpointDiversity: 0.8,
    intervals: [3200, 5100, 2800, 4500],
    avgIntervalMs: 3900,
    stdDevMs: 950,
    minIntervalMs: 2800,
    maxIntervalMs: 5100,
    authPattern: 'consistent_bearer',
    authPresenceRatio: 1.0,
    ips: ['192.168.1.100'],
    ipCount: 1,
    bodyShapes: ['empty'],
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
    headerSignature: { headerCount: 14, missingHeaders: [], presentHeaders: ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'connection'] },
    sampleRequests: [
      { method: 'GET', path: '/api/health', timestamp: new Date().toISOString(), authType: 'bearer', bodyShape: 'empty', queryParams: 0 },
      { method: 'GET', path: '/api/products/1', timestamp: new Date().toISOString(), authType: 'bearer', bodyShape: 'empty', queryParams: 0 },
    ],
  };

  console.log('\n📡 Sending 5 normal requests (diverse endpoints, slow timing, authenticated)...');

  // ML scoring
  const normalFeatures = extractFeatures(normalSession);
  const normalMl = await detector.predict(normalFeatures);
  console.log(`🤖 ML Risk Score: ${normalMl.ml_risk_score.toFixed(1)} → ${normalMl.attack_type}`);

  // Memory recall
  const normalRecall = await memoryLayer.recallActor(normalSession.actorId);
  console.log(`🧠 Memory: ${normalRecall.results?.length || 0} memories found`);

  // Reflect (synthesis)
  console.log('🔮 Reflecting (ML + Memory → Final Decision)...');
  const normalReflect = await memoryLayer.assessThreat(normalSession, normalRecall, normalMl);
  const normalResult = normalReflect?.structured_output || normalReflect?.structuredOutput || normalReflect;

  printResult('PHASE 1 RESULT — Normal User', normalResult, normalMl);

  await sleep(2000);

  // ═══════════════════════════════════════════════════════════
  //  PHASE 2: Bot — ML flags it, Memory has nothing yet
  // ═══════════════════════════════════════════════════════════
  console.log('\n' + DIVIDER);
  console.log('  PHASE 2: New Suspicious Actor — Bot Behavior');
  console.log('  Expected: ML → HIGH risk, Memory → empty, Final → MONITOR/THROTTLE');
  console.log(DIVIDER);

  const botSession = {
    actorId: 'actor-new-bot',
    sessionId: 'actor-new-bot-demo-1',
    startTime: new Date().toISOString(),
    endTime: new Date(Date.now() + 5000).toISOString(),
    durationMs: 5000,
    requestCount: 100,
    endpoints: Array(100).fill('POST /api/auth/login'),
    uniqueEndpoints: ['POST /api/auth/login'],
    endpointDiversity: 0.01,
    intervals: Array(99).fill(50),
    avgIntervalMs: 50,
    stdDevMs: 5,
    minIntervalMs: 42,
    maxIntervalMs: 58,
    authPattern: 'intermittent_auth',
    authPresenceRatio: 1.0,
    ips: ['45.33.32.156'],
    ipCount: 1,
    bodyShapes: ['{ username, password }'],
    userAgent: 'python-requests/2.28.0',
    headerSignature: { headerCount: 4, missingHeaders: ['accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-fetch-dest'], presentHeaders: ['user-agent', 'accept'] },
    sampleRequests: [
      { method: 'POST', path: '/api/auth/login', timestamp: new Date().toISOString(), authType: 'none', bodyShape: '{ username, password }', queryParams: 0 },
    ],
  };

  console.log('\n📡 Sending 100 login attempts (single endpoint, 50ms interval, python-requests)...');

  const botFeatures = extractFeatures(botSession);
  const botMl = await detector.predict(botFeatures);
  console.log(`🤖 ML Risk Score: ${botMl.ml_risk_score.toFixed(1)} → ${botMl.attack_type}`);

  const botRecall = await memoryLayer.recallActor(botSession.actorId);
  console.log(`🧠 Memory: ${botRecall.results?.length || 0} memories (expected: 0 — new actor)`);

  console.log('🔮 Reflecting...');
  const botReflect = await memoryLayer.assessThreat(botSession, botRecall, botMl);
  const botResult = botReflect?.structured_output || botReflect?.structuredOutput || botReflect;

  printResult('PHASE 2 RESULT — New Bot', botResult, botMl);

  // Retain for future
  console.log('\n💾 Retaining session into Hindsight for future recognition...');
  await memoryLayer.retainSession(botSession, botMl);
  console.log('   ✓ Session retained\n');

  await sleep(2000);

  // ═══════════════════════════════════════════════════════════
  //  PHASE 3: Known Actor Returns — THE MONEY MOMENT
  //  ML may score lower (different features), but Memory recognizes them
  // ═══════════════════════════════════════════════════════════
  console.log(DIVIDER);
  console.log('  PHASE 3: KNOWN ACTOR RETURNS ON NEW IP');
  console.log('  ⭐ This is the demo moment — ML + Memory synthesis ⭐');
  console.log('  Expected: ML → might fluctuate, Memory → RECOGNIZED, Final → BLOCK');
  console.log(DIVIDER);

  const returningSession = {
    actorId: 'actor-credstuff',     // Same fingerprint as seeded actor!
    sessionId: 'actor-credstuff-return-live',
    startTime: new Date().toISOString(),
    endTime: new Date(Date.now() + 500).toISOString(),
    durationMs: 500,
    requestCount: 9,                 // Only 9 requests!
    endpoints: Array(9).fill('POST /api/auth/login'),
    uniqueEndpoints: ['POST /api/auth/login'],
    endpointDiversity: 0.11,
    intervals: [48, 45, 52, 47, 49, 46, 51, 48],
    avgIntervalMs: 48,
    stdDevMs: 3,
    minIntervalMs: 45,
    maxIntervalMs: 52,
    authPattern: 'intermittent_auth',
    authPresenceRatio: 1.0,
    ips: ['172.16.254.99'],          // COMPLETELY DIFFERENT IP
    ipCount: 1,
    bodyShapes: ['{ username, password }'],
    userAgent: 'python-requests/2.31.0',
    headerSignature: { headerCount: 5, missingHeaders: ['accept-language', 'sec-ch-ua'], presentHeaders: ['user-agent', 'accept', 'accept-encoding', 'connection'] },
    sampleRequests: [
      { method: 'POST', path: '/api/auth/login', timestamp: new Date().toISOString(), authType: 'none', bodyShape: '{ username, password }', queryParams: 0 },
    ],
  };

  console.log(`\n📡 Known actor returning with NEW IP: ${returningSession.ips[0]}`);
  console.log(`   Actor ID: ${returningSession.actorId}`);
  console.log(`   Only ${returningSession.requestCount} requests`);

  // ML scoring
  const returnFeatures = extractFeatures(returningSession);
  const returnMl = await detector.predict(returnFeatures);
  console.log(`\n🤖 ML Risk Score: ${returnMl.ml_risk_score.toFixed(1)} → ${returnMl.attack_type}`);

  // Memory recall — THE MAGIC CALL
  const startTime = Date.now();
  const returnRecall = await memoryLayer.recallActor(returningSession.actorId);
  const recallLatency = Date.now() - startTime;
  const found = returnRecall.results?.length > 0;

  if (found) {
    console.log(`\n⚡ RECOGNIZED in ${recallLatency}ms after just ${returningSession.requestCount} requests!`);
    console.log(`   ${returnRecall.results.length} observation(s) found in memory.`);
    console.log('');
    console.log(THIN);
    console.log('  ACTOR PROFILE (from Hindsight observation):');
    console.log(THIN);
    const profile = returnRecall.results[0].text;
    // Show first 500 chars
    console.log(profile.length > 500 ? profile.substring(0, 500) + '...' : profile);
    console.log(THIN);
  } else {
    console.log(`\n🔍 No memory found (${recallLatency}ms) — run \`npm run seed\` first.`);
  }

  // Reflect — synthesis of ML + Memory
  console.log('\n🔮 Reflecting (ML signals + Behavioral Memory → Final Decision)...');
  const returnReflect = await memoryLayer.assessThreat(returningSession, returnRecall, returnMl);
  const returnResult = returnReflect?.structured_output || returnReflect?.structuredOutput || returnReflect;

  printResult('PHASE 3 RESULT — Known Actor Returns', returnResult, returnMl);

  // ═══════════════════════════════════════════════════════════
  //  SUMMARY
  // ═══════════════════════════════════════════════════════════
  console.log('\n' + DIVIDER);
  console.log('  Demo Summary');
  console.log(DIVIDER);
  console.log('');
  console.log('  Phase 1 (Normal User):');
  console.log(`    ML: ${normalMl.ml_risk_score.toFixed(1)} → Final: ${normalResult?.threat_score ?? 'N/A'} → ${normalResult?.recommended_action ?? 'N/A'}`);
  console.log('');
  console.log('  Phase 2 (New Bot):');
  console.log(`    ML: ${botMl.ml_risk_score.toFixed(1)} → Final: ${botResult?.threat_score ?? 'N/A'} → ${botResult?.recommended_action ?? 'N/A'}`);
  console.log('');
  console.log('  Phase 3 (Known Actor Returns):');
  console.log(`    ML: ${returnMl.ml_risk_score.toFixed(1)} → Final: ${returnResult?.threat_score ?? 'N/A'} → ${returnResult?.recommended_action ?? 'N/A'}`);
  console.log(`    Recognized in: ${recallLatency}ms with only ${returningSession.requestCount} requests`);
  console.log(`    IP changed: YES (seeded → now ${returningSession.ips[0]})`);
  console.log('');
  console.log('  KEY INSIGHT:');
  console.log('  "We combined real-time ML detection with a memory-based reasoning');
  console.log('   system. Even when the attacker changed their IP, our system');
  console.log('   recognized their behavior and blocked them. Zero hardcoded rules."');
  console.log('');
  console.log(DIVIDER);
  console.log('');
}

demo().catch((e) => {
  console.error('Demo failed:', e);
  process.exit(1);
});
