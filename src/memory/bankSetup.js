// src/memory/bankSetup.js
// ═══════════════════════════════════════════════════════════════
// One-time bank configuration — run on server startup.
// Sets the missions and disposition that shape all Hindsight
// behavior for this memory bank.
// ═══════════════════════════════════════════════════════════════
import hindsight from './hindsightClient.js';
import config from '../config.js';

export async function setupMemoryBank() {
  console.log('🏦 Setting up Hindsight memory bank...');

  // 1. Create bank (idempotent — OK if exists)
  try {
    await hindsight.createBank();
    console.log(`   ✓ Bank "${config.hindsight.bankId}" ready`);
  } catch (e) {
    console.log(`   ⚠ Bank creation: ${e.message}`);
  }

  // 2. Configure retain mission (steers fact extraction)
  try {
    await hindsight.configureBankRetain(config.bankConfig.retainMission, 'verbose');
    console.log('   ✓ Retain mission configured');
  } catch (e) {
    console.log(`   ⚠ Retain config: ${e.message}`);
  }

  // 3. Configure observation consolidation
  try {
    await hindsight.configureBankObservations(config.bankConfig.observationsMission);
    console.log('   ✓ Observation mission configured');
  } catch (e) {
    console.log(`   ⚠ Observation config: ${e.message}`);
  }

  // 4. Configure reflect mission (shapes threat analysis persona)
  try {
    await hindsight.configureBankReflect(config.bankConfig.reflectMission);
    console.log('   ✓ Reflect mission configured');
  } catch (e) {
    console.log(`   ⚠ Reflect config: ${e.message}`);
  }

  // 5. Set disposition (high skepticism for adversarial analysis)
  // Note: Cloud API may not support all disposition fields — non-fatal
  try {
    await hindsight.configureDisposition(0.8, 0.7, 0.2);
    console.log('   ✓ Disposition configured (skepticism: 0.8, literalism: 0.7, empathy: 0.2)');
  } catch (e) {
    console.log(`   ⚠ Disposition config skipped (not supported on Cloud): ${e.message.substring(0, 80)}`);
  }

  console.log('🏦 Memory bank setup complete.\n');
}
