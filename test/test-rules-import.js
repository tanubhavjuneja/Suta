// test/test-rules-import.js
// Test script to verify rules import functionality

import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function testRulesImport() {
  console.log('=== Testing Rules Import ===\n');

  const runtimeConfigModule = await import('../src/runtimeConfig.js');
  const { loadRulesFromPath } = runtimeConfigModule;

  const configDir = join(__dirname, '..', 'config');
  const testRulesPath = join(configDir, 'email-firewall-rules.json');

  console.log('1. Testing loadRulesFromPath with JSON file...');
  console.log('   File path:', testRulesPath);

  if (!fs.existsSync(testRulesPath)) {
    console.log('   ERROR: Test file not found:', testRulesPath);
    process.exit(1);
  }

  const rules = loadRulesFromPath(testRulesPath);

  if (!rules) {
    console.log('   ERROR: Failed to load rules');
    process.exit(1);
  }

  console.log('   SUCCESS: Loaded', rules.length, 'rules');
  console.log('   Rules:', JSON.stringify(rules, null, 2));

  console.log('\n2. Verifying rule structure...');
  const validRules = rules.filter(r => r.pattern && r.action);
  console.log('   Valid rules:', validRules.length);

  if (validRules.length !== rules.length) {
    console.log('   ERROR: Some rules are invalid');
    process.exit(1);
  }

  console.log('   SUCCESS: All rules are valid');

  console.log('\n3. Testing enforcement actions...');
  const actions = new Set(rules.map(r => r.action));
  console.log('   Actions found:', Array.from(actions));

  const expectedActions = ['block', 'monitor'];
  const hasExpected = expectedActions.some(a => actions.has(a));
  if (!hasExpected) {
    console.log('   WARNING: No expected actions found');
  }

  console.log('\n=== Rules Import Test PASSED ===\n');
  console.log('Summary:');
  console.log('  - File loaded:', testRulesPath);
  console.log('  - Rules count:', rules.length);
  console.log('  - All rules valid: YES');
  console.log('');

  return { success: true, rules };
}

testRulesImport().catch(e => {
  console.error('TEST FAILED:', e.message);
  process.exit(1);
});