// test/test-add-rules.js
// Test script to verify adding new rules programmatically

async function testAddRules() {
  console.log('=== Testing Add Rules ===\n');

  const runtimeConfigModule = await import('../src/runtimeConfig.js');
  const { config, updateConfig } = runtimeConfigModule;

  console.log('1. Testing adding a rule via updateConfig...');

  const newRule = {
    pattern: '10.10.10.0/24',
    action: 'block',
    description: 'Test rule - blocked subnet',
    source: 'test'
  };

  if (!config.rules) {
    config.rules = [];
  }

  const beforeCount = config.rules.length;

  updateConfig({
    rules: [...config.rules, newRule]
  });

  console.log('   Rule added successfully');
  console.log('   Rule count:', beforeCount, '->', config.rules.length);

  console.log('\n2. Testing rule object structure...');
  const added = config.rules.find(r => r.pattern === newRule.pattern);
  console.log('   Added rule:', JSON.stringify(added, null, 2));

  console.log('\n3. Verifying rule fields...');
  const hasRequired = added && added.pattern && added.action;
  console.log('   Has required fields:', hasRequired ? 'YES' : 'NO');

  if (!hasRequired) {
    console.log('   ERROR: Rule missing required fields');
    process.exit(1);
  }

  console.log('\n=== Add Rules Test PASSED ===\n');
  console.log('Summary:');
  console.log('  - Rule added:', newRule.pattern);
  console.log('  - Action:', newRule.action);
  console.log('');

  return { success: true, rule: added };
}

testAddRules().catch(e => {
  console.error('TEST FAILED:', e.message);
  process.exit(1);
});