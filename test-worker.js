// test-worker.js - Test script for worker endpoints

const tests = [];

async function test(name, fn) {
  try {
    const result = await fn();
    if (result.success) {
      console.log(`PASS: ${name}`);
      tests.push({ name, success: true });
    } else {
      console.log(`FAIL: ${name} - ${result.error}`);
      tests.push({ name, success: false, error: result.error });
    }
  } catch (e) {
    console.log(`ERROR: ${name} - ${e.message}`);
    tests.push({ name, success: false, error: e.message });
  }
}

async function main() {
  console.log('Testing Worker Endpoints...\n');

  // Test 1: Get Config
  await test('Get Config', async () => {
    const res = await fetch('http://localhost:3000/admin/config');
    const data = await res.json();
    return { success: res.ok && data.port };
  });

  // Test 2: Get Blocked IPs
  await test('Get Blocked IPs', async () => {
    const res = await fetch('http://localhost:3000/admin/blocked-ips');
    const data = await res.json();
    return { success: res.ok && Array.isArray(data) };
  });

  // Test 3: Block an IP
  await test('Block IP', async () => {
    const res = await fetch('http://localhost:3000/admin/blocked-ips', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: '192.168.1.100', reason: 'Test block' })
    });
    const data = await res.json();
    return { success: res.ok && data.success };
  });

  // Test 4: Get Blocked IPs after block
  await test('Get Blocked IPs (after block)', async () => {
    const res = await fetch('http://localhost:3000/admin/blocked-ips');
    const data = await res.json();
    return { success: res.ok && data.length > 0 && data[0].ip === '192.168.1.100' };
  });

  // Test 5: Unblock IP
  await test('Unblock IP', async () => {
    const res = await fetch('http://localhost:3000/admin/blocked-ips/192.168.1.100', {
      method: 'DELETE'
    });
    const data = await res.json();
    return { success: res.ok && data.success };
  });

  // Test 6: Get logs
  await test('Get Logs', async () => {
    const res = await fetch('http://localhost:3000/admin/logs');
    const data = await res.json();
    return { success: res.ok && data.files !== undefined };
  });

  // Test 7: Get log config
  await test('Get Log Config', async () => {
    const res = await fetch('http://localhost:3000/admin/logs/config');
    const data = await res.json();
    return { success: res.ok && data.maxDays !== undefined };
  });

  // Test 8: Server status
  await test('Server Status', async () => {
    const res = await fetch('http://localhost:3000/admin/server/status');
    const data = await res.json();
    return { success: res.ok && data.port !== undefined };
  });

  // Test 9: Pipeline Status (should be active now)
  await test('Pipeline Status (active)', async () => {
    const res = await fetch('http://localhost:3000/admin/server/status');
    const data = await res.json();
    return { success: res.ok && data.running === true };
  });

  // Test 10: Get Rules
  await test('Get Rules', async () => {
    const res = await fetch('http://localhost:3000/admin/rules');
    const data = await res.json();
    return { success: res.ok && data.rules !== undefined };
  });

  // Summary
  console.log('\n--- Test Results ---');
  const passed = tests.filter(t => t.success).length;
  const failed = tests.filter(t => !t.success).length;
  console.log(`Passed: ${passed}/${tests.length}`);
  if (failed > 0) {
    console.log('Failed tests:');
    tests.filter(t => !t.success).forEach(t => console.log(`  - ${t.name}: ${t.error}`));
  }
}

main();