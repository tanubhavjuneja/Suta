// test-debug.js - Debug test
import fetch from 'fetch';

async function main() {
  console.log('Testing getLogConfig...');
  
  try {
    const res = await fetch('http://localhost:3000/admin/logs/config');
    console.log('Status:', res.status);
    const text = await res.text();
    console.log('Raw response:', text);
    const data = JSON.parse(text);
    console.log('Parsed:', data);
  } catch (e) {
    console.log('Error:', e.message);
  }
}

main();