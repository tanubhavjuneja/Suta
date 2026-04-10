// src/ml/dataGenerator.js
// Generates training data from multiple sources
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';
import memoryLayer from '../memory/memoryLayer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const patternsPath = join(__dirname, '../../config/training-patterns.json');

const ATTACK_TYPES = ['normal', 'credential_stuffing', 'data_scraping', 'enumeration', 'rate_limit_evasion', 'brute_force'];
const NUM_CLASSES = ATTACK_TYPES.length;

// Load patterns from external file
let patterns = [];

function loadPatterns() {
  try {
    if (fs.existsSync(patternsPath)) {
      const data = JSON.parse(fs.readFileSync(patternsPath, 'utf8'));
      if (data.patterns && Array.isArray(data.patterns)) {
        patterns = data.patterns;
        console.log('[DataGen] Loaded', patterns.length, 'patterns from file');
        return;
      }
    }
  } catch (e) {
    console.log('[DataGen] Failed to load patterns:', e.message);
  }
  
  patterns = [
    { label: 'normal', riskRange: [0, 20], count: 120 },
    { label: 'credential_stuffing', riskRange: [70, 98], count: 80 },
    { label: 'data_scraping', riskRange: [55, 90], count: 80 },
    { label: 'enumeration', riskRange: [50, 85], count: 80 },
    { label: 'rate_limit_evasion', riskRange: [45, 80], count: 80 },
    { label: 'brute_force', riskRange: [75, 99], count: 60 },
  ];
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

// Generate base session from pattern
function generateBaseSession(pattern) {
  const gen = pattern.generator || {};
  const isNormal = pattern.label === 'normal';
  
  return {
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
      missingHeaders: gen.missingHeaders || [],
    },
  };
}

// Convert session to feature vector (simplified - uses featureExtractor internally)
function sessionToFeatures(session) {
  const features = new Array(20).fill(0);
  
  features[0] = Math.min(session.requestCount / 2000, 1);
  features[1] = Math.min(session.durationMs / 500000, 1);
  features[2] = Math.min(session.avgIntervalMs / 15000, 1);
  features[3] = Math.min(session.stdDevMs / 5000, 1);
  features[4] = session.authPresenceRatio;
  features[5] = session.ipCount > 1 ? 1 : 0;
  features[6] = session.headerSignature.headerCount / 20;
  features[7] = session.headerSignature.missingHeaders.length / 10;
  features[8] = new Set(session.endpoints || []).size / Math.max(session.requestCount, 1);
  features[9] = session.userAgent.includes('python') || session.userAgent.includes('curl') ? 1 : 0;
  features[10] = session.endpoints?.includes('login') || session.endpoints?.includes('auth') ? 1 : 0;
  features[11] = session.endpoints?.some(e => e.includes('/users/')) ? 1 : 0;
  features[12] = session.endpoints?.some(e => e.includes('/search')) ? 1 : 0;
  features[13] = session.endpoints?.some(e => e.includes('/products')) ? 1 : 0;
  features[14] = session.authPattern === 'no_auth' ? 1 : 0;
  features[15] = session.authPattern === 'intermittent_auth' ? 1 : 0;
  features[16] = session.requestCount > 100 ? 1 : 0;
  features[17] = session.requestCount > 500 ? 1 : 0;
  features[18] = session.avgIntervalMs < 100 ? 1 : 0;
  features[19] = session.ipCount > 3 ? 1 : 0;
  
  return features;
}

// Generate from firewall rules
function generateFromRules(rules) {
  const features = [];
  const riskScores = [];
  const attackLabels = [];
  
  for (const rule of rules) {
    const labelIndex = ATTACK_TYPES.indexOf('credential_stuffing');
    if (labelIndex === -1) continue;
    
    const isBlock = rule.action === 'block';
    const risk = isBlock ? randFloat(60, 95) : randFloat(20, 50);
    
    const session = {
      requestCount: randInt(50, 500),
      durationMs: randInt(10000, 100000),
      avgIntervalMs: randInt(10, 200),
      stdDevMs: randInt(5, 50),
      ipCount: 1,
      authPattern: 'no_auth',
      authPresenceRatio: 0,
      userAgent: 'python-requests/2.31.0',
      headerSignature: { headerCount: randInt(3, 6), missingHeaders: ['accept-language', 'sec-ch-ua'] },
    };
    
    if (rule.pattern) {
      if (rule.pattern.includes('/auth') || rule.pattern.includes('login')) {
        session.endpoints = Array.from({ length: session.requestCount }, () => 'POST /api/auth/login');
      } else if (rule.pattern.includes('/users')) {
        session.endpoints = Array.from({ length: session.requestCount }, () => 'GET /api/users/1');
      } else {
        session.endpoints = Array.from({ length: session.requestCount }, () => rule.pattern);
      }
    } else {
      session.endpoints = Array.from({ length: session.requestCount }, () => 'GET /api/blocked');
    }
    
    const featureVec = sessionToFeatures(session);
    features.push(featureVec);
    riskScores.push(risk);
    
    const oneHot = new Array(NUM_CLASSES).fill(0);
    oneHot[labelIndex] = 1;
    attackLabels.push(oneHot);
  }
  
  return { features, riskScores, attackLabels };
}

// Generate from Hindsight memories
async function generateFromHindsight() {
  const features = [];
  const riskScores = [];
  const attackLabels = [];
  
  try {
    const queryResult = await memoryLayer.query('List all known attack patterns and blocked actors with their signatures');
    
    if (queryResult && queryResult.text) {
      const text = queryResult.text;
      
      const highRiskPatterns = [
        { type: 'credential_stuffing', indicator: ['login', 'auth', 'password'] },
        { type: 'data_scraping', indicator: ['users', 'profile', 'bulk'] },
        { type: 'enumeration', indicator: ['users', 'id', 'sequential'] },
      ];
      
      for (const pattern of highRiskPatterns) {
        if (text.toLowerCase().includes(pattern.indicator[0])) {
          for (let i = 0; i < 20; i++) {
            const session = {
              requestCount: randInt(100, 1000),
              durationMs: randInt(10000, 100000),
              avgIntervalMs: randInt(50, 500),
              stdDevMs: randInt(10, 100),
              ipCount: randInt(1, 5),
              authPattern: 'no_auth',
              authPresenceRatio: 0,
              userAgent: pick(['python-requests/2.31.0', 'curl/8.4.0', 'Scrapy/2.11']),
              headerSignature: { headerCount: randInt(3, 8), missingHeaders: ['accept-language', 'sec-ch-ua'] },
              endpoints: Array.from({ length: session.requestCount }, () => 'GET /api/' + pattern.indicator[0]),
            };
            
            const featureVec = sessionToFeatures(session);
            features.push(featureVec);
            riskScores.push(randFloat(55, 90));
            
            const labelIndex = ATTACK_TYPES.indexOf(pattern.type);
            if (labelIndex !== -1) {
              const oneHot = new Array(NUM_CLASSES).fill(0);
              oneHot[labelIndex] = 1;
              attackLabels.push(oneHot);
            }
          }
        }
      }
    }
  } catch (e) {
    console.log('[DataGen] Hindsight query failed:', e.message);
  }
  
  return { features, riskScores, attackLabels };
}

// Main function - combine all sources
export async function generateTrainingData(rules = []) {
  console.log('[DataGen] Generating training data...');
  
  const features = [];
  const riskScores = [];
  const attackLabels = [];
  
  // 1. Base patterns from config file
  for (const pattern of patterns) {
    const labelIndex = ATTACK_TYPES.indexOf(pattern.label);
    if (labelIndex === -1) continue;
    
    const count = pattern.count || 50;
    for (let i = 0; i < count; i++) {
      const session = generateBaseSession(pattern);
      
      const defaults = ['GET /api/health', 'GET /api/users/1', 'GET /api/users/2/profile', 'GET /api/products/5', 'GET /api/search', 'POST /api/auth/login'];
      session.endpoints = Array.from({ length: session.requestCount }, () => pick(defaults));
      
      const featureVec = sessionToFeatures(session);
      features.push(featureVec);
      riskScores.push(randFloat(pattern.riskRange[0], pattern.riskRange[1]));
      
      const oneHot = new Array(NUM_CLASSES).fill(0);
      oneHot[labelIndex] = 1;
      attackLabels.push(oneHot);
    }
  }
  
  console.log('[DataGen] Base patterns:', features.length, 'samples');
  
  // 2. From firewall rules
  if (rules && rules.length > 0) {
    const ruleData = generateFromRules(rules);
    features.push(...ruleData.features);
    riskScores.push(...ruleData.riskScores);
    attackLabels.push(...ruleData.attackLabels);
    console.log('[DataGen] From rules:', ruleData.features.length, 'samples');
  }
  
  // 3. From Hindsight memories
  const hindsightData = await generateFromHindsight();
  if (hindsightData.features.length > 0) {
    features.push(...hindsightData.features);
    riskScores.push(...hindsightData.riskScores);
    attackLabels.push(...hindsightData.attackLabels);
    console.log('[DataGen] From Hindsight:', hindsightData.features.length, 'samples');
  }
  
  console.log('[DataGen] Total:', features.length, 'samples');
  
  return { features, riskScores, attackLabels };
}

export { ATTACK_TYPES, NUM_CLASSES };