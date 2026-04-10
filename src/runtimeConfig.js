// src/runtimeConfig.js
// Shared runtime configuration - exported for both server.js and enforcer.js
// This avoids circular imports while allowing dynamic config updates
import 'dotenv/config';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const configDir = join(__dirname, '..', 'config');

if (!fs.existsSync(configDir)) {
  fs.mkdirSync(configDir, { recursive: true });
}

const userConfigPath = join(configDir, 'user-config.json');
const rulesCachePath = join(configDir, 'rules-cache.json');
const modelCachePath = join(configDir, 'model-cache.json');
const blockedIPsPath = join(configDir, 'blocked-ips.json');
const rulesPath = join(configDir, 'rules.json');

// Default config - reads from environment variables first, then hardcoded fallbacks
const defaultConfig = {
  port: parseInt(process.env.PORT || '3000', 10),
  hindsight: { 
    baseUrl: process.env.HINDSIGHT_BASE_URL || 'http://localhost:8888',
  },
  enforcement: { 
    blockScore: parseInt(process.env.BLOCK_SCORE || '85', 10),
    throttleScore: parseInt(process.env.THROTTLE_SCORE || '70', 10),
    monitorScore: parseInt(process.env.MONITOR_SCORE || '40', 10),
  },
  rulesFilePath: process.env.RULES_FILE_PATH || '',
  importedRules: [],
  ollamaEndpoint: process.env.OLLAMA_ENDPOINT || 'http://localhost:11434',
  ollamaModel: process.env.OLLAMA_MODEL || 'llama3.2',
  
  // Logging configuration
  logging: {
    maxDays: parseInt(process.env.LOG_MAX_DAYS || '7', 10),
    maxSizeMB: parseInt(process.env.LOG_MAX_SIZE_MB || '100', 10),
    chunkSizeMB: parseInt(process.env.LOG_CHUNK_SIZE_MB || '4', 10),
  },
  
  // Training configuration
  training: {
    enabled: process.env.TRAINING_ENABLED === 'true' || false,
    intervalHours: parseInt(process.env.TRAINING_INTERVAL_HOURS || '1', 10),
    useIncremental: true,
    enableRulesTrigger: true,
    rulesThreshold: parseInt(process.env.TRAINING_RULES_THRESHOLD || '5', 10),
    forceFullRetrainEvery: parseInt(process.env.TRAINING_FULL_RETRAIN_HOURS || '24', 10),
    trainingStatus: 'idle',
    lastTrainedAt: null,
    nextScheduledAt: null,
    rulesChangedSinceLastTrain: 0,
  },
  
  // Ollama analysis configuration
  ollama: {
    autoAnalyze: process.env.OLLAMA_AUTO_ANALYZE === 'true' || false,
    analyzeIntervalMinutes: parseInt(process.env.OLLAMA_ANALYZE_INTERVAL || '30', 10),
    analysisStatus: 'idle',
    lastAnalyzedAt: null,
  },
  
  // Runtime stats
  _stats: {
    totalRequests: 0,
    allowed: 0,
    blocked: 0,
    blockedIPs: 0,
    activeActors: 0,
  },
};

// Runtime config - starts with defaults, then loads from user config file
let runtimeConfig = { ...defaultConfig };

// Load from user config file if exists
export function loadUserConfig() {
  try {
    if (fs.existsSync(userConfigPath)) {
      const data = fs.readFileSync(userConfigPath, 'utf8');
      const saved = JSON.parse(data);
      // Merge saved config with defaults (env vars take precedence)
      runtimeConfig = { ...defaultConfig, ...saved };
      console.log('[Config] Loaded user config from file');
    }
  } catch (e) {
    console.log('[Config] Using default config');
  }
  return runtimeConfig;
}

// Save current config to file
export function saveUserConfig() {
  try {
    fs.writeFileSync(userConfigPath, JSON.stringify(runtimeConfig, null, 2));
    return true;
  } catch (e) {
    console.error('[Config] Failed to save:', e.message);
    return false;
  }
}

// Load rules from file path
export function loadRulesFromPath(filePath) {
  try {
    if (!filePath || !fs.existsSync(filePath)) {
      return null;
    }
    const content = fs.readFileSync(filePath, 'utf8');
    const ext = filePath.toLowerCase();
    
    if (ext.endsWith('.json')) {
      return JSON.parse(content);
    } else if (ext.endsWith('.csv') || ext.endsWith('.txt')) {
      const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
      return lines.map(line => {
        const parts = line.split(/[,\t\s]+/);
        return {
          pattern: parts[0]?.trim(),
          action: parts[1]?.trim() || 'block',
          description: parts.slice(2).join(' ').trim() || 'Imported rule',
        };
      });
    }
    return null;
  } catch (e) {
    console.error('[Rules] Failed to load:', e.message);
    return null;
  }
}

// Rules cache functions
export function getRulesCache() {
  try {
    if (fs.existsSync(rulesCachePath)) {
      return JSON.parse(fs.readFileSync(rulesCachePath, 'utf8'));
    }
  } catch {}
  return { hash: '', rules: [], ollamaSuggestions: [] };
}

export function saveRulesCache(cache) {
  try {
    fs.writeFileSync(rulesCachePath, JSON.stringify(cache, null, 2));
  } catch (e) {
    console.error('[Rules] Failed to save cache:', e.message);
  }
}

// Model cache functions
export function getModelCache() {
  try {
    if (fs.existsSync(modelCachePath)) {
      return JSON.parse(fs.readFileSync(modelCachePath, 'utf8'));
    }
  } catch {}
  return { hash: '', trained: false, trainedAt: null };
}

export function saveModelCache(cache) {
  try {
    fs.writeFileSync(modelCachePath, JSON.stringify(cache, null, 2));
  } catch (e) {
    console.error('[Model] Failed to save cache:', e.message);
  }
}

// Compute hash for rules (for model cache invalidation)
export function computeRulesHash(rules) {
  return JSON.stringify(rules).split('').reduce((a, b) => ((a << 5) - a) + b.charCodeAt(0), 0).toString(16);
}

// Update config
export function updateConfig(newConfig) {
  let changed = false;
  
  if (newConfig.port && newConfig.port !== runtimeConfig.port) {
    runtimeConfig.port = newConfig.port;
    changed = true;
  }
  if (newConfig.hindsight?.baseUrl && newConfig.hindsight.baseUrl !== runtimeConfig.hindsight.baseUrl) {
    runtimeConfig.hindsight.baseUrl = newConfig.hindsight.baseUrl;
    changed = true;
  }
  if (newConfig.enforcement) {
    if (newConfig.enforcement.blockScore !== undefined) {
      runtimeConfig.enforcement.blockScore = newConfig.enforcement.blockScore;
      changed = true;
    }
    if (newConfig.enforcement.throttleScore !== undefined) {
      runtimeConfig.enforcement.throttleScore = newConfig.enforcement.throttleScore;
      changed = true;
    }
    if (newConfig.enforcement.monitorScore !== undefined) {
      runtimeConfig.enforcement.monitorScore = newConfig.enforcement.monitorScore;
      changed = true;
    }
  }
  if (newConfig.rulesFilePath !== undefined && newConfig.rulesFilePath !== runtimeConfig.rulesFilePath) {
    runtimeConfig.rulesFilePath = newConfig.rulesFilePath;
    changed = true;
  }
  if (newConfig.importedRules) {
    runtimeConfig.importedRules = newConfig.importedRules;
    changed = true;
  }
  if (newConfig.ollamaEndpoint !== undefined) {
    runtimeConfig.ollamaEndpoint = newConfig.ollamaEndpoint;
    changed = true;
  }
  if (newConfig.ollamaModel !== undefined) {
    runtimeConfig.ollamaModel = newConfig.ollamaModel;
    changed = true;
  }
  
  // Training config updates
  if (newConfig.training) {
    if (newConfig.training.enabled !== undefined) {
      runtimeConfig.training.enabled = newConfig.training.enabled;
      changed = true;
    }
    if (newConfig.training.intervalHours !== undefined) {
      runtimeConfig.training.intervalHours = newConfig.training.intervalHours;
      changed = true;
    }
    if (newConfig.training.useIncremental !== undefined) {
      runtimeConfig.training.useIncremental = newConfig.training.useIncremental;
      changed = true;
    }
    if (newConfig.training.enableRulesTrigger !== undefined) {
      runtimeConfig.training.enableRulesTrigger = newConfig.training.enableRulesTrigger;
      changed = true;
    }
    if (newConfig.training.rulesThreshold !== undefined) {
      runtimeConfig.training.rulesThreshold = newConfig.training.rulesThreshold;
      changed = true;
    }
    if (newConfig.training.forceFullRetrainEvery !== undefined) {
      runtimeConfig.training.forceFullRetrainEvery = newConfig.training.forceFullRetrainEvery;
      changed = true;
    }
    if (newConfig.training.trainingStatus !== undefined) {
      runtimeConfig.training.trainingStatus = newConfig.training.trainingStatus;
    }
    if (newConfig.training.lastTrainedAt !== undefined) {
      runtimeConfig.training.lastTrainedAt = newConfig.training.lastTrainedAt;
    }
    if (newConfig.training.nextScheduledAt !== undefined) {
      runtimeConfig.training.nextScheduledAt = newConfig.training.nextScheduledAt;
    }
    if (newConfig.training.rulesChangedSinceLastTrain !== undefined) {
      runtimeConfig.training.rulesChangedSinceLastTrain = newConfig.training.rulesChangedSinceLastTrain;
    }
  }
  
  // Ollama config updates
  if (newConfig.ollama) {
    if (newConfig.ollama.autoAnalyze !== undefined) {
      runtimeConfig.ollama.autoAnalyze = newConfig.ollama.autoAnalyze;
      changed = true;
    }
    if (newConfig.ollama.analyzeIntervalMinutes !== undefined) {
      runtimeConfig.ollama.analyzeIntervalMinutes = newConfig.ollama.analyzeIntervalMinutes;
      changed = true;
    }
    if (newConfig.ollama.analysisStatus !== undefined) {
      runtimeConfig.ollama.analysisStatus = newConfig.ollama.analysisStatus;
    }
    if (newConfig.ollama.lastAnalyzedAt !== undefined) {
      runtimeConfig.ollama.lastAnalyzedAt = newConfig.ollama.lastAnalyzedAt;
    }
  }
  
  // Stats updates
  if (newConfig._stats) {
    if (newConfig._stats.totalRequests !== undefined) {
      runtimeConfig._stats.totalRequests = newConfig._stats.totalRequests;
    }
    if (newConfig._stats.allowed !== undefined) {
      runtimeConfig._stats.allowed = newConfig._stats.allowed;
    }
    if (newConfig._stats.blocked !== undefined) {
      runtimeConfig._stats.blocked = newConfig._stats.blocked;
    }
    if (newConfig._stats.blockedIPs !== undefined) {
      runtimeConfig._stats.blockedIPs = newConfig._stats.blockedIPs;
    }
    if (newConfig._stats.activeActors !== undefined) {
      runtimeConfig._stats.activeActors = newConfig._stats.activeActors;
    }
  }
  
  if (changed) {
    saveUserConfig();
  }
  
  return runtimeConfig;
}

// Export the config object (live reference)
export const config = runtimeConfig;

// Initialize on load
loadUserConfig();

export default config;