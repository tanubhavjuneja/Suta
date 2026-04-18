// src/runtimeConfig.js
// Shared runtime configuration - exported for both server.js and enforcer.js
// This avoids circular imports while allowing dynamic config updates
import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createDefaultConfig, mergeConfig } from './configDefaults.js';

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

// Runtime config - preserve this object reference so imports stay in sync
const runtimeConfig = mergeConfig();

// Load from user config file if exists
export function loadUserConfig() {
  try {
    let saved = {};
    if (fs.existsSync(userConfigPath)) {
      const data = fs.readFileSync(userConfigPath, 'utf8');
      saved = JSON.parse(data);
      console.log('[Config] Loaded user config from file');
    }
    Object.assign(runtimeConfig, mergeConfig(saved));
  } catch (e) {
    console.log('[Config] Using default config');
    Object.assign(runtimeConfig, createDefaultConfig());
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
  if (newConfig.rules) {
    runtimeConfig.rules = newConfig.rules;
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
      changed = true;
    }
    if (newConfig.training.lastTrainedAt !== undefined) {
      runtimeConfig.training.lastTrainedAt = newConfig.training.lastTrainedAt;
      changed = true;
    }
    if (newConfig.training.nextScheduledAt !== undefined) {
      runtimeConfig.training.nextScheduledAt = newConfig.training.nextScheduledAt;
      changed = true;
    }
    if (newConfig.training.rulesChangedSinceLastTrain !== undefined) {
      runtimeConfig.training.rulesChangedSinceLastTrain = newConfig.training.rulesChangedSinceLastTrain;
      changed = true;
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
      changed = true;
    }
    if (newConfig.ollama.lastAnalyzedAt !== undefined) {
      runtimeConfig.ollama.lastAnalyzedAt = newConfig.ollama.lastAnalyzedAt;
      changed = true;
    }
  }

  if (newConfig.logging) {
    if (newConfig.logging.maxDays !== undefined) {
      runtimeConfig.logging.maxDays = newConfig.logging.maxDays;
      changed = true;
    }
    if (newConfig.logging.maxSizeMB !== undefined) {
      runtimeConfig.logging.maxSizeMB = newConfig.logging.maxSizeMB;
      changed = true;
    }
    if (newConfig.logging.chunkSizeMB !== undefined) {
      runtimeConfig.logging.chunkSizeMB = newConfig.logging.chunkSizeMB;
      changed = true;
    }
  }
  
  // Stats updates
  if (newConfig._stats) {
    if (newConfig._stats.totalRequests !== undefined) {
      runtimeConfig._stats.totalRequests = newConfig._stats.totalRequests;
      changed = true;
    }
    if (newConfig._stats.allowed !== undefined) {
      runtimeConfig._stats.allowed = newConfig._stats.allowed;
      changed = true;
    }
    if (newConfig._stats.blocked !== undefined) {
      runtimeConfig._stats.blocked = newConfig._stats.blocked;
      changed = true;
    }
    if (newConfig._stats.blockedIPs !== undefined) {
      runtimeConfig._stats.blockedIPs = newConfig._stats.blockedIPs;
      changed = true;
    }
    if (newConfig._stats.activeActors !== undefined) {
      runtimeConfig._stats.activeActors = newConfig._stats.activeActors;
      changed = true;
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
