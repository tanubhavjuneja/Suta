import 'dotenv/config';

function readIntEnv(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? `${fallback}`, 10);
  return Number.isFinite(value) ? value : fallback;
}

function readBoolEnv(name, fallback = false) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return value === 'true';
}

export function createDefaultConfig() {
  return {
    port: readIntEnv('PORT', 3000),
    hindsight: {
      baseUrl: process.env.HINDSIGHT_BASE_URL || 'http://localhost:8888',
    },
    enforcement: {
      blockScore: readIntEnv('BLOCK_SCORE', 85),
      throttleScore: readIntEnv('THROTTLE_SCORE', 70),
      monitorScore: readIntEnv('MONITOR_SCORE', 40),
    },
    rulesFilePath: process.env.RULES_FILE_PATH || '',
    importedRules: [],
    rules: [],
    ollamaEndpoint: process.env.OLLAMA_ENDPOINT || 'http://localhost:11434',
    ollamaModel: process.env.OLLAMA_MODEL || 'llama3.2',
    logging: {
      maxDays: readIntEnv('LOG_MAX_DAYS', 7),
      maxSizeMB: readIntEnv('LOG_MAX_SIZE_MB', 100),
      chunkSizeMB: readIntEnv('LOG_CHUNK_SIZE_MB', 4),
    },
    training: {
      enabled: readBoolEnv('TRAINING_ENABLED', false),
      intervalHours: readIntEnv('TRAINING_INTERVAL_HOURS', 1),
      useIncremental: readBoolEnv('TRAINING_USE_INCREMENTAL', true),
      enableRulesTrigger: readBoolEnv('TRAINING_ENABLE_RULES_TRIGGER', true),
      rulesThreshold: readIntEnv('TRAINING_RULES_THRESHOLD', 5),
      forceFullRetrainEvery: readIntEnv('TRAINING_FULL_RETRAIN_HOURS', 24),
      trainingStatus: 'idle',
      lastTrainedAt: null,
      nextScheduledAt: null,
      rulesChangedSinceLastTrain: 0,
    },
    ollama: {
      autoAnalyze: readBoolEnv('OLLAMA_AUTO_ANALYZE', false),
      analyzeIntervalMinutes: readIntEnv('OLLAMA_ANALYZE_INTERVAL', 30),
      analysisStatus: 'idle',
      lastAnalyzedAt: null,
    },
    _stats: {
      totalRequests: 0,
      allowed: 0,
      blocked: 0,
      blockedIPs: 0,
      activeActors: 0,
    },
  };
}

export function mergeConfig(saved = {}) {
  const defaults = createDefaultConfig();

  return {
    ...defaults,
    ...saved,
    hindsight: {
      ...defaults.hindsight,
      ...(saved.hindsight || {}),
    },
    enforcement: {
      ...defaults.enforcement,
      ...(saved.enforcement || {}),
    },
    importedRules: Array.isArray(saved.importedRules) ? saved.importedRules : defaults.importedRules,
    rules: Array.isArray(saved.rules) ? saved.rules : defaults.rules,
    logging: {
      ...defaults.logging,
      ...(saved.logging || {}),
    },
    training: {
      ...defaults.training,
      ...(saved.training || {}),
    },
    ollama: {
      ...defaults.ollama,
      ...(saved.ollama || {}),
    },
    _stats: {
      ...defaults._stats,
      ...(saved._stats || {}),
    },
  };
}
