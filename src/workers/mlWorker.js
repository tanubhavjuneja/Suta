// src/workers/mlWorker.js
// ML Worker - handles model training, Ollama analysis, log queries
// ═══════════════════════════════════════════════════════════════
import { parentPort } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createDefaultConfig, mergeConfig } from '../configDefaults.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_DIR = path.join(__dirname, '../../config');
const MODEL_DIR = path.join(CONFIG_DIR, 'model');
const FALLBACK_PATTERNS = [
  { label: 'normal', riskRange: [0, 20], count: 40, generator: {} },
  { label: 'credential_stuffing', riskRange: [70, 98], count: 30, generator: {} },
  { label: 'data_scraping', riskRange: [55, 90], count: 30, generator: {} },
  { label: 'enumeration', riskRange: [50, 85], count: 30, generator: {} },
  { label: 'rate_limit_evasion', riskRange: [45, 80], count: 20, generator: {} },
  { label: 'brute_force', riskRange: [75, 99], count: 20, generator: {} },
];

class MLWorker {
  constructor() {
    this.isTraining = false;
    this.modelLoaded = false;
    this.modelInfo = { trained: false };
    this.config = createDefaultConfig();
    this.trainingTimer = null;
    this.analysisTimer = null;
    this.init();
  }

  init() {
    this.ensureDirs();
    this.loadConfig();
    this.setupHandlers();
    this.startSchedulers();
    console.log('[MLWorker] Initialized');
  }

  ensureDirs() {
    if (!fs.existsSync(MODEL_DIR)) {
      fs.mkdirSync(MODEL_DIR, { recursive: true });
    }
  }

  loadConfig() {
    const configPath = path.join(CONFIG_DIR, 'user-config.json');
    try {
      if (fs.existsSync(configPath)) {
        this.config = mergeConfig(JSON.parse(fs.readFileSync(configPath, 'utf8')));
      } else {
        this.config = createDefaultConfig();
      }
    } catch (e) {
      this.config = createDefaultConfig();
    }
  }

  saveConfig() {
    const configPath = path.join(CONFIG_DIR, 'user-config.json');
    try {
      this.config = mergeConfig(this.config);
      fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
    } catch (e) {
      console.error('[MLWorker] Config save failed:', e.message);
    }
  }

  setupHandlers() {
    parentPort.on('message', async (msg) => {
      const { type, id, payload } = msg;
      let result;

      try {
        switch (type) {
          case 'ML_TRAIN':
            result = await this.train(payload.mode);
            break;

          case 'ML_ANALYZE':
            result = await this.runOllamaAnalysis(payload);
            break;

          case 'ML_QUERY_LOGS':
            result = await this.queryLogs(payload);
            break;

          case 'ML_GET_STATUS':
            result = this.getStatus();
            break;

          case 'ML_RULES_CHANGED':
            this.handleRulesChanged();
            result = { success: true };
            break;

          case 'ML_REFRESH_CONFIG':
            result = this.refreshConfig();
            break;

          case 'ML_BLOCK_IP':
            result = this.handleIpBlock(payload);
            break;

          case 'ML_UNBLOCK_IP':
            result = this.handleIpUnblock(payload);
            break;

          default:
            result = { success: false, error: `Unknown type: ${type}` };
        }
      } catch (err) {
        result = { success: false, error: err.message };
      }

      parentPort.postMessage({
        type: result.success ? 'RESPONSE_SUCCESS' : 'RESPONSE_ERROR',
        id,
        result
      });
    });
  }

  async train(mode = 'full') {
    if (this.isTraining) {
      return { success: false, error: 'Already training' };
    }

    this.isTraining = true;
    this.logAdmin({ event: 'training_started', mode });
    this.loadConfig();
    this.config.training.trainingStatus = 'training';
    this.saveConfig();

    try {
      const rules = this.config.importedRules || [];
      const trainingData = await this.generateTrainingData(rules);

      if (trainingData.features.length === 0) {
        throw new Error('No training data generated');
      }

      await this.runTensorFlowTraining(trainingData, mode);
      this.modelLoaded = true;
      this.modelInfo = {
        trained: true,
        trainedAt: new Date().toISOString(),
        samples: trainingData.features.length,
        mode
      };

      // Update config
      this.loadConfig();
      if (!this.config.training) this.config.training = {};
      this.config.training.trainingStatus = 'completed';
      this.config.training.lastTrainedAt = new Date().toISOString();
      this.config.training.rulesChangedSinceLastTrain = 0;
      this.updateNextTrainingSchedule();
      this.saveConfig();

      this.logAdmin({ 
        event: 'training_completed', 
        mode, 
        samples: trainingData.features.length 
      });

      return { 
        success: true, 
        mode,
        samples: trainingData.features.length,
        timestamp: new Date().toISOString()
      };
    } catch (e) {
      this.loadConfig();
      this.config.training.trainingStatus = 'failed';
      this.saveConfig();
      this.logAdmin({ event: 'training_failed', error: e.message });
      return { success: false, error: e.message };
    } finally {
      this.isTraining = false;
    }
  }

  loadTrainingPatterns() {
    const patternsPath = path.join(CONFIG_DIR, 'training-patterns.json');

    try {
      if (!fs.existsSync(patternsPath)) {
        return [];
      }

      const raw = JSON.parse(fs.readFileSync(patternsPath, 'utf8'));
      if (Array.isArray(raw)) {
        return raw.length > 0 ? raw : FALLBACK_PATTERNS;
      }
      if (Array.isArray(raw.patterns)) {
        return raw.patterns.length > 0 ? raw.patterns : FALLBACK_PATTERNS;
      }
      if (raw.patterns && typeof raw.patterns === 'object') {
        const patterns = Object.values(raw.patterns).filter((entry) => entry && typeof entry === 'object');
        return patterns.length > 0 ? patterns : FALLBACK_PATTERNS;
      }

      const patterns = Object.values(raw).filter((entry) =>
        entry && typeof entry === 'object' && (entry.label || entry.generator || entry.riskRange)
      );
      return patterns.length > 0 ? patterns : FALLBACK_PATTERNS;
    } catch (e) {
      console.log('[MLWorker] Failed to load training patterns:', e.message);
      return FALLBACK_PATTERNS;
    }

    return FALLBACK_PATTERNS;
  }

  async generateTrainingData(rules) {
    const features = [];
    const riskScores = [];
    const attackLabels = [];

    // Generate from patterns file
    const patterns = this.loadTrainingPatterns();
    patterns.forEach((p) => {
      // Generate synthetic samples from each pattern category
      const count = p.count || 1;
      const gen = p.generator || {};
      for (let i = 0; i < Math.min(count, 20); i++) {
        const featureVector = this.patternToFeatures({
          interval_mean: this.randRange(gen.avgIntervalMs?.min || 500, gen.avgIntervalMs?.max || 5000),
          interval_std: this.randRange(gen.stdDevMs?.min || 50, gen.stdDevMs?.max || 2000),
          request_count: this.randRange(gen.requestCount?.min || 5, gen.requestCount?.max || 50),
          endpoint_diversity: gen.endpoints ? 1 / gen.endpoints.length : 0.5,
          auth_present: gen.authPattern?.includes('consistent_bearer') || false,
          risk_score: this.randRange(p.riskRange?.[0] || 0, p.riskRange?.[1] || 50),
          header_anomaly: gen.missingHeaders?.length > 3 ? 0.8 : 0.1,
          body_anomaly: gen.bodyShapes?.length === 1 ? 0.6 : 0.2,
          rate_burst: (gen.avgIntervalMs?.min || 500) < 100 ? 0.9 : 0.1,
          ip_variance: (gen.ipCount?.max || 1) > 2 ? 0.8 : 0.2,
        });
        features.push(featureVector);
        riskScores.push(this.randRange(p.riskRange?.[0] || 0, p.riskRange?.[1] || 50));
        attackLabels.push(this.labelToOneHot(p.label || 'normal'));
      }
    });

    // Generate from rules
    if (Array.isArray(rules)) {
      rules.forEach(rule => {
        const featureVector = this.ruleToFeatures(rule);
        features.push(featureVector);
        riskScores.push(rule.action === 'block' ? 85 : 30);
        attackLabels.push(this.labelToOneHot('enumeration'));
      });
    }

    // Query Hindsight for blocked IPs (local file)
    const blockedIPs = this.getBlockedIPs();
    blockedIPs.forEach(ipEntry => {
      const featureVector = this.ipToFeatures(ipEntry);
      features.push(featureVector);
      riskScores.push(ipEntry.score || 80);
      attackLabels.push(this.labelToOneHot('credential_stuffing'));
    });

    // Query Hindsight logs for blocked actor data (enrichment)
    const hindsightData = await this.queryHindsightForTraining();
    hindsightData.forEach(entry => {
      const featureVector = this.ipToFeatures({
        score: entry.score || 75,
      });
      features.push(featureVector);
      riskScores.push(entry.score || 75);
      attackLabels.push(this.labelToOneHot(entry.attackType || 'credential_stuffing'));
    });

    return { features, riskScores, attackLabels };
  }

  randRange(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  patternToFeatures(pattern) {
    return [
      (pattern.interval_mean || 500) / 10000,
      (pattern.interval_std || 200) / 10000,
      pattern.request_count / 100,
      pattern.endpoint_diversity || 0.5,
      pattern.auth_present ? 1 : 0,
      pattern.risk_score / 100,
      pattern.header_anomaly || 0,
      pattern.body_anomaly || 0,
      pattern.rate_burst || 0,
      pattern.ip_variance || 0,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
    ];
  }

  ruleToFeatures(rule) {
    return [
      0.5,
      0.3,
      0.1,
      rule.action === 'block' ? 0.9 : 0.2,
      0.5,
      rule.action === 'block' ? 0.85 : 0.3,
      0.2,
      0.1,
      0.8,
      0.3,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
    ];
  }

  ipToFeatures(ipEntry) {
    return [
      0.1,
      0.05,
      1,
      0.9,
      0.6,
      (ipEntry.score || 80) / 100,
      0.8,
      0.5,
      1,
      0.8,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
      Math.random() * 0.1,
    ];
  }

  labelToOneHot(label) {
    const labels = ['normal', 'credential_stuffing', 'data_scraping', 'enumeration', 'rate_limit_evasion', 'brute_force'];
    const idx = labels.indexOf(label);
    const oneHot = new Array(6).fill(0);
    if (idx >= 0) oneHot[idx] = 1;
    else oneHot[0] = 1;
    return oneHot;
  }

  async runTensorFlowTraining(trainingData, mode) {
    // Save training data
    const dataPath = path.join(MODEL_DIR, 'training-data.json');
    fs.writeFileSync(dataPath, JSON.stringify({
      features: trainingData.features,
      riskScores: trainingData.riskScores,
      attackLabels: trainingData.attackLabels,
    }));

    // Log admin event
    this.logAdmin({
      event: 'training_data_generated',
      samples: trainingData.features.length,
      mode
    });

    // For now, just mark as done - actual TensorFlow training happens in main process
    return { success: true };
  }

  getBlockedIPs() {
    const blockedPath = path.join(CONFIG_DIR, 'blocked-ips.json');
    try {
      if (fs.existsSync(blockedPath)) {
        const data = JSON.parse(fs.readFileSync(blockedPath, 'utf8'));
        return Object.values(data).filter(ip => ip.manualBlock !== true);
      }
    } catch (e) {}
    return [];
  }

  async queryHindsightForTraining() {
    // Query admin audit logs for blocked actor entries to enrich training data
    try {
      const logsDir = path.join(CONFIG_DIR, 'logs');
      if (!fs.existsSync(logsDir)) return [];

      const files = fs.readdirSync(logsDir)
        .filter(f => f.startsWith('admin-audit-') && f.endsWith('.log'))
        .sort((a, b) => b.localeCompare(a))
        .slice(0, 7); // Last 7 days

      const entries = [];
      for (const file of files) {
        const content = fs.readFileSync(path.join(logsDir, file), 'utf8');
        const lines = content.split('\n').filter(l => l.trim());

        for (const line of lines) {
          try {
            // Parse log line: [timestamp] {json}
            const jsonStart = line.indexOf('{');
            if (jsonStart < 0) continue;
            const event = JSON.parse(line.substring(jsonStart));

            if (event.event === 'ip_blocked' && event.score) {
              entries.push({
                ip: event.ip,
                score: event.score,
                reason: event.reason,
                attackType: this.reasonToAttackType(event.reason),
              });
            }
          } catch (e) { /* skip malformed lines */ }
        }
      }

      console.log(`[MLWorker] Enriched training with ${entries.length} Hindsight entries`);
      return entries;
    } catch (e) {
      console.log('[MLWorker] Hindsight query failed:', e.message);
      return [];
    }
  }

  reasonToAttackType(reason) {
    if (!reason) return 'normal';
    const r = reason.toLowerCase();
    if (r.includes('credential') || r.includes('brute') || r.includes('login')) return 'credential_stuffing';
    if (r.includes('scrap') || r.includes('data')) return 'data_scraping';
    if (r.includes('enum')) return 'enumeration';
    if (r.includes('rate') || r.includes('evas')) return 'rate_limit_evasion';
    if (r.includes('brute')) return 'brute_force';
    return 'credential_stuffing'; // default for blocked IPs
  }

  // ─── Training & Analysis Schedulers ───────────────────────────
  startSchedulers() {
    this.loadConfig();

    // Training scheduler
    const trainingConfig = this.config.training || {};
    this.updateNextTrainingSchedule();
    if (trainingConfig.enabled) {
      const intervalMs = (trainingConfig.intervalHours || 1) * 60 * 60 * 1000;
      console.log(`[MLWorker] Training scheduler: every ${trainingConfig.intervalHours || 1}h`);

      this.trainingTimer = setInterval(async () => {
        console.log('[MLWorker] Scheduled training tick');
        const mode = this.shouldForceFullRetrain(trainingConfig) ? 'full' : 'incremental';
        await this.train(mode);
        this.updateNextTrainingSchedule();
      }, intervalMs);
    }

    // Ollama analysis scheduler
    const ollamaConfig = this.config.ollama || {};
    if (ollamaConfig.autoAnalyze) {
      const analysisMs = (ollamaConfig.analyzeIntervalMinutes || 30) * 60 * 1000;
      console.log(`[MLWorker] Analysis scheduler: every ${ollamaConfig.analyzeIntervalMinutes || 30}min`);

      this.analysisTimer = setInterval(async () => {
        console.log('[MLWorker] Scheduled Ollama analysis tick');
        await this.runOllamaAnalysis({});
      }, analysisMs);
    }
  }

  updateNextTrainingSchedule() {
    const trainingConfig = this.config.training || {};
    if (!trainingConfig.enabled) {
      this.config.training.nextScheduledAt = null;
      this.saveConfig();
      return;
    }

    const intervalMs = (trainingConfig.intervalHours || 1) * 60 * 60 * 1000;
    this.config.training.nextScheduledAt = new Date(Date.now() + intervalMs).toISOString();
    this.saveConfig();
  }

  refreshConfig() {
    this.stopSchedulers();
    this.loadConfig();
    this.startSchedulers();
    return {
      success: true,
      training: this.config.training,
      ollama: this.config.ollama,
    };
  }

  shouldForceFullRetrain(trainingConfig) {
    const forceEveryHours = trainingConfig.forceFullRetrainEvery || 24;
    const lastTrained = this.config.training?.lastTrainedAt;
    if (!lastTrained) return true;

    const hoursSince = (Date.now() - new Date(lastTrained).getTime()) / (1000 * 60 * 60);
    return hoursSince >= forceEveryHours;
  }

  stopSchedulers() {
    if (this.trainingTimer) {
      clearInterval(this.trainingTimer);
      this.trainingTimer = null;
    }
    if (this.analysisTimer) {
      clearInterval(this.analysisTimer);
      this.analysisTimer = null;
    }
  }

  async runOllamaAnalysis(payload) {
    const ollamaEndpoint = this.config.ollamaEndpoint || 'http://localhost:11434';
    const ollamaModel = this.config.ollamaModel || 'llama3.2';

    try {
      // Check Ollama availability
      const checkRes = await fetch(ollamaEndpoint + '/api/tags');
      if (!checkRes.ok) {
        return { success: false, error: 'Ollama not available' };
      }
    } catch (e) {
      return { success: false, error: 'Cannot connect to Ollama' };
    }

    this.logAdmin({ event: 'analysis_started' });
    this.loadConfig();
    this.config.ollama.analysisStatus = 'analyzing';
    this.saveConfig();

    try {
      const rulesContext = (this.config.importedRules || []).map(r => 
        `- ${r.pattern} (${r.action}): ${r.description || ''}`
      ).join('\n');

      const prompt = `You are a firewall security analyst. Given these firewall rules:
${rulesContext || 'No rules configured'}

Analyze the traffic and suggest any NEW firewall rules needed. 
Return ONLY valid JSON array of rules with format: 
[{"pattern": "IP/endpoint/pattern", "action": "block|allow", "description": "reason"}]
If no new rules needed, return empty array [].`;

      const response = await fetch(ollamaEndpoint + '/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: ollamaModel,
          prompt: prompt,
          stream: false,
          format: 'json',
        }),
      });

      if (!response.ok) {
        throw new Error('Ollama request failed');
      }

      const result = await response.json();
      let suggestions = [];

      try {
        suggestions = JSON.parse(result.response);
        if (!Array.isArray(suggestions)) suggestions = [];
      } catch {
        suggestions = [];
      }

      // Save suggestions
      const suggestionsPath = path.join(CONFIG_DIR, 'ollama-suggestions.json');
      fs.writeFileSync(suggestionsPath, JSON.stringify(suggestions, null, 2));

      // Update config
      this.loadConfig();
      if (!this.config.ollama) this.config.ollama = {};
      this.config.ollama.analysisStatus = 'completed';
      this.config.ollama.lastAnalyzedAt = new Date().toISOString();
      this.saveConfig();

      this.logAdmin({
        event: 'analysis_completed',
        suggestionsCount: suggestions.length
      });

      return { success: true, suggestions };
    } catch (e) {
      this.loadConfig();
      this.config.ollama.analysisStatus = 'failed';
      this.saveConfig();
      this.logAdmin({ event: 'analysis_failed', error: e.message });
      return { success: false, error: e.message };
    }
  }

  async queryLogs({ query, lines = 100 }) {
    try {
      const maxLines = lines;
      const logsDir = path.join(CONFIG_DIR, 'logs');
      if (!fs.existsSync(logsDir)) {
        return { success: true, results: [] };
      }

      const files = fs.readdirSync(logsDir)
        .filter(f => f.startsWith('suta-') && f.endsWith('.log'))
        .sort((a, b) => b.localeCompare(a));

      const results = [];
      for (const file of files.slice(0, 5)) {
        const content = fs.readFileSync(path.join(logsDir, file), 'utf8');
        const fileLines = content.split('\n');
        
        fileLines.forEach(line => {
          if (query && line.toLowerCase().includes(query.toLowerCase())) {
            results.push({ file, line: line.trim() });
          }
        });

        if (results.length >= maxLines) break;
      }

      this.logAdmin({ event: 'logs_queried', query, resultsCount: results.length });

      return { success: true, results: results.slice(0, maxLines) };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  handleRulesChanged() {
    this.loadConfig();
    if (!this.config.training) this.config.training = {};
    this.config.training.rulesChangedSinceLastTrain = 
      (this.config.training.rulesChangedSinceLastTrain || 0) + 1;
    this.saveConfig();

    this.logAdmin({
      event: 'rules_changed',
      totalChanges: this.config.training.rulesChangedSinceLastTrain
    });

    // Check if threshold reached
    const threshold = this.config.training.rulesThreshold || 5;
    if (
      this.config.training.enableRulesTrigger !== false &&
      this.config.training.rulesChangedSinceLastTrain >= threshold
    ) {
      const mode = this.config.training.useIncremental === false ? 'full' : 'incremental';
      this.train(mode);
    }
  }

  handleIpBlock(payload) {
    const { ip, actorId, reason, score } = payload;
    
    // Update rules with IP mapping
    this.loadConfig();
    if (!this.config.rules) this.config.rules = [];
    
    // Check if rule exists for this IP pattern
    let rule = this.config.rules.find(r => r.pattern === ip);
    
    if (rule) {
      // Add IP to rule
      if (!rule.associatedIPs) rule.associatedIPs = [];
      if (!rule.associatedIPs.includes(ip)) {
        rule.associatedIPs.push(ip);
      }
      // Add score to weight
      rule.weight = (rule.weight || 0) + (score || 50);
      rule.updatedAt = new Date().toISOString();
    } else {
      // Create new auto-generated rule
      this.config.rules.push({
        id: 'rule-' + Date.now(),
        pattern: ip,
        action: 'block',
        description: `Auto-generated from blocked IP: ${reason}`,
        source: 'auto-generated',
        associatedIPs: [ip],
        weight: score || 50,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }

    this.saveConfig();

    this.logAdmin({
      event: 'ip_blocked',
      ip,
      actorId,
      reason,
      score,
      rulePattern: ip
    });

    return { success: true };
  }

  handleIpUnblock(payload) {
    const { ip } = payload;
    
    this.loadConfig();
    
    // Find rules associated with this IP
    if (this.config.rules) {
      this.config.rules = this.config.rules.map(rule => {
        if (rule.associatedIPs && rule.associatedIPs.includes(ip)) {
          // Remove IP from associatedIPs
          rule.associatedIPs = rule.associatedIPs.filter(i => i !== ip);
          
          // Subtract score from weight - find the blocked IP entry
          const blockedPath = path.join(CONFIG_DIR, 'blocked-ips.json');
          if (fs.existsSync(blockedPath)) {
            const blockedData = JSON.parse(fs.readFileSync(blockedPath, 'utf8'));
            const blockedEntry = blockedData[ip];
            if (blockedEntry) {
              rule.weight = Math.max(0, (rule.weight || 0) - (blockedEntry.score || 50));
            }
          }
          
          rule.updatedAt = new Date().toISOString();
        }
        return rule;
      }).filter(rule => {
        // Delete rule if weight is 0 or no associated IPs
        const keep = rule.weight > 0 && (rule.associatedIPs?.length > 0);
        if (!keep) {
          this.logAdmin({ event: 'rule_deleted', ruleId: rule.id, reason: 'weight_zero' });
        }
        return keep;
      });

      this.saveConfig();
    }

    this.logAdmin({ event: 'ip_unblocked', ip });

    return { success: true };
  }

  getStatus() {
    return {
      isTraining: this.isTraining,
      modelLoaded: this.modelLoaded,
      modelInfo: this.modelInfo,
    };
  }

  logAdmin(event) {
    const timestamp = new Date().toISOString();
    const logsDir = path.join(CONFIG_DIR, 'logs');
    
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    const date = new Date().toISOString().split('T')[0];
    const adminLogPath = path.join(logsDir, `admin-audit-${date}.log`);
    
    const logLine = `[${timestamp}] ${JSON.stringify(event)}\n`;
    fs.appendFileSync(adminLogPath, logLine);

    // Also send to parent for real-time updates
    parentPort.postMessage({
      type: 'ADMIN_LOG',
      payload: {
        time: timestamp,
        ...event,
      }
    });
  }
}

new MLWorker();
