// src/workers/mlWorker.js
// ML Worker - handles model training, Ollama analysis, log queries
// ═══════════════════════════════════════════════════════════════
import { parentPort } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_DIR = path.join(__dirname, '../../config');
const MODEL_DIR = path.join(CONFIG_DIR, 'model');

class MLWorker {
  constructor() {
    this.isTraining = false;
    this.modelLoaded = false;
    this.modelInfo = { trained: false };
    this.init();
  }

  init() {
    this.ensureDirs();
    this.loadConfig();
    this.setupHandlers();
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
        this.config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      }
    } catch (e) {
      this.config = {};
    }
  }

  saveConfig() {
    const configPath = path.join(CONFIG_DIR, 'user-config.json');
    try {
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

    try {
      this.loadConfig();
      const rules = this.config.importedRules || [];
      const trainingData = await this.generateTrainingData(rules);

      if (trainingData.features.length === 0) {
        throw new Error('No training data generated');
      }

      const modelResult = await this.runTensorFlowTraining(trainingData, mode);
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
      this.logAdmin({ event: 'training_failed', error: e.message });
      return { success: false, error: e.message };
    } finally {
      this.isTraining = false;
    }
  }

  async generateTrainingData(rules) {
    const features = [];
    const riskScores = [];
    const attackLabels = [];

    // Generate from patterns
    const patternsPath = path.join(CONFIG_DIR, 'training-patterns.json');
    let patterns = [];
    if (fs.existsSync(patternsPath)) {
      patterns = JSON.parse(fs.readFileSync(patternsPath, 'utf8'));
    }

    patterns.forEach(p => {
      const featureVector = this.patternToFeatures(p);
      features.push(featureVector);
      riskScores.push(p.risk_score || 50);
      attackLabels.push(this.labelToOneHot(p.attack_type || 'normal'));
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

    // Query Hindsight for blocked IPs
    const blockedIPs = this.getBlockedIPs();
    blockedIPs.forEach(ipEntry => {
      const featureVector = this.ipToFeatures(ipEntry);
      features.push(featureVector);
      riskScores.push(ipEntry.score || 80);
      attackLabels.push(this.labelToOneHot('credential_stuffing'));
    });

    return { features, riskScores, attackLabels };
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
      this.logAdmin({ event: 'analysis_failed', error: e.message });
      return { success: false, error: e.message };
    }
  }

  async queryLogs({ query, lines = 100 }) {
    try {
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
        const lines = content.split('\n');
        
        lines.forEach(line => {
          if (query && line.toLowerCase().includes(query.toLowerCase())) {
            results.push({ file, line: line.trim() });
          }
        });

        if (results.length >= lines) break;
      }

      this.logAdmin({ event: 'logs_queried', query, resultsCount: results.length });

      return { success: true, results: results.slice(0, lines) };
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
    if (this.config.training.rulesChangedSinceLastTrain >= threshold) {
      this.train('incremental');
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
      payload: event
    });
  }
}

new MLWorker();