// src/workers/dashboardWorker.js
// Dashboard Worker - handles settings, IP management, event feed
// ═══════════════════════════════════════════════════════════════
import { parentPort } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createDefaultConfig, mergeConfig } from '../configDefaults.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_DIR = path.join(__dirname, '../../config');

class DashboardWorker {
  constructor() {
    this.events = [];
    this.maxEvents = 1000;
    this.requestId = 0;
    this.pendingWorkerRequests = new Map();
    this.init();
  }

  init() {
    this.loadConfig();
    this.setupHandlers();
    console.log('[DashboardWorker] Initialized');
  }

  loadConfig() {
    const configPath = path.join(CONFIG_DIR, 'user-config.json');
    try {
      if (fs.existsSync(configPath)) {
        this.config = mergeConfig(JSON.parse(fs.readFileSync(configPath, 'utf8')));
      } else {
        this.config = this.getDefaultConfig();
        fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
        console.log('[DashboardWorker] Created default config file');
      }
    } catch (e) {
      this.config = this.getDefaultConfig();
    }
  }

  getDefaultConfig() {
    return createDefaultConfig();
  }

  saveConfig() {
    const configPath = path.join(CONFIG_DIR, 'user-config.json');
    this.config = mergeConfig(this.config);
    fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
  }

  setupHandlers() {
    parentPort.on('message', async (msg) => {
      const { type, id, payload } = msg;
      let result;

      if (this.handleWorkerResponse(msg)) {
        return;
      }

      try {
        switch (type) {
          case 'DASHBOARD_GET_CONFIG':
            result = this.getConfig();
            break;

          case 'DASHBOARD_SAVE_CONFIG':
            result = await this.saveDashboardConfig(payload);
            break;

          case 'DASHBOARD_GET_RULES':
            result = this.getRules();
            break;

          case 'DASHBOARD_ADD_RULE':
            result = await this.addRule(payload);
            break;

          case 'DASHBOARD_DELETE_RULE':
            result = await this.deleteRule(payload);
            break;

          case 'DASHBOARD_GET_BLOCKED_IPS':
            result = await this.getBlockedIPs();
            break;

          case 'DASHBOARD_BLOCK_IP':
            result = await this.blockIP(payload);
            break;

          case 'DASHBOARD_UNBLOCK_IP':
            result = await this.unblockIP(payload);
            break;

          case 'DASHBOARD_GET_RULES_BY_IP':
            result = this.getRulesByIP(payload.ip);
            break;

          case 'DASHBOARD_SEND_EVENT':
            result = this.addEvent(payload);
            break;

          case 'DASHBOARD_GET_EVENTS':
            result = this.getEvents(payload);
            break;

          case 'DASHBOARD_GET_TRAINING_STATUS':
            result = this.getTrainingStatus();
            break;

          case 'DASHBOARD_TRIGGER_TRAINING':
            result = await this.triggerTraining(payload);
            break;

          case 'DASHBOARD_GET_SUGGESTIONS':
            result = this.getSuggestions();
            break;

          case 'DASHBOARD_APPROVE_SUGGESTION':
            result = await this.approveSuggestion(payload);
            break;

          case 'DASHBOARD_REJECT_SUGGESTION':
            result = this.rejectSuggestion(payload);
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

  handleWorkerResponse(msg) {
    const { type, id, result } = msg;
    if (!id || !this.pendingWorkerRequests.has(id)) {
      return false;
    }

    const { resolve, reject, timeout } = this.pendingWorkerRequests.get(id);
    clearTimeout(timeout);
    this.pendingWorkerRequests.delete(id);

    if (type === 'RESPONSE_ERROR') {
      reject(new Error(result?.error || 'Worker request failed'));
    } else {
      resolve(result);
    }

    return true;
  }

  requestWorker(type, payload = {}) {
    return new Promise((resolve, reject) => {
      const id = `dashboard-${++this.requestId}`;
      const timeout = setTimeout(() => {
        this.pendingWorkerRequests.delete(id);
        reject(new Error(`Timeout waiting for ${type}`));
      }, 30000);

      this.pendingWorkerRequests.set(id, { resolve, reject, timeout });
      parentPort.postMessage({ type, id, payload });
    });
  }

  getConfig() {
    this.loadConfig();
    return {
      success: true,
      config: mergeConfig(this.config)
    };
  }

  async saveDashboardConfig(newConfig) {
    this.loadConfig();
    const rulesChanged = newConfig.rulesFilePath !== undefined || newConfig.importedRules !== undefined;
    const mlConfigChanged = rulesChanged
      || newConfig.training !== undefined
      || newConfig.ollama !== undefined
      || newConfig.ollamaEndpoint !== undefined
      || newConfig.ollamaModel !== undefined;

    if (newConfig.port !== undefined) this.config.port = newConfig.port;
    if (newConfig.hindsight) this.config.hindsight = { ...this.config.hindsight, ...newConfig.hindsight };
    if (newConfig.enforcement) this.config.enforcement = { ...this.config.enforcement, ...newConfig.enforcement };
    if (newConfig.rulesFilePath !== undefined) {
      this.config.rulesFilePath = newConfig.rulesFilePath;
      // Load rules from file if provided
      if (newConfig.rulesFilePath && fs.existsSync(newConfig.rulesFilePath)) {
        try {
          const content = fs.readFileSync(newConfig.rulesFilePath, 'utf8');
          const ext = newConfig.rulesFilePath.toLowerCase();
          if (ext.endsWith('.json')) {
            this.config.importedRules = JSON.parse(content);
          } else if (ext.endsWith('.csv') || ext.endsWith('.txt')) {
            const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
            this.config.importedRules = lines.map(line => {
              const parts = line.split(/[,\t\s]+/);
              return {
                pattern: parts[0]?.trim(),
                action: parts[1]?.trim() || 'block',
                description: parts.slice(2).join(' ').trim() || 'Imported rule',
              };
            });
          }
        } catch (e) {
          console.error('[Dashboard] Failed to load rules:', e.message);
        }
      }
    }
    if (newConfig.importedRules) this.config.importedRules = newConfig.importedRules;
    if (newConfig.ollamaEndpoint) this.config.ollamaEndpoint = newConfig.ollamaEndpoint;
    if (newConfig.ollamaModel) this.config.ollamaModel = newConfig.ollamaModel;
    if (newConfig.training) this.config.training = { ...this.config.training, ...newConfig.training };
    if (newConfig.ollama) this.config.ollama = { ...this.config.ollama, ...newConfig.ollama };
    if (newConfig.logging) this.config.logging = { ...this.config.logging, ...newConfig.logging };

    this.saveConfig();

    if (mlConfigChanged) {
      await this.requestWorker('ML_REFRESH_CONFIG', {});
    }

    if (rulesChanged) {
      await this.requestWorker('ML_RULES_CHANGED', {});
    }

    // Notify logging worker about config change
    if (newConfig.logging) {
      await this.requestWorker('LOG_SET_CONFIG', newConfig.logging);
    }

    this.logAdmin({ event: 'settings_saved', changes: Object.keys(newConfig) });

    return { success: true };
  }

  getRules() {
    this.loadConfig();
    return {
      success: true,
      importedRules: this.config.importedRules || [],
      rulesFilePath: this.config.rulesFilePath || '',
      autoRules: this.config.rules || [],
    };
  }

  async addRule(rule) {
    this.loadConfig();
    if (!this.config.importedRules) this.config.importedRules = [];

    this.config.importedRules.push({
      pattern: rule.pattern,
      action: rule.action || 'block',
      description: rule.description || '',
      source: rule.source || 'manual',
    });

    this.saveConfig();

    await this.requestWorker('ML_RULES_CHANGED', {});

    this.logAdmin({ event: 'rule_added', pattern: rule.pattern });

    return { success: true, ruleCount: this.config.importedRules.length };
  }

  async deleteRule({ index }) {
    this.loadConfig();
    if (!this.config.importedRules || index < 0 || index >= this.config.importedRules.length) {
      return { success: false, error: 'Invalid index' };
    }

    const removed = this.config.importedRules.splice(index, 1)[0];
    this.saveConfig();

    await this.requestWorker('ML_RULES_CHANGED', {});

    this.logAdmin({ event: 'rule_deleted', pattern: removed.pattern });

    return { success: true, ruleCount: this.config.importedRules.length };
  }

  async getBlockedIPs() {
    return this.requestWorker('PIPELINE_GET_BLOCKED_IPS', {});
  }

  async blockIP({ ip, reason, manualBlock = true }) {
    return this.requestWorker('PIPELINE_BLOCK_IP', {
      ip,
      reason: reason || 'manual_block',
      score: 85,
      manualBlock,
    });
  }

  async unblockIP({ ip }) {
    return this.requestWorker('PIPELINE_UNBLOCK_IP', { ip });
  }

  getRulesByIP(ip) {
    this.loadConfig();
    const matchingRules = [];

    // Check imported rules
    if (this.config.importedRules) {
      this.config.importedRules.forEach((rule, idx) => {
        if (rule.pattern === ip || rule.pattern.includes(ip.split('.').slice(0, 2).join('.'))) {
          matchingRules.push({ ...rule, index: idx, source: 'imported' });
        }
      });
    }

    // Check auto-generated rules with associated IPs
    if (this.config.rules) {
      this.config.rules.forEach(rule => {
        if (rule.associatedIPs && rule.associatedIPs.includes(ip)) {
          matchingRules.push({ ...rule, source: 'auto-generated' });
        }
      });
    }

    return { success: true, rules: matchingRules };
  }

  addEvent(event) {
    this.events.push({
      ...event,
      timestamp: event.timestamp || new Date().toISOString(),
    });

    if (this.events.length > this.maxEvents) {
      this.events.shift();
    }

    // Forward to logging
    parentPort.postMessage({
      type: 'LOG_WRITE',
      payload: { level: 'info', message: `EVENT: ${event.type} - ${JSON.stringify(event)}` }
    });

    return { success: true };
  }

  getEvents({ count = 50, type = null }) {
    let filtered = this.events;
    if (type) {
      filtered = filtered.filter(e => e.type === type);
    }
    return { success: true, events: filtered.slice(-count) };
  }

  getTrainingStatus() {
    this.loadConfig();
    return {
      success: true,
      status: this.config.training
    };
  }

  async triggerTraining({ mode = 'full' }) {
    const result = await this.requestWorker('ML_TRAIN', { mode });
    this.logAdmin({ event: 'training_triggered', mode });
    return result;
  }

  getSuggestions() {
    const suggestionsPath = path.join(CONFIG_DIR, 'ollama-suggestions.json');
    try {
      if (fs.existsSync(suggestionsPath)) {
        const suggestions = JSON.parse(fs.readFileSync(suggestionsPath, 'utf8'));
        return { success: true, suggestions };
      }
    } catch (e) {}
    return { success: true, suggestions: [] };
  }

  async approveSuggestion({ index }) {
    const suggestionsPath = path.join(CONFIG_DIR, 'ollama-suggestions.json');
    try {
      if (fs.existsSync(suggestionsPath)) {
        const suggestions = JSON.parse(fs.readFileSync(suggestionsPath, 'utf8'));
        const suggestion = suggestions[index];
        
        if (suggestion) {
          this.loadConfig();
          if (!this.config.importedRules) this.config.importedRules = [];
          
          this.config.importedRules.push({
            pattern: suggestion.pattern,
            action: suggestion.action || 'block',
            description: suggestion.description || 'Ollama suggested rule',
            source: 'ollama',
          });
          
          this.saveConfig();
          
          suggestions.splice(index, 1);
          fs.writeFileSync(suggestionsPath, JSON.stringify(suggestions, null, 2));
          
          await this.requestWorker('ML_RULES_CHANGED', {});
          
          this.logAdmin({ event: 'ollama_suggestion_approved', pattern: suggestion.pattern });
          
          return { success: true };
        }
      }
    } catch (e) {}
    return { success: false, error: 'Suggestion not found' };
  }

  rejectSuggestion({ index }) {
    const suggestionsPath = path.join(CONFIG_DIR, 'ollama-suggestions.json');
    try {
      if (fs.existsSync(suggestionsPath)) {
        const suggestions = JSON.parse(fs.readFileSync(suggestionsPath, 'utf8'));
        suggestions.splice(index, 1);
        fs.writeFileSync(suggestionsPath, JSON.stringify(suggestions, null, 2));
        this.logAdmin({ event: 'ollama_suggestion_rejected', index });
      }
    } catch (e) {}
    return { success: true };
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
    this.events.push({
      type: 'admin_log',
      time: timestamp,
      ...event,
    });
    if (this.events.length > this.maxEvents) {
      this.events.shift();
    }

    parentPort.postMessage({
      type: 'ADMIN_LOG',
      payload: {
        time: timestamp,
        ...event,
      }
    });
  }
}

new DashboardWorker();
