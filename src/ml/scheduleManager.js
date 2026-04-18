// src/ml/scheduleManager.js
// Manages training triggers and schedule
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const configDir = join(__dirname, '../../config');
const userConfigPath = join(configDir, 'user-config.json');

function loadConfig() {
  try {
    if (fs.existsSync(userConfigPath)) {
      return JSON.parse(fs.readFileSync(userConfigPath, 'utf8'));
    }
  } catch (e) {}
  return {};
}

function saveConfig(cfg) {
  try {
    fs.writeFileSync(userConfigPath, JSON.stringify(cfg, null, 2));
  } catch (e) {}
}

class ScheduleManager {
  constructor() {
    this.timer = null;
    this.analysisTimer = null;
    this.ruleChanges = 0;
    this.lastRuleHash = '';
    this.onTrainingTrigger = null;
    this.onAnalysisTrigger = null;
    this.isRunning = false;
    this.config = null;
  }

  initialize(onTrainingTrigger, onAnalysisTrigger) {
    this.onTrainingTrigger = onTrainingTrigger;
    this.onAnalysisTrigger = onAnalysisTrigger;
    this.config = loadConfig();
    
    const training = this.config.training || {};
    
    if (training.enabled) {
      this.start();
    }
  }

  start() {
    if (this.isRunning || !this.config) return;
    this.isRunning = true;
    
    const intervalMs = (this.config.training?.intervalHours || 1) * 60 * 60 * 1000;
    
    console.log('[Schedule] Starting, interval:', this.config.training?.intervalHours || 1, 'hours');
    
    this.timer = setInterval(() => {
      this.checkTrainingTrigger();
    }, intervalMs);
    
    if (this.config.ollama?.autoAnalyze) {
      const analysisIntervalMs = (this.config.ollama.analyzeIntervalMinutes || 30) * 60 * 1000;
      this.analysisTimer = setInterval(() => {
        if (this.onAnalysisTrigger) {
          this.onAnalysisTrigger();
        }
      }, analysisIntervalMs);
    }
    
    this.updateNextScheduled();
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.analysisTimer) {
      clearInterval(this.analysisTimer);
      this.analysisTimer = null;
    }
    this.isRunning = false;
    console.log('[Schedule] Stopped');
  }

  updateConfig(newConfig) {
    this.config = loadConfig();
    
    const wasRunning = this.isRunning;
    
    if (wasRunning) {
      this.stop();
    }
    
    if (newConfig.training?.enabled) {
      this.config.training = { ...this.config.training, ...newConfig.training };
      saveConfig(this.config);
      this.start();
    }
    
    this.updateNextScheduled();
  }

  updateNextScheduled() {
    if (!this.config) return;
    const intervalMs = (this.config.training?.intervalHours || 1) * 60 * 60 * 1000;
    const nextScheduled = new Date(Date.now() + intervalMs).toISOString();
    if (!this.config.training) this.config.training = {};
    this.config.training.nextScheduledAt = nextScheduled;
    saveConfig(this.config);
  }

  checkTrainingTrigger() {
    const cfg = this.config.training || {};
    if (!cfg.enabled) return;
    
    let shouldTrain = false;
    let reason = '';
    
    const timeTriggered = true;
    if (timeTriggered && cfg.useIncremental) {
      shouldTrain = true;
      reason = 'scheduled_incremental';
    } else if (timeTriggered) {
      shouldTrain = true;
      reason = 'scheduled_full';
    }
    
    const currentHash = this.lastRuleHash;
    if (cfg.enableRulesTrigger && this.ruleChanges >= (cfg.rulesThreshold || 5)) {
      shouldTrain = true;
      reason = 'rules_changed';
      this.ruleChanges = 0;
    }
    
    if (shouldTrain && this.onTrainingTrigger) {
      const mode = reason.includes('incremental') ? 'incremental' : 'full';
      console.log('[Schedule] Triggering:', reason);
      this.onTrainingTrigger(mode);
      this.updateNextScheduled();
    }
  }

  recordRuleChange() {
    this.ruleChanges++;
    
    const cfg = this.config.training || {};
    if (cfg.enabled && cfg.enableRulesTrigger && this.ruleChanges >= (cfg.rulesThreshold || 5)) {
      if (this.onTrainingTrigger) {
        console.log('[Schedule] Rules threshold reached');
        this.onTrainingTrigger('incremental');
        this.ruleChanges = 0;
      }
    }
    
    if (!this.config.training) this.config.training = {};
    this.config.training.rulesChangedSinceLastTrain = this.ruleChanges;
    saveConfig(this.config);
  }

  getStatus() {
    const cfg = this.config?.training || {};
    const modelCachePath = join(configDir, 'model', 'info.json');
    let modelInfo = {};
    try {
      if (fs.existsSync(modelCachePath)) {
        modelInfo = JSON.parse(fs.readFileSync(modelCachePath, 'utf8'));
      }
    } catch {}
    
    return {
      running: this.isRunning,
      enabled: cfg.enabled || false,
      intervalHours: cfg.intervalHours || 1,
      nextScheduledAt: cfg.nextScheduledAt || null,
      lastTrainedAt: modelInfo.trainedAt || null,
      rulesChangedSinceLastTrain: this.ruleChanges,
      rulesThreshold: cfg.rulesThreshold || 5,
      enableRulesTrigger: cfg.enableRulesTrigger || false,
      forceFullRetrainEvery: cfg.forceFullRetrainEvery || 24,
    };
  }

  runAnalysisNow() {
    if (this.onAnalysisTrigger) {
      this.onAnalysisTrigger();
    }
  }
}

const scheduleManager = new ScheduleManager();
export default scheduleManager;
export { ScheduleManager };