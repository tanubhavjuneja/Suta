// src/ml/trainingManager.js
// Main coordinator for ML training operations
import modelManager from './modelManager.js';
import { generateTrainingData } from './dataGenerator.js';
import scheduleManager from './scheduleManager.js';
import memoryLayer from '../memory/memoryLayer.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const configDir = join(__dirname, '../../config');

function loadConfig() {
  try {
    const configPath = join(configDir, 'user-config.json');
    if (fs.existsSync(configPath)) {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
  } catch (e) {}
  return {};
}

function saveConfig(cfg) {
  try {
    const configPath = join(configDir, 'user-config.json');
    fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2));
  } catch (e) {}
}

class TrainingManager {
  constructor() {
    this.isTraining = false;
    this.lastTrainingResult = null;
  }

  async initialize() {
    console.log('[Training] Initializing...');
    
    await modelManager.initialize();
    
    scheduleManager.initialize(
      (mode) => this.onTrainingTrigger(mode),
      () => this.onAnalysisTrigger()
    );
    
    const status = this.getStatus();
    console.log('[Training] Ready. Model loaded:', status.modelLoaded);
    
    return status;
  }

  async onTrainingTrigger(mode = 'incremental') {
    if (this.isTraining) {
      console.log('[Training] Already training, skipping trigger');
      return;
    }
    
    console.log('[Training] Triggered:', mode);
    await this.train(mode);
  }

  async onAnalysisTrigger() {
    const cfg = loadConfig();
    if (!cfg.ollama?.autoAnalyze) return;
    
    console.log('[Analysis] Running periodic analysis...');
    await this.runOllamaAnalysis();
  }

  async train(mode = 'full') {
    if (this.isTraining) {
      return { success: false, error: 'Already training' };
    }
    
    this.isTraining = true;
    
    const config = loadConfig();
    if (!config.training) config.training = {};
    config.training.trainingStatus = 'training';
    saveConfig(config);
    
    console.log('[Training] Starting', mode, 'training...');
    
    try {
      const rules = config.importedRules || [];
      const trainingData = await generateTrainingData(rules);
      
      if (trainingData.features.length === 0) {
        throw new Error('No training data generated');
      }
      
      let result;
      
      if (mode === 'incremental' && modelManager.isReady()) {
        console.log('[Training] Incremental training...');
        await modelManager.trainIncremental(trainingData, 10);
        result = { mode: 'incremental', epochs: 10 };
      } else {
        console.log('[Training] Full training...');
        const trainResult = await modelManager.trainFull(trainingData, 50);
        await modelManager.hotSwap(trainResult.model, { trainingMode: mode });
        result = { mode: 'full', epochs: 50 };
      }
      
      await modelManager.saveModel(modelManager.currentModel, {
        trainingMode: mode,
        trainingDataSize: trainingData.features.length,
      });
      
      this.lastTrainingResult = {
        success: true,
        mode: result.mode,
        samples: trainingData.features.length,
        timestamp: new Date().toISOString(),
      };
      
      const updatedConfig = loadConfig();
      updatedConfig.training = updatedConfig.training || {};
      updatedConfig.training.trainingStatus = 'completed';
      updatedConfig.training.lastTrainedAt = new Date().toISOString();
      updatedConfig.training.rulesChangedSinceLastTrain = 0;
      saveConfig(updatedConfig);
      
      console.log('[Training] Completed:', result.mode, '-', trainingData.features.length, 'samples');
      
      return { success: true, ...result };
      
    } catch (e) {
      console.error('[Training] Failed:', e.message);
      
      this.lastTrainingResult = {
        success: false,
        error: e.message,
        timestamp: new Date().toISOString(),
      };
      
      const failedConfig = loadConfig();
      failedConfig.training = failedConfig.training || {};
      failedConfig.training.trainingStatus = 'failed';
      saveConfig(failedConfig);
      
      return { success: false, error: e.message };
    } finally {
      this.isTraining = false;
    }
  }

  async predict(featureVector) {
    return modelManager.predict(featureVector);
  }

  async runOllamaAnalysis() {
    const config = loadConfig();
    const ollamaEndpoint = config.ollamaEndpoint;
    const ollamaModel = config.ollamaModel;
    
    if (!ollamaEndpoint) {
      return { success: false, error: 'Ollama not configured' };
    }
    
    try {
      const response = await fetch(ollamaEndpoint + '/api/tags');
      if (!response.ok) {
        return { success: false, error: 'Ollama not available' };
      }
    } catch (e) {
      return { success: false, error: 'Cannot connect to Ollama' };
    }
    
    const updatedConfig = loadConfig();
    if (!updatedConfig.ollama) updatedConfig.ollama = {};
    updatedConfig.ollama.analysisStatus = 'analyzing';
    saveConfig(updatedConfig);
    
    try {
      const rulesContext = (config.importedRules || []).map(r => 
        '- ' + r.pattern + ' (' + r.action + '): ' + (r.description || '')
      ).join('\n');
      
      let memoryContext = '';
      try {
        const queryResult = await memoryLayer.query('List recent blocked actors and their attack patterns');
        memoryContext = queryResult?.text || 'No memory data';
      } catch (e) {
        memoryContext = 'Memory query failed';
      }
      
      const modelInfo = modelManager.getModelInfo();
      const trafficSummary = {
        modelLoaded: modelInfo.trained,
        lastTrained: modelInfo.trainedAt,
      };
      
      const prompt = `You are a firewall security analyst. Analyze this system:

EXISTING RULES:
${rulesContext || 'No rules configured'}

ATTACK MEMORIES (from Hindsight):
${memoryContext}

MODEL STATUS:
${JSON.stringify(trafficSummary, null, 2)}

Based on this analysis, suggest any NEW firewall rules needed. 
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
      
      const suggestionsPath = join(configDir, 'ollama-suggestions.json');
      fs.writeFileSync(suggestionsPath, JSON.stringify(suggestions, null, 2));
      
      const finalConfig = loadConfig();
      finalConfig.ollama = finalConfig.ollama || {};
      finalConfig.ollama.analysisStatus = 'completed';
      finalConfig.ollama.lastAnalyzedAt = new Date().toISOString();
      saveConfig(finalConfig);
      
      console.log('[Analysis] Found', suggestions.length, 'suggestions');
      
      return { success: true, suggestions };
      
    } catch (e) {
      console.error('[Analysis] Failed:', e.message);
      
      const failedConfig = loadConfig();
      failedConfig.ollama = failedConfig.ollama || {};
      failedConfig.ollama.analysisStatus = 'failed';
      saveConfig(failedConfig);
      
      return { success: false, error: e.message };
    }
  }

  getModelInfo() {
    return modelManager.getModelInfo();
  }

  getScheduleStatus() {
    return scheduleManager.getStatus();
  }

  getStatus() {
    const config = loadConfig();
    const modelInfo = modelManager.getModelInfo();
    const scheduleStatus = scheduleManager.getStatus();
    
    return {
      isTraining: this.isTraining,
      modelLoaded: modelManager.isReady(),
      modelInfo: modelInfo,
      schedule: scheduleStatus,
      lastResult: this.lastTrainingResult,
      config: config,
    };
  }

  updateSchedule(newConfig) {
    scheduleManager.updateConfig(newConfig);
    return scheduleManager.getStatus();
  }

  recordRuleChange() {
    scheduleManager.recordRuleChange();
  }
}

const trainingManager = new TrainingManager();
export default trainingManager;
export { TrainingManager };