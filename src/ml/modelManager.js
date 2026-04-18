// src/ml/modelManager.js
// Handles TensorFlow.js model persistence, loading, and hot-swapping
import * as tf from '@tensorflow/tfjs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const configDir = join(__dirname, '../..', 'config');
const modelDir = join(configDir, 'model');

if (!fs.existsSync(modelDir)) {
  fs.mkdirSync(modelDir, { recursive: true });
}

class ModelManager {
  constructor() {
    this.currentModel = null;
    this.isTraining = false;
    this.modelInfo = {
      params: 0,
      layers: 0,
      trained: false,
      trainedAt: null,
      lastAccuracy: null,
    };
  }

  async initialize() {
    await this.loadModel();
  }

  async loadModel() {
    const modelPath = join(modelDir, 'model.json');
    const infoPath = join(modelDir, 'info.json');
    
    try {
      if (fs.existsSync(modelPath)) {
        this.currentModel = await tf.loadLayersModel(`file://${modelPath}`);
        this.currentModel.compile({
          optimizer: tf.train.adam(0.001),
          loss: ['meanSquaredError', 'categoricalCrossentropy'],
          lossWeights: [1.0, 0.5],
        });
        
        if (fs.existsSync(infoPath)) {
          const info = JSON.parse(fs.readFileSync(infoPath, 'utf8'));
          this.modelInfo = { ...this.modelInfo, ...info };
        }
        
        console.log('[ModelManager] Loaded model from disk');
        console.log('[ModelManager] Params:', this.currentModel.countParams());
        return true;
      }
    } catch (e) {
      console.log('[ModelManager] No existing model, will create new one');
    }
    return false;
  }

  async saveModel(model, info = {}) {
    try {
      await model.save(`file://${modelDir}`);
      
      const modelInfo = {
        params: model.countParams(),
        layers: model.layers.length,
        trained: true,
        trainedAt: new Date().toISOString(),
        ...info,
      };
      
      fs.writeFileSync(join(modelDir, 'info.json'), JSON.stringify(modelInfo, null, 2));
      console.log('[ModelManager] Model saved');
      return true;
    } catch (e) {
      console.error('[ModelManager] Save failed:', e.message);
      return false;
    }
  }

  async buildNewModel() {
    const input = tf.input({ shape: [20] });
    
    let x = tf.layers.dense({ units: 64, activation: 'relu', name: 'feature_embedding' }).apply(input);
    x = tf.layers.dense({ units: 32, activation: 'relu', name: 'ffn_1' }).apply(x);
    x = tf.layers.dropout({ rate: 0.2 }).apply(x);
    x = tf.layers.dense({ units: 32, activation: 'relu', name: 'ffn_2' }).apply(x);
    
    const riskScore = tf.layers.dense({ units: 1, activation: 'sigmoid', name: 'risk_score' }).apply(x);
    const attackType = tf.layers.dense({ units: 6, activation: 'softmax', name: 'attack_type' }).apply(x);
    
    const model = tf.model({
      inputs: input,
      outputs: [riskScore, attackType],
      name: 'AnomalyDetector',
    });
    
    model.compile({
      optimizer: tf.train.adam(0.001),
      loss: ['meanSquaredError', 'categoricalCrossentropy'],
      lossWeights: [1.0, 0.5],
    });
    
    return model;
  }

  async trainIncremental(trainingData, epochs = 10) {
    if (!this.currentModel) {
      throw new Error('No model to retrain');
    }
    
    const { features, riskScores, attackLabels } = trainingData;
    
    const xs = tf.tensor2d(features);
    const ysRisk = tf.tensor2d(riskScores.map(s => [s / 100]), [riskScores.length, 1]);
    const ysAttack = tf.tensor2d(attackLabels);
    
    this.currentModel.compile({
      optimizer: tf.train.adam(0.0001),
      loss: ['meanSquaredError', 'categoricalCrossentropy'],
      lossWeights: [1.0, 0.5],
    });
    
    const history = await this.currentModel.fit(xs, [ysRisk, ysAttack], {
      epochs,
      batchSize: Math.min(32, features.length),
      validationSplit: 0.2,
      shuffle: true,
      verbose: 0,
    });
    
    xs.dispose();
    ysRisk.dispose();
    ysAttack.dispose();
    
    return history;
  }

  async trainFull(trainingData, epochs = 50) {
    const model = await this.buildNewModel();
    
    const { features, riskScores, attackLabels } = trainingData;
    
    const xs = tf.tensor2d(features);
    const ysRisk = tf.tensor2d(riskScores.map(s => [s / 100]), [riskScores.length, 1]);
    const ysAttack = tf.tensor2d(attackLabels);
    
    const history = await model.fit(xs, [ysRisk, ysAttack], {
      epochs,
      batchSize: Math.min(32, features.length),
      validationSplit: 0.2,
      shuffle: true,
      verbose: 0,
      callbacks: {
        onEpochEnd: (epoch, logs) => {
          if ((epoch + 1) % 10 === 0) {
            console.log(`   Epoch ${epoch + 1}/${epochs} — loss: ${(logs.loss || 0).toFixed(4)}`);
          }
        },
      },
    });
    
    xs.dispose();
    ysRisk.dispose();
    ysAttack.dispose();
    
    return { model, history };
  }

  async hotSwap(newModel, info = {}) {
    const oldModel = this.currentModel;
    
    this.currentModel = newModel;
    this.modelInfo = {
      ...this.modelInfo,
      params: newModel.countParams(),
      layers: newModel.layers.length,
      trained: true,
      trainedAt: new Date().toISOString(),
      ...info,
    };
    
    if (oldModel) {
      try {
        oldModel.dispose();
      } catch (e) {}
    }
    
    console.log('[ModelManager] Hot-swap completed');
  }

  async predict(featureVector) {
    if (!this.currentModel || !this.modelInfo.trained) {
      return {
        ml_risk_score: 50,
        attack_type: 'unknown',
        attack_probabilities: {},
        confidence: 0,
        model_ready: false,
      };
    }
    
    const inputTensor = tf.tensor2d([Array.from(featureVector)]);
    const [riskTensor, attackTensor] = this.currentModel.predict(inputTensor);
    
    const riskScore = (await riskTensor.data())[0] * 100;
    const attackProbs = await attackTensor.data();
    
    const ATTACK_TYPES = ['normal', 'credential_stuffing', 'data_scraping', 'enumeration', 'rate_limit_evasion', 'brute_force'];
    
    let maxIdx = 0;
    let maxProb = 0;
    for (let i = 0; i < attackProbs.length; i++) {
      if (attackProbs[i] > maxProb) {
        maxProb = attackProbs[i];
        maxIdx = i;
      }
    }
    
    const probabilities = {};
    for (let i = 0; i < ATTACK_TYPES.length; i++) {
      probabilities[ATTACK_TYPES[i]] = Math.round(attackProbs[i] * 1000) / 10;
    }
    
    inputTensor.dispose();
    riskTensor.dispose();
    attackTensor.dispose();
    
    return {
      ml_risk_score: Math.round(riskScore * 10) / 10,
      attack_type: ATTACK_TYPES[maxIdx],
      attack_probabilities: probabilities,
      confidence: Math.round(maxProb * 100),
      model_ready: true,
    };
  }

  getModelInfo() {
    return { ...this.modelInfo };
  }

  isReady() {
    return this.currentModel !== null && this.modelInfo.trained;
  }
}

const modelManager = new ModelManager();
export default modelManager;
export { ModelManager };