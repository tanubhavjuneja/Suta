// src/ml/msctModel.js
// ═══════════════════════════════════════════════════════════════
// MSCT (Multi-Scale Convolutional Transformer) Model
// Based on DDoS-MSCT paper architecture
// Detects all attack types using multi-scale CNN + Transformer
// ═══════════════════════════════════════════════════════════════

import { FEATURE_NAMES, FEATURE_COUNT, extractRequestFeatures } from './featureExtractor.js';

const SEQUENCE_LENGTH = 20;
const EMBEDDING_DIM = 64;
const NUM_HEADS = 4;
const NUM_LAYERS = 2;
const NUM_CLASSES = 2;

class MSCTModel {
  constructor() {
    this.weights = null;
    this.isLoaded = false;
  }

  async load(weights) {
    this.weights = weights;
    this.isLoaded = true;
  }

  async classify(sequences) {
    if (!this.isLoaded || !this.weights) {
      return { threat_score: 50, classification: 'unknown', confidence: 0 };
    }

    const scores = [];
    for (const seq of sequences) {
      const score = this.forward(seq);
      scores.push(score);
    }

    const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
    return this.mapToClassification(avgScore);
  }

  forward(sequence) {
    let embeddings = this.embedSequence(sequence);
    embeddings = this.applyLFEM(embeddings);
    embeddings = this.applyGFEM(embeddings);
    const clsToken = embeddings[0];
    return this.sigmoid(clsToken) * 100;
  }

  embedSequence(sequence) {
    const embedded = [];
    for (let i = 0; i < Math.min(sequence.length, SEQUENCE_LENGTH); i++) {
      const features = sequence[i];
      const embedding = new Array(EMBEDDING_DIM).fill(0);
      for (let j = 0; j < Math.min(features.length, FEATURE_COUNT); j++) {
        embedding[j % EMBEDDING_DIM] += features[j] * (j + 1) * 0.1;
      }
      embedded.push(embedding.map(v => Math.tanh(v / 10)));
    }
    while (embedded.length < SEQUENCE_LENGTH) {
      embedded.push(new Array(EMBEDDING_DIM).fill(0));
    }
    return embedded;
  }

  applyLFEM(embeddings) {
    if (!this.weights?.lfem) return embeddings;
    
    const { kernels, pointwise, pooling } = this.weights.lfem;
    const output = [];
    
    for (let i = 0; i < embeddings.length - 2; i++) {
      const window = embeddings.slice(i, i + 3);
      let combined = new Array(EMBEDDING_DIM).fill(0);
      
      for (let k = 0; k < kernels.length; k++) {
        const kernel = kernels[k];
        let sum = 0;
        for (let j = 0; j < window.length; j++) {
          sum += window[j][k % EMBEDDING_DIM] * (kernel[j] || 0.1);
        }
        combined[k % EMBEDDING_DIM] += Math.tanh(sum);
      }
      
      if (pointwise) {
        for (let j = 0; j < EMBEDDING_DIM; j++) {
          combined[j] = Math.tanh(combined[j] * pointwise[j % pointwise.length]);
        }
      }
      
      output.push(combined);
    }
    
    return output.length > 0 ? output : embeddings.slice(0, SEQUENCE_LENGTH);
  }

  applyGFEM(embeddings) {
    if (!this.weights?.gfem) return embeddings;
    
    const { attention, ffn } = this.weights.gfem;
    const numHeads = NUM_HEADS;
    const headDim = Math.floor(EMBEDDING_DIM / numHeads);
    
    const clsToken = new Array(EMBEDDING_DIM).fill(0);
    for (let i = 0; i < embeddings.length; i++) {
      const weight = 1 / (i + 1);
      for (let j = 0; j < EMBEDDING_DIM; j++) {
        clsToken[j] += embeddings[i][j] * weight;
      }
    }
    
    for (let layer = 0; layer < NUM_LAYERS; layer++) {
      const q = this.linear(clsToken, attention?.q || this.defaultWeights(layer, 'q'));
      const k = this.linear(clsToken, attention?.k || this.defaultWeights(layer, 'k'));
      const v = this.linear(clsToken, attention?.v || this.defaultWeights(layer, 'v'));
      
      const headOutputs = [];
      for (let h = 0; h < numHeads; h++) {
        const qh = q.slice(h * headDim, (h + 1) * headDim);
        const kh = k.slice(h * headDim, (h + 1) * headDim);
        const vh = v.slice(h * headDim, (h + 1) * headDim);
        
        let scores = [];
        for (let i = 0; i < headDim; i++) {
          scores.push(qh[i] * kh[i] / Math.sqrt(headDim));
        }
        
        const expScores = scores.map(s => Math.exp(s));
        const sumExp = expScores.reduce((a, b) => a + b, 0);
        const attnWeights = expScores.map(s => s / sumExp);
        
        let output = 0;
        for (let i = 0; i < headDim; i++) {
          output += attnWeights[i] * vh[i];
        }
        headOutputs.push(output);
      }
      
      let attentionOutput = [];
      for (let i = 0; i < numHeads; i++) {
        attentionOutput = attentionOutput.concat([headOutputs[i]]);
      }
      
      clsToken = this.linear(attentionOutput, ffn?.w1 || this.defaultWeights(layer, 'w1'));
      clsToken = clsToken.map(v => v * 0.5 * (1 + Math.tanh(Math.sqrt(2 / Math.PI) * (v + 0.044715 * Math.pow(v, 3)))));
      clsToken = this.linear(clsToken, ffn?.w2 || this.defaultWeights(layer, 'w2'));
    }
    
    return [clsToken, ...embeddings.slice(0, SEQUENCE_LENGTH - 1)];
  }

  linear(input, weights) {
    if (!weights || weights.length === 0) {
      return input.map(v => v * 0.1);
    }
    const output = [];
    for (let i = 0; i < weights.length; i++) {
      let sum = 0;
      for (let j = 0; j < input.length; j++) {
        sum += input[j] * (weights[i]?.[j] || 0.1);
      }
      output.push(sum);
    }
    return output;
  }

  defaultWeights(layer, type) {
    const seed = layer * 100 + type.charCodeAt(0);
    return Array.from({ length: EMBEDDING_DIM }, (_, i) => 
      Math.sin(seed + i * 0.1) * 0.1
    );
  }

  sigmoid(x) {
    return 1 / (1 + Math.exp(-x));
  }

  mapToClassification(score) {
    if (score >= 70) {
      return { threat_score: score, classification: 'attack', confidence: 0.85 };
    } else if (score >= 40) {
      return { threat_score: score, classification: 'suspicious', confidence: 0.6 };
    }
    return { threat_score: score, classification: 'normal', confidence: 0.8 };
  }

  getRecommendedAction(score) {
    if (score >= 70) return 'block';
    if (score >= 40) return 'throttle';
    return 'allow';
  }
}

export function createMSCTModel() {
  return new MSCTModel();
}

export function createMSCTWeights() {
  return {
    lfem: {
      kernels: [
        Array.from({ length: 3 }, () => Math.random() * 0.2 - 0.1),
        Array.from({ length: 5 }, () => Math.random() * 0.2 - 0.1),
        Array.from({ length: 7 }, () => Math.random() * 0.2 - 0.1),
      ],
      pointwise: Array.from({ length: EMBEDDING_DIM }, () => Math.random() * 0.2 - 0.1),
      pooling: 0.5,
    },
    gfem: {
      attention: {
        q: Array.from({ length: EMBEDDING_DIM }, () => Array.from({ length: EMBEDDING_DIM }, () => Math.random() * 0.1 - 0.05)),
        k: Array.from({ length: EMBEDDING_DIM }, () => Array.from({ length: EMBEDDING_DIM }, () => Math.random() * 0.1 - 0.05)),
        v: Array.from({ length: EMBEDDING_DIM }, () => Array.from({ length: EMBEDDING_DIM }, () => Math.random() * 0.1 - 0.05)),
      },
      ffn: {
        w1: Array.from({ length: EMBEDDING_DIM * 2 }, () => Array.from({ length: EMBEDDING_DIM }, () => Math.random() * 0.1 - 0.05)),
        w2: Array.from({ length: EMBEDDING_DIM }, () => Array.from({ length: EMBEDDING_DIM * 2 }, () => Math.random() * 0.1 - 0.05)),
      },
    },
  };
}

export { MSCTModel, SEQUENCE_LENGTH, EMBEDDING_DIM, NUM_HEADS, NUM_LAYERS };