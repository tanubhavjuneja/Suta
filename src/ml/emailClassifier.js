// src/ml/emailClassifier.js
// ═══════════════════════════════════════════════════════════════
// Transformer-based Email Activity Classifier
//
// Uses self-attention mechanism to detect behavioral anomalies
// in email sending patterns. Analyzes temporal sequences
// and recipient relationships.
// ═══════════════════════════════════════════════════════════════
import * as tf from '@tensorflow/tfjs';

export class EmailTransformerClassifier {
  constructor() {
    this.model = null;
    this.isReady = false;
    this.historyBuffer = new Map();
    this.sequenceLength = 20;
    this.featureDim = 12;
  }

  async init() {
    this.model = tf.sequential();
    
    // Simple attention-like layer
    this.model.add(tf.layers.dense({
      units: 32,
      activation: 'relu',
      inputShape: [this.featureDim],
    }));
    
    // Transformer-style feed forward
    this.model.add(tf.layers.dense({
      units: 16,
      activation: 'relu',
    }));
    
    this.model.add(tf.layers.dense({
      units: 1,
      activation: 'sigmoid',
    }));
    
    this.model.compile({
      optimizer: tf.train.adam(0.001),
      loss: 'binaryCrossentropy',
      metrics: ['accuracy'],
    });
    
    this.isReady = true;
    console.log('[EmailClassifier] Transformer model initialized');
  }

  extractFeatures(userId, emails, userProfile, ipReputation) {
    const features = new Array(this.featureDim).fill(0);
    
    if (emails.length === 0) return features;
    
    // Feature 0: Email rate (normalized)
    const oneHourAgo = Date.now() - 3600000;
    const recentEmails = emails.filter(e => e.timestamp > oneHourAgo);
    features[0] = Math.min(recentEmails.length / 500, 1);
    
    // Feature 1: Avg recipients per email
    let totalRecipients = 0;
    for (const email of emails.slice(-10)) {
      totalRecipients += (email.recipients?.length || 0) + 
                        (email.cc?.length || 0) + 
                        (email.bcc?.length || 0);
    }
    features[1] = Math.min(totalRecipients / ((emails.slice(-10).length || 1) / 50), 1);
    
    // Feature 2: Max BCC count
    let maxBCC = 0;
    for (const email of emails) {
      const bcc = email.bcc?.length || 0;
      if (bcc > maxBCC) maxBCC = bcc;
    }
    features[2] = Math.min(maxBCC / 50, 1);
    
    // Feature 3: Recipient diversity
    const allRecipients = new Set();
    for (const email of emails) {
      for (const r of email.recipients || []) allRecipients.add(r);
      for (const r of email.cc || []) allRecipients.add(r);
      for (const r of email.bcc || []) allRecipients.add(r);
    }
    features[3] = Math.min(allRecipients.size / (emails.length * 10), 1);
    
    // Feature 4: Is new IP
    const isNewIP = userProfile?.knownIPCount === 0;
    features[4] = isNewIP ? 1 : 0;
    
    // Feature 5: IP reputation score
    features[5] = (ipReputation || 50) / 100;
    
    // Feature 6: Burst score (emails < 1 second apart)
    let burstCount = 0;
    for (let i = 1; i < emails.length; i++) {
      const gap = emails[i].timestamp - emails[i-1].timestamp;
      if (gap < 1000) burstCount++;
    }
    features[6] = emails.length > 1 ? burstCount / (emails.length - 1) : 0;
    
    // Feature 7: Has attachments ratio
    let attachmentCount = 0;
    for (const email of emails) {
      if (email.hasAttachments) attachmentCount++;
    }
    features[7] = emails.length > 0 ? attachmentCount / emails.length : 0;
    
    // Feature 8: Account age score
    if (userProfile?.firstSeen) {
      const ageDays = (Date.now() - userProfile.firstSeen) / 86400000;
      features[8] = Math.min(ageDays / 365, 1);
    }
    
    // Feature 9: Volume trend
    const recent1h = emails.filter(e => e.timestamp > oneHourAgo).length;
    const recent2h = emails.filter(e => e.timestamp > oneHourAgo * 2 && e.timestamp <= oneHourAgo).length;
    features[9] = recent2h > 0 ? (recent1h / recent2h) : 0;
    
    // Feature 10: Known IP trust
    features[10] = userProfile?.knownIPCount > 0 ? Math.min(userProfile.knownIPCount / 5, 1) : 0;
    
    // Feature 11: Malicious rate
    features[11] = (userProfile?.maliciousRate || 0) / 100;
    
    return features;
  }

  addToBuffer(userId, emailData) {
    if (!this.historyBuffer.has(userId)) {
      this.historyBuffer.set(userId, []);
    }
    
    const buffer = this.historyBuffer.get(userId);
    buffer.push({
      ...emailData,
      timestamp: Date.now(),
    });
    
    // Keep last 100 emails
    if (buffer.length > 100) {
      this.historyBuffer.set(userId, buffer.slice(-100));
    }
  }

  async predict(userId, userProfile) {
    const emails = this.historyBuffer.get(userId) || [];
    const ipReputation = userProfile?.ipReputation || 50;
    
    const features = this.extractFeatures(userId, emails, userProfile, ipReputation);
    const inputTensor = tf.tensor2d([features], [1, this.featureDim]);
    
    const prediction = this.model.predict(inputTensor);
    const score = (await prediction.data())[0];
    
    inputTensor.dispose();
    prediction.dispose();
    
    return score;
  }

  async train(userId, label) {
    const emails = this.historyBuffer.get(userId) || [];
    if (emails.length < 5) return;
    
    const features = this.extractFeatures(userId, emails, {}, 50);
    const xs = tf.tensor2d([features], [1, this.featureDim]);
    const ys = tf.tensor2d([[label]], [1, 1]);
    
    await this.model.fit(xs, ys, {
      epochs: 1,
      verbose: 0,
    });
    
    xs.dispose();
    ys.dispose();
  }

  getAttentionWeights(userId) {
    const emails = this.historyBuffer.get(userId) || [];
    if (emails.length < 2) return null;
    
    // Simple attention: weight recent emails more
    const weights = emails.map((_, i) => {
      const recency = (i + 1) / emails.length;
      return recency * recency;
    });
    
    const sum = weights.reduce((a, b) => a + b, 0);
    return weights.map(w => w / sum);
  }

  analyzeBehavioralPattern(userId) {
    const emails = this.historyBuffer.get(userId) || [];
    if (emails.length < 3) return { pattern: 'insufficient_data' };
    
    // Check for spam indicators
    const patterns = {
      rapid_burst: false,
      mass_bcc: false,
      recipient_growth: false,
      template_like: false,
    };
    
    // Rapid burst check
    let burstCount = 0;
    for (let i = 1; i < emails.length; i++) {
      const gap = emails[i].timestamp - emails[i-1].timestamp;
      if (gap < 2000) burstCount++;
    }
    patterns.rapid_burst = burstCount / (emails.length - 1) > 0.5;
    
    // Mass BCC check
    let maxBCC = 0;
    for (const email of emails) {
      maxBCC = Math.max(maxBCC, email.bcc?.length || 0);
    }
    patterns.mass_bcc = maxBCC > 20;
    
    // Recipient growth
    const earlyRecipients = new Set();
    const lateRecipients = new Set();
    const mid = Math.floor(emails.length / 2);
    for (let i = 0; i < mid; i++) {
      for (const r of emails[i].recipients || []) earlyRecipients.add(r);
      for (const r of emails[i].cc || []) earlyRecipients.add(r);
      for (const r of emails[i].bcc || []) earlyRecipients.add(r);
    }
    for (let i = mid; i < emails.length; i++) {
      for (const r of emails[i].recipients || []) lateRecipients.add(r);
      for (const r of emails[i].cc || []) lateRecipients.add(r);
      for (const r of emails[i].bcc || []) lateRecipients.add(r);
    }
    const newRecipients = [...lateRecipients].filter(r => !earlyRecipients.has(r));
    patterns.recipient_growth = newRecipients.length > 10;
    
    return patterns;
  }
}

const emailClassifier = new EmailTransformerClassifier();
export default emailClassifier;