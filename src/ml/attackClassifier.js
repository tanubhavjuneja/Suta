// src/ml/attackClassifier.js
// ═══════════════════════════════════════════════════════════════
// Attack Classifier using MSCT architecture
// Detects and classifies: DDoS, Brute Force, Web Scraping, SQL Injection, XSS, etc.
// ═══════════════════════════════════════════════════════════════

import { createMSCTModel, createMSCTWeights } from './msctModel.js';
import { extractRequestFeatures } from './featureExtractor.js';

const ATTACK_TYPES = {
  NORMAL: 'normal',
  DDoS: 'ddos',
  BRUTE_FORCE: 'brute_force',
  WEB_SCRAPING: 'web_scraping',
  CREDENTIAL_STUFFING: 'credential_stuffing',
  SQL_INJECTION: 'sql_injection',
  XSS: 'xss',
  PATH_TRAVERSAL: 'path_traversal',
  RATE_LIMIT_BYPASS: 'rate_limit_bypass',
  CRAWLER: 'crawler',
};

class AttackClassifier {
  constructor() {
    this.model = createMSCTModel();
    this.sequenceHistory = new Map();
    this.maxHistoryLength = 20;
    this.initializeWeights();
  }

  initializeWeights() {
    const weights = createMSCTWeights();
    this.model.load(weights);
  }

  getSequenceKey(ip, actorId) {
    return actorId || ip;
  }

  addToSequence(actorId, features) {
    const key = this.getSequenceKey(actorId, actorId);
    
    if (!this.sequenceHistory.has(key)) {
      this.sequenceHistory.set(key, []);
    }
    
    const history = this.sequenceHistory.get(key);
    history.push(features);
    
    if (history.length > this.maxHistoryLength) {
      history.shift();
    }
    
    return history;
  }

  clearHistory(actorId) {
    const key = this.getSequenceKey(actorId, actorId);
    this.sequenceHistory.delete(key);
  }

  async classifyRequest(reqData) {
    const { ip, actorId, method, path, headers, body } = reqData;
    
    const features = extractRequestFeatures(reqData, []);
    const sequence = this.addToSequence(actorId, features);
    
    const classification = await this.model.classify([sequence]);
    
    const attackType = this.detectAttackType(reqData, classification.threat_score);
    
    return {
      ...classification,
      attack_type: attackType,
      recommended_action: this.getRecommendedAction(classification.threat_score, attackType),
    };
  }

  detectAttackType(reqData, threatScore) {
    const { method, path, headers, body } = reqData;
    const pathLower = (path || '').toLowerCase();
    const bodyStr = (body || '').toString().toLowerCase();
    
    if (threatScore < 40) {
      return ATTACK_TYPES.NORMAL;
    }
    
    if (this.detectSQLInjection(pathLower, bodyStr)) {
      return ATTACK_TYPES.SQL_INJECTION;
    }
    
    if (this.detectXSS(pathLower, bodyStr)) {
      return ATTACK_TYPES.XSS;
    }
    
    if (this.detectPathTraversal(pathLower)) {
      return ATTACK_TYPES.PATH_TRAVERSAL;
    }
    
    if ((pathLower.includes('login') || pathLower.includes('auth')) && 
        (method === 'POST' || method === 'PUT')) {
      return ATTACK_TYPES.BRUTE_FORCE;
    }
    
    if (this.isCrawlerBehavior(reqData, threatScore)) {
      return ATTACK_TYPES.CRAWLER;
    }
    
    if (threatScore > 70) {
      return ATTACK_TYPES.DDoS;
    }
    
    if (threatScore > 50) {
      return ATTACK_TYPES.WEB_SCRAPING;
    }
    
    return ATTACK_TYPES.RATE_LIMIT_BYPASS;
  }

  detectSQLInjection(pathOrBody) {
    const sqlPatterns = [
      /union\s+select/i,
      /union\s+all\s+select/i,
      /'\s+or\s+'1'\s*=\s*'1/i,
      /'\s+or\s+1\s*=\s*1/i,
      /;\s*drop\s+table/i,
      /;\s*delete\s+from/i,
      /exec\s*\(/i,
      /xp_cmdshell/i,
      /information_schema/i,
      /concat\s*\(/i,
      /benchmark\s*\(/i,
      /sleep\s*\(/i,
    ];
    
    return sqlPatterns.some(pattern => pattern.test(pathOrBody));
  }

  detectXSS(pathOrBody) {
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /onclick\s*=/i,
      /<img\s+[^>]*onerror/i,
      /<svg\s+[^>]*onload/i,
      /alert\s*\(/i,
      /eval\s*\(/i,
    ];
    
    return xssPatterns.some(pattern => pattern.test(pathOrBody));
  }

  detectPathTraversal(path) {
    const traversalPatterns = [
      /\.\.\//i,
      /\.\.%2f/i,
      /%2e%2e%2f/i,
      /etc\/passwd/i,
      /windows\/system32/i,
    ];
    
    return traversalPatterns.some(pattern => pattern.test(path));
  }

  isCrawlerBehavior(reqData, threatScore) {
    const { headers } = reqData;
    const ua = (headers?.['user-agent'] || '').toLowerCase();
    
    const botUA = ['python', 'curl', 'wget', 'scrapy', 'bot', 'crawler', 'spider'];
    const hasBotUA = botUA.some(bot => ua.includes(bot));
    
    if (threatScore > 50 && hasBotUA) {
      return true;
    }
    
    return false;
  }

  getRecommendedAction(threatScore, attackType) {
    if (attackType === ATTACK_TYPES.SQL_INJECTION ||
        attackType === ATTACK_TYPES.XSS ||
        attackType === ATTACK_TYPES.PATH_TRAVERSAL) {
      return 'block';
    }
    
    if (threatScore >= 70) return 'block';
    if (threatScore >= 40) return 'throttle';
    return 'allow';
  }

  getAttackTypeLabel(attackType) {
    const labels = {
      [ATTACK_TYPES.NORMAL]: 'Normal Traffic',
      [ATTACK_TYPES.DDoS]: 'DDoS Attack',
      [ATTACK_TYPES.BRUTE_FORCE]: 'Brute Force',
      [ATTACK_TYPES.WEB_SCRAPING]: 'Web Scraping',
      [ATTACK_TYPES.CREDENTIAL_STUFFING]: 'Credential Stuffing',
      [ATTACK_TYPES.SQL_INJECTION]: 'SQL Injection',
      [ATTACK_TYPES.XSS]: 'Cross-Site Scripting (XSS)',
      [ATTACK_TYPES.PATH_TRAVERSAL]: 'Path Traversal',
      [ATTACK_TYPES.RATE_LIMIT_BYPASS]: 'Rate Limit Bypass',
      [ATTACK_TYPES.CRAWLER]: 'Malicious Crawler',
    };
    
    return labels[attackType] || 'Unknown';
  }
}

export function createAttackClassifier() {
  return new AttackClassifier();
}

export { ATTACK_TYPES };