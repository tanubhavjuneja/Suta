// src/engine/emailPipeline.js
// ═══════════════════════════════════════════════════════════════
// EMAIL DETECTION PIPELINE
//
// Unified pipeline for email server protection: SMTP, webmail, submission.
// ═══════════════════════════════════════════════════════════════
import userReputation from '../enforcement/userReputation.js';
import emailBlocklist from '../enforcement/emailBlocklist.js';
import { generateUserFingerprint, extractClientIP } from '../ingestion/emailFingerprintGenerator.js';
import { config } from '../runtimeConfig.js';
import eventLog from './eventLog.js';

const emailConfig = config.email || {};
const MAX_EMAILS_PER_HOUR = emailConfig.maxEmailsPerHour || 500;
const MAX_RECIPIENTS_PER_EMAIL = emailConfig.maxRecipientsPerEmail || 100;
const MAX_BCC_PER_EMAIL = emailConfig.maxBCCPerEmail || 20;
const SUSPICIOUS_NEW_IP_EMAILS_PER_HOUR = emailConfig.suspiciousNewIPEmailsPerHour || 50;
const NEW_IP_MULTIPLIER = emailConfig.newIPMultiplier || 2;

export function assessEmailRequest(userId, ip, emailData) {
  const isNewIP = userReputation.isNewIP(userId, ip);
  const isAdminTrustedIP = userReputation.isIPTrustedByAdmin(ip);
  const isAdminTrustedUser = userReputation.isUserTrustedByAdmin(userId);
  const maliciousRate = userReputation.getMaliciousRate(userId);
  
  let riskScore = 0;
  let reasons = [];
  let action = 'allow';

  if (isAdminTrustedIP || isAdminTrustedUser) {
    reasons.push('admin_trusted');
    riskScore -= 30;
  }

  const emailsPerHour = userReputation.getEmailsPerHour(userId);
  const maxBCC = userReputation.getRecentBCCMax(userId);
  const recipientsPerEmail = userReputation.getRecipientsPerEmail(userId);

  if (emailsPerHour > MAX_EMAILS_PER_HOUR) {
    reasons.push('high_volume');
    riskScore += 40;
  } else if (emailsPerHour > MAX_EMAILS_PER_HOUR * 0.5) {
    reasons.push('elevated_volume');
    riskScore += 20;
  }

  if (isNewIP && emailsPerHour > SUSPICIOUS_NEW_IP_EMAILS_PER_HOUR) {
    reasons.push('new_ip_high_volume');
    riskScore += 25;
  }

  if (maxBCC > MAX_BCC_PER_EMAIL) {
    reasons.push('mass_bcc');
    riskScore += 30;
  } else if (maxBCC > MAX_BCC_PER_EMAIL * 0.5) {
    reasons.push('elevated_bcc');
    riskScore += 15;
  }

  if (recipientsPerEmail > MAX_RECIPIENTS_PER_EMAIL) {
    reasons.push('mass_recipients');
    riskScore += 25;
  }

  riskScore += maliciousRate * NEW_IP_MULTIPLIER;

  riskScore = Math.max(0, Math.min(100, riskScore));

  if (riskScore >= config.enforcement.blockScore) {
    action = 'block';
  } else if (riskScore >= config.enforcement.throttleScore) {
    action = 'throttle';
  } else if (riskScore >= config.enforcement.monitorScore || isNewIP) {
    action = 'monitor';
  }

  return {
    userId,
    ip,
    isNewIP,
    isAdminTrustedIP,
    isAdminTrustedUser,
    riskScore,
    reasons,
    action,
    emailsPerHour,
    recipientsPerEmail,
    maxBCC,
    maliciousRate,
  };
}

export function processEmailSubmission(req, res, next) {
  try {
    const userId = req.headers['x-authenticated-user'] || req.headers['from'];
    const ip = extractClientIP(req);
    
    if (!userId) {
      eventLog.error('email_pipeline', 'No userId in request');
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (emailBlocklist.isUserBlocked(userId)) {
      const entry = emailBlocklist.getUserEntry(userId);
      eventLog.enforcement(userId, 'block', entry?.score || 100, 'blocked_user');
      return res.status(403).json({
        error: 'BLOCKED',
        reason: 'User is temporarily blocked',
        user: userId,
        expires: entry?.expiresAt,
      });
    }

    if (emailBlocklist.isIPBlocked(ip)) {
      const entry = emailBlocklist.getIPEntry(ip);
      eventLog.enforcement(userId, 'block', entry?.score || 100, 'blocked_ip');
      return res.status(403).json({
        error: 'BLOCKED',
        reason: 'IP is temporarily blocked',
        ip: ip,
        expires: entry?.expiresAt,
      });
    }

    const emailData = {
      recipients: req.headers['to']?.split(',').map(e => e.trim()) || [],
      cc: req.headers['cc']?.split(',').map(e => e.trim()) || [],
      bcc: req.headers['bcc']?.split(',').map(e => e.trim()) || [],
      subject: req.headers['subject'] || '',
      hasAttachments: req.headers['content-type']?.includes('multipart'),
    };

    const reputationScore = userReputation.computeReputationScore(userId, ip);
    userReputation.recordEmail(userId, ip, emailData);

    const assessment = assessEmailRequest(userId, ip, emailData);

    eventLog.email(assessment);

    if (assessment.action === 'block') {
      emailBlocklist.blockUser(userId, assessment.reasons.join(', '), assessment.riskScore);
      eventLog.enforcement(userId, 'block', assessment.riskScore, 'email_pipeline');
      return res.status(403).json({
        error: 'BLOCKED',
        reason: assessment.reasons.join(', '),
        riskScore: assessment.riskScore,
      });
    }

    if (assessment.action === 'throttle') {
      eventLog.enforcement(userId, 'throttle', assessment.riskScore, 'email_pipeline');
    }

    if (assessment.action === 'monitor' || assessment.isNewIP) {
      emailBlocklist.addMonitoring(userId, {
        ip,
        emailCount: assessment.emailsPerHour,
        recipientCount: assessment.recipientsPerEmail,
        riskScore: assessment.riskScore,
      });
    }

    req.emailAssessment = assessment;
    req.userId = userId;
    next();
  } catch (e) {
    eventLog.error('email_pipeline', e.message);
    next();
  }
}