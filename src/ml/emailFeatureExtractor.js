// src/ml/emailFeatureExtractor.js
// ═══════════════════════════════════════════════════════════════
// Email-specific feature extraction for the email firewall
//
// Converts email activity metrics into numerical feature vectors
// that the ML model can use to detect email-based attacks.
// ═══════════════════════════════════════════════════════════════

export const EMAIL_FEATURE_NAMES = [
  'emails_per_hour',        // 0: Email sending rate
  'avg_recipients',       // 1: Average recipients per email
  'max_recipients',       // 2: Maximum recipients in a single email
  'recipient_diversity',   // 3: Unique recipients / total emails
  'cc_ratio',           // 4: Ratio of emails with CC
  'bcc_ratio',          // 5: Ratio of emails with BCC
  'max_bcc',           // 6: Maximum BCC count
  'attachment_ratio',    // 7: Ratio of emails with attachments
  'domain_switching',   // 8: Number of different sender domains
  'is_new_ip',         // 9: 1 if current IP is new for user
  'ip_reputation',     // 10: User's reputation score (0-100)
  'auth_failure_rate', // 11: Recent auth failures
  'session_duration',   // 12: Time since first email
  'burst_score',     // 13: How bursty the sending is
  'reply_to_mismatch', // 14: Reply-To != From
  'subject_similarity', // 15: Similarity of subjects (spam bot indicator)
  'known_ip_count',    // 16: Number of known IPs for user
  'volume_trend',     // 17: Is volume increasing?
];

export const EMAIL_FEATURE_COUNT = EMAIL_FEATURE_NAMES.length;

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

export function extractEmailFeatures(emailActivity) {
  const features = new Float32Array(EMAIL_FEATURE_COUNT);

  const emails = emailActivity.recentEmails || [];
  const user = emailActivity.userProfile;

  // 0: Emails per hour
  const emailsPerHour = emails.length;
  features[0] = clamp(emailsPerHour / 1000, 0, 1);

  // 1-2: Recipient counts
  if (emails.length > 0) {
    let totalRecipients = 0;
    let maxRecipients = 0;
    for (const email of emails) {
      const count = (email.recipients?.length || 0) +
                    (email.cc?.length || 0) +
                    (email.bcc?.length || 0);
      totalRecipients += count;
      if (count > maxRecipients) maxRecipients = count;
    }
    features[1] = clamp(totalRecipients / emails.length / 50, 0, 1);
    features[2] = clamp(maxRecipients / 100, 0, 1);
  }

  // 3: Recipient diversity
  if (emails.length > 0) {
    const allRecipients = new Set();
    for (const email of emails) {
      for (const r of email.recipients || []) allRecipients.add(r);
      for (const r of email.cc || []) allRecipients.add(r);
      for (const r of email.bcc || []) allRecipients.add(r);
    }
    features[3] = clamp(allRecipients.size / emails.length / 10, 0, 1);
  }

  // 4-5: CC/BCC ratios
  let ccCount = 0;
  let bccCount = 0;
  for (const email of emails) {
    if ((email.cc?.length || 0) > 0) ccCount++;
    if ((email.bcc?.length || 0) > 0) bccCount++;
  }
  features[4] = emails.length > 0 ? ccCount / emails.length : 0;
  features[5] = emails.length > 0 ? bccCount / emails.length : 0;

  // 6: Max BCC
  let maxBCC = 0;
  for (const email of emails) {
    const bcc = email.bcc?.length || 0;
    if (bcc > maxBCC) maxBCC = bcc;
  }
  features[6] = clamp(maxBCC / 50, 0, 1);

  // 7: Attachment ratio
  let attachments = 0;
  for (const email of emails) {
    if (email.hasAttachments) attachments++;
  }
  features[7] = emails.length > 0 ? attachments / emails.length : 0;

  // 8: Domain switching (placeholder - would need email headers)
  features[8] = 0;

  // 9: Is new IP
  features[9] = emailActivity.isNewIP ? 1 : 0;

  // 10: IP reputation
  features[10] = (emailActivity.ipReputation || 50) / 100;

  // 11: Auth failure rate
  features[11] = clamp((emailActivity.authFailures || 0) / 20, 0, 1);

  // 12: Session duration
  if (emails.length > 0) {
    const firstEmail = emails[0]?.timestamp || Date.now();
    const duration = Date.now() - firstEmail;
    features[12] = clamp(duration / (60 * 60 * 1000), 0, 1);
  }

  // 13: Burst score
  if (emails.length > 1) {
    let burstCount = 0;
    for (let i = 1; i < emails.length; i++) {
      const gap = emails[i].timestamp - emails[i-1].timestamp;
      if (gap < 1000) burstCount++; // Under 1 second
    }
    features[13] = clamp(burstCount / emails.length, 0, 1);
  }

  // 14: Reply-To mismatch
  let mismatchCount = 0;
  for (const email of emails) {
    if (email.replyTo && email.from && email.replyTo !== email.from) {
      mismatchCount++;
    }
  }
  features[14] = emails.length > 0 ? mismatchCount / emails.length : 0;

  // 15: Subject similarity (placeholder - would need text analysis)
  features[15] = 0;

  // 16: Known IP count
  features[16] = user ? clamp(user.knownIPCount / 10, 0, 1) : 0;

  // 17: Volume trend (placeholder - would need historical data)
  features[17] = 0;

  return features;
}

export function extractSingleEmailFeatures(emailData, userProfile) {
  const activity = {
    recentEmails: [emailData],
    userProfile: userProfile || {},
    isNewIP: emailData.isNewIP || false,
    ipReputation: emailData.ipReputation || 50,
    authFailures: 0,
  };
  return extractEmailFeatures(activity);
}