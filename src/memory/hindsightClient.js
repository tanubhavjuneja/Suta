// src/memory/hindsightClient.js
// ═══════════════════════════════════════════════════════════════
// Pure HTTP wrapper around Hindsight Cloud API
// Uses the Cloud path format: /v1/default/banks/{bankId}/memories/*
// ═══════════════════════════════════════════════════════════════
import config from '../config.js';

class HindsightClient {
  constructor() {
    this.baseUrl = config.hindsight.baseUrl.replace(/\/+$/, '');
    this.bankId = config.hindsight.bankId;
    this.apiKey = config.hindsight.apiKey;
  }

  // ── Internal HTTP helper ──────────────────────────────────────
  async _request(method, path, body = null) {
    const url = `${this.baseUrl}${path}`;
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(url, opts);
    const text = await res.text();

    if (!res.ok) {
      throw new Error(`Hindsight ${method} ${path} failed (${res.status}): ${text}`);
    }

    return text ? JSON.parse(text) : null;
  }

  // Cloud API base path for this bank
  get _bankPath() {
    return `/v1/default/banks/${this.bankId}`;
  }

  // ════════════════════════════════════════════════════════════
  //  RETAIN — Store attack session as natural language report
  // ════════════════════════════════════════════════════════════
  async retain(content, options = {}) {
    const {
      context = 'api-abuse-detection',
      timestamp = new Date().toISOString(),
      documentId = null,
      tags = [],
      observationScopes = 'per_tag',
      entities = [],
      metadata = {},
    } = options;

    const item = { content };
    if (context) item.context = context;
    if (timestamp) item.timestamp = timestamp;
    if (tags.length > 0) item.tags = tags;
    if (entities.length > 0) item.entities = entities;
    if (Object.keys(metadata).length > 0) item.metadata = metadata;

    const body = {
      items: [item],
      observation_scopes: observationScopes,
    };

    if (documentId) body.document_id = documentId;

    return this._request('POST', `${this._bankPath}/memories`, body);
  }

  // ════════════════════════════════════════════════════════════
  //  RECALL — Retrieve past patterns / actor profiles
  // ════════════════════════════════════════════════════════════
  async recall(query, options = {}) {
    const {
      types = null,       // ["world", "experience", "observation"]
      tags = null,
      tagsMatch = null,   // "any" | "any_strict" | "all" | "all_strict"
      budget = 'mid',
      maxTokens = null,
    } = options;

    const body = { query, budget };
    if (types) body.types = types;
    if (tags) body.tags = tags;
    if (tagsMatch) body.tags_match = tagsMatch;
    if (maxTokens) body.max_tokens = maxTokens;

    return this._request('POST', `${this._bankPath}/memories/recall`, body);
  }

  // ════════════════════════════════════════════════════════════
  //  REFLECT — AI-powered threat assessment with structured output
  // ════════════════════════════════════════════════════════════
  async reflect(query, options = {}) {
    const {
      budget = 'mid',
      responseSchema = null,
      tags = null,
      tagsMatch = null,
      maxTokens = null,
    } = options;

    const body = { query, budget };
    if (responseSchema) body.response_schema = responseSchema;
    if (tags) body.tags = tags;
    if (tagsMatch) body.tags_match = tagsMatch;
    if (maxTokens) body.max_tokens = maxTokens;

    return this._request('POST', `${this._bankPath}/reflect`, body);
  }

  // ════════════════════════════════════════════════════════════
  //  BANK MANAGEMENT
  // ════════════════════════════════════════════════════════════
  async createBank() {
    try {
      return await this._request('PUT', `${this._bankPath}`, {});
    } catch (e) {
      // Bank may already exist — that's fine
      if (!e.message.includes('409') && !e.message.includes('already')) throw e;
    }
  }

  async configureBankRetain(retainMission, extractionMode = 'verbose') {
    return this._request('PATCH', `${this._bankPath}`, {
      retain_mission: retainMission,
      retain_extraction_mode: extractionMode,
    });
  }

  async configureBankObservations(observationsMission) {
    return this._request('PATCH', `${this._bankPath}`, {
      observations_mission: observationsMission,
      enable_observations: true,
    });
  }

  async configureBankReflect(reflectMission) {
    return this._request('PATCH', `${this._bankPath}`, {
      reflect_mission: reflectMission,
    });
  }

  async configureDisposition(skepticism = 0.8, literalism = 0.7, empathy = 0.2) {
    return this._request('PATCH', `${this._bankPath}`, {
      disposition_skepticism: skepticism,
      disposition_literalism: literalism,
      disposition_empathy: empathy,
    });
  }

  async getBankConfig() {
    return this._request('GET', `${this._bankPath}`);
  }

  // ── Health check ──
  async ping() {
    try {
      await this._request('GET', `/v1/default/banks`);
      return true;
    } catch {
      return false;
    }
  }
}

// Singleton
const hindsight = new HindsightClient();
export default hindsight;
