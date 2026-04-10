// src/workers/workerManager.js
// Worker Manager - spawns and manages all child processes
// ═══════════════════════════════════════════════════════════════
import { Worker } from 'worker_threads';
import path from 'path';
import { fileURLToPath } from 'url';
import { EventEmitter } from 'events';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class WorkerManager extends EventEmitter {
  constructor() {
    super();
    this.workers = new Map();
    this.messageId = 0;
    this.relayMessageId = 0;
    this.pendingMessages = new Map();
    this.pendingRelays = new Map();
  }

  async spawnWorker(name, workerPath) {
    return new Promise((resolve, reject) => {
      const worker = new Worker(workerPath);
      
      worker.on('error', (err) => {
        console.error(`[WorkerManager] ${name} error:`, err.message);
        this.emit('worker_error', { name, error: err.message });
      });

      worker.on('exit', (code) => {
        console.log(`[WorkerManager] ${name} exited with code ${code}`);
        this.workers.delete(name);
        this.emit('worker_exit', { name, code });
      });

      worker.on('message', (msg) => {
        this.handleWorkerMessage(name, msg);
      });

      this.workers.set(name, worker);
      console.log(`[WorkerManager] Spawned ${name}`);
      
      resolve(worker);
    });
  }

  async initialize() {
    const workerDir = path.join(__dirname);
    
    await this.spawnWorker('logging', path.join(workerDir, 'loggingWorker.js'));
    await this.spawnWorker('ml', path.join(workerDir, 'mlWorker.js'));
    await this.spawnWorker('pipeline', path.join(workerDir, 'pipelineWorker.js'));
    await this.spawnWorker('dashboard', path.join(workerDir, 'dashboardWorker.js'));
    
    console.log('[WorkerManager] All workers initialized');
  }

  async sendMessage(workerName, type, payload = {}) {
    return new Promise((resolve, reject) => {
      const worker = this.workers.get(workerName);
      if (!worker) {
        reject(new Error(`Worker ${workerName} not found`));
        return;
      }

      const id = ++this.messageId;
      const timeout = setTimeout(() => {
        this.pendingMessages.delete(id);
        reject(new Error(`Timeout waiting for ${workerName} ${type}`));
      }, 30000);

      this.pendingMessages.set(id, { resolve, timeout });

      worker.postMessage({ type, id, payload });
    });
  }

  handleWorkerMessage(workerName, msg) {
    const { type, id, result, payload } = msg;

    if (id && this.pendingMessages.has(id)) {
      const { resolve, timeout } = this.pendingMessages.get(id);
      clearTimeout(timeout);
      this.pendingMessages.delete(id);
      resolve(result);
      return;
    }

    if (id && this.pendingRelays.has(id)) {
      const relay = this.pendingRelays.get(id);
      this.pendingRelays.delete(id);

      const sourceWorker = this.workers.get(relay.sourceWorker);
      if (sourceWorker) {
        sourceWorker.postMessage({
          type,
          id: relay.sourceId,
          result,
          payload,
        });
      }
      return;
    }

    if (type === 'ADMIN_LOG') {
      this.emit('admin_log', payload);
    } else if (type === 'PIPELINE_LOG') {
      this.emit('pipeline_log', payload);
    } else if (type === 'WORKER_LOG') {
      this.emit('worker_log', payload);
    } else {
      const targetWorker = this.getForwardTarget(workerName, type);
      if (targetWorker) {
        this.forwardWorkerMessage(workerName, targetWorker, msg);
      }
    }
  }

  getForwardTarget(sourceWorker, type) {
    if (type.startsWith('LOG_') && sourceWorker !== 'logging') return 'logging';
    if (type.startsWith('ML_') && sourceWorker !== 'ml') return 'ml';
    if (type.startsWith('PIPELINE_') && sourceWorker !== 'pipeline') return 'pipeline';
    if (type.startsWith('DASHBOARD_') && sourceWorker !== 'dashboard') return 'dashboard';
    return null;
  }

  forwardWorkerMessage(sourceWorker, targetWorker, msg) {
    const worker = this.workers.get(targetWorker);
    if (!worker) {
      return;
    }

    if (msg.id) {
      const relayId = `relay-${++this.relayMessageId}`;
      this.pendingRelays.set(relayId, {
        sourceWorker,
        sourceId: msg.id,
      });

      worker.postMessage({
        type: msg.type,
        id: relayId,
        payload: msg.payload,
      });
      return;
    }

    worker.postMessage({
      type: msg.type,
      payload: msg.payload,
    });
  }

  async log(level, message) {
    return this.sendMessage('logging', 'LOG_WRITE', { level, message });
  }

  async getLogFiles() {
    return this.sendMessage('logging', 'LOG_GET_FILES');
  }

  async readLogs(payload) {
    return this.sendMessage('logging', 'LOG_READ', payload);
  }

  async getLogConfig() {
    return this.sendMessage('logging', 'LOG_GET_CONFIG');
  }

  async setLogConfig(payload) {
    return this.sendMessage('logging', 'LOG_SET_CONFIG', payload);
  }

  async trainModel(mode = 'full') {
    return this.sendMessage('ml', 'ML_TRAIN', { mode });
  }

  async runAnalysis(payload) {
    return this.sendMessage('ml', 'ML_ANALYZE', payload);
  }

  async queryLogs(payload) {
    return this.sendMessage('ml', 'ML_QUERY_LOGS', payload);
  }

  async getMLStatus() {
    return this.sendMessage('ml', 'ML_GET_STATUS');
  }

  async rulesChanged() {
    return this.sendMessage('ml', 'ML_RULES_CHANGED', {});
  }

  async startPipeline() {
    return this.sendMessage('pipeline', 'PIPELINE_START');
  }

  async stopPipeline() {
    return this.sendMessage('pipeline', 'PIPELINE_STOP');
  }

  async getPipelineStatus() {
    return this.sendMessage('pipeline', 'PIPELINE_GET_STATUS');
  }

  async processRequest(payload) {
    return this.sendMessage('pipeline', 'PIPELINE_PROCESS_REQUEST', payload);
  }

  async blockIP(payload) {
    return this.sendMessage('pipeline', 'PIPELINE_BLOCK_IP', payload);
  }

  async unblockIP(payload) {
    return this.sendMessage('pipeline', 'PIPELINE_UNBLOCK_IP', payload);
  }

  async getBlockedIPs() {
    return this.sendMessage('pipeline', 'PIPELINE_GET_BLOCKED_IPS');
  }

  async checkIP(ip) {
    return this.sendMessage('pipeline', 'PIPELINE_CHECK_IP', { ip });
  }

  async getConfig() {
    return this.sendMessage('dashboard', 'DASHBOARD_GET_CONFIG');
  }

  async saveConfig(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_SAVE_CONFIG', payload);
  }

  async getRules() {
    return this.sendMessage('dashboard', 'DASHBOARD_GET_RULES');
  }

  async addRule(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_ADD_RULE', payload);
  }

  async deleteRule(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_DELETE_RULE', payload);
  }

  async dashboardBlockIP(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_BLOCK_IP', payload);
  }

  async dashboardUnblockIP(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_UNBLOCK_IP', payload);
  }

  async getRulesByIP(ip) {
    return this.sendMessage('dashboard', 'DASHBOARD_GET_RULES_BY_IP', { ip });
  }

  async addEvent(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_SEND_EVENT', payload);
  }

  async getEvents(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_GET_EVENTS', payload);
  }

  async getTrainingStatus() {
    return this.sendMessage('dashboard', 'DASHBOARD_GET_TRAINING_STATUS');
  }

  async triggerTraining(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_TRIGGER_TRAINING', payload);
  }

  async getSuggestions() {
    return this.sendMessage('dashboard', 'DASHBOARD_GET_SUGGESTIONS');
  }

  async approveSuggestion(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_APPROVE_SUGGESTION', payload);
  }

  async rejectSuggestion(payload) {
    return this.sendMessage('dashboard', 'DASHBOARD_REJECT_SUGGESTION', payload);
  }

  async shutdown() {
    for (const [name, worker] of this.workers) {
      worker.terminate();
      console.log(`[WorkerManager] Terminated ${name}`);
    }
    this.workers.clear();
  }
}

const workerManager = new WorkerManager();
export { workerManager, WorkerManager };
