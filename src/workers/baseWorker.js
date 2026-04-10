// src/workers/baseWorker.js
// Base worker class with common IPC handling
// ═══════════════════════════════════════════════════════════════
const { parentPort } = require('worker_threads');

class BaseWorker {
  constructor(workerName) {
    this.workerName = workerName;
    this.handlers = new Map();
    this.setupParentListener();
  }

  setupParentListener() {
    parentPort.on('message', async (msg) => {
      const { type, id, payload } = msg;
      
      try {
        const handler = this.handlers.get(type);
        let result;
        
        if (handler) {
          result = await handler(payload);
        } else {
          result = { success: false, error: `Unknown message type: ${type}` };
        }
        
        parentPort.postMessage({
          type: result.success ? 'RESPONSE_SUCCESS' : 'RESPONSE_ERROR',
          id,
          worker: this.workerName,
          result
        });
      } catch (err) {
        parentPort.postMessage({
          type: 'RESPONSE_ERROR',
          id,
          worker: this.workerName,
          result: { success: false, error: err.message }
        });
      }
    });
  }

  registerHandler(type, handler) {
    this.handlers.set(type, handler);
  }

  sendToParent(type, payload = {}) {
    parentPort.postMessage({ type, worker: this.workerName, payload });
  }

  log(message, level = 'info') {
    this.sendToParent('WORKER_LOG', { level, message: `[${this.workerName}] ${message}` });
  }

  error(message, error) {
    this.sendToParent('WORKER_LOG', { 
      level: 'error', 
      message: `[${this.workerName}] ${message}: ${error?.message || error}` 
    });
  }
}

module.exports = { BaseWorker };