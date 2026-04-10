// src/workers/loggingWorker.js
// Logging Worker - handles rolling logs and audit trail
// ═══════════════════════════════════════════════════════════════
import { parentPort } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const LOG_DIR = path.join(__dirname, '../../config/logs');
const CHUNK_SIZE = 4 * 1024 * 1024; // 4MB
const DEFAULT_MAX_DAYS = 7;
const DEFAULT_MAX_SIZE_MB = 100;

class LoggingWorker {
  constructor() {
    this.logConfig = {
      maxDays: DEFAULT_MAX_DAYS,
      maxSizeMB: DEFAULT_MAX_SIZE_MB,
      chunkSizeMB: 4
    };
    this.currentLogFile = null;
    this.currentLogStream = null;
    this.currentLogSize = 0;
    this.adminLogStream = null;
    this.init();
  }

  init() {
    this.ensureLogDir();
    this.loadConfig();
    this.initLogStream();
    this.initAdminLogStream();
    this.cleanupOldLogs();
    this.setupHandlers();
    
    console.log('[LoggingWorker] Initialized');
  }

  ensureLogDir() {
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true });
    }
  }

  loadConfig() {
    const configPath = path.join(__dirname, '../../config/user-config.json');
    try {
      if (fs.existsSync(configPath)) {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        if (config.logging) {
          this.logConfig = { ...this.logConfig, ...config.logging };
        }
      }
    } catch (e) {
      console.log('[LoggingWorker] Using default config');
    }
  }

  saveConfig() {
    const configPath = path.join(__dirname, '../../config/user-config.json');
    try {
      let config = {};
      if (fs.existsSync(configPath)) {
        config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      }
      config.logging = this.logConfig;
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    } catch (e) {
      console.error('[LoggingWorker] Failed to save config:', e.message);
    }
  }

  getLogFilename(prefix = 'suta') {
    const now = new Date();
    const date = now.toISOString().split('T')[0];
    return `${prefix}-${date}.log`;
  }

  initLogStream() {
    const filename = this.getLogFilename('suta');
    const filepath = path.join(LOG_DIR, filename);
    this.currentLogFile = filepath;
    this.currentLogStream = fs.createWriteStream(filepath, { flags: 'a' });
    this.currentLogSize = fs.existsSync(filepath) ? fs.statSync(filepath).size : 0;
  }

  initAdminLogStream() {
    const filename = this.getLogFilename('admin-audit');
    const filepath = path.join(LOG_DIR, filename);
    this.adminLogStream = fs.createWriteStream(filepath, { flags: 'a' });
  }

  rotateLogIfNeeded() {
    if (this.currentLogSize >= CHUNK_SIZE) {
      this.currentLogStream.end();
      this.initLogStream();
    }
  }

  writeLog(level, message) {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] [${level.toUpperCase()}] ${message}\n`;
    
    this.currentLogStream.write(logLine);
    this.currentLogSize += Buffer.byteLength(logLine, 'utf8');
    this.rotateLogIfNeeded();
  }

  writeAdminLog(event) {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] ${JSON.stringify(event)}\n`;
    
    this.adminLogStream.write(logLine);
  }

  cleanupOldLogs() {
    try {
      const files = fs.readdirSync(LOG_DIR);
      const now = Date.now();
      const maxAgeMs = this.logConfig.maxDays * 24 * 60 * 60 * 1000;
      const maxTotalSize = this.logConfig.maxSizeMB * 1024 * 1024;

      // Delete old files by date
      files.forEach(file => {
        const filepath = path.join(LOG_DIR, file);
        const stats = fs.statSync(filepath);
        if (now - stats.mtimeMs > maxAgeMs) {
          fs.unlinkSync(filepath);
          console.log('[LoggingWorker] Deleted old log:', file);
        }
      });

      // Check total size and delete oldest if needed
      let totalSize = 0;
      const logFiles = files
        .filter(f => f.startsWith('suta-') && f.endsWith('.log'))
        .map(f => ({
          name: f,
          path: path.join(LOG_DIR, f),
          mtime: fs.statSync(path.join(LOG_DIR, f)).mtimeMs
        }))
        .sort((a, b) => a.mtime - b.mtime); // oldest first

      logFiles.forEach(file => {
        const size = fs.statSync(file.path).size;
        if (totalSize + size > maxTotalSize) {
          fs.unlinkSync(file.path);
          console.log('[LoggingWorker] Deleted size-exceeded log:', file.name);
        } else {
          totalSize += size;
        }
      });
    } catch (e) {
      console.error('[LoggingWorker] Cleanup error:', e.message);
    }
  }

  setupHandlers() {
    parentPort.on('message', async (msg) => {
      const { type, id, payload } = msg;
      let result;

      try {
        switch (type) {
          case 'LOG_WRITE':
            this.writeLog(payload.level || 'info', payload.message);
            result = { success: true };
            break;

          case 'LOG_READ':
            result = await this.readLogs(payload);
            break;

          case 'LOG_GET_FILES':
            result = await this.getLogFiles();
            break;

          case 'LOG_GET_CONFIG':
            result = { success: true, config: this.logConfig };
            break;

          case 'LOG_SET_CONFIG':
            this.logConfig = { ...this.logConfig, ...payload };
            this.saveConfig();
            this.cleanupOldLogs();
            result = { success: true };
            break;

          case 'LOG_ADMIN_EVENT':
            this.writeAdminLog(payload);
            result = { success: true };
            break;

          default:
            result = { success: false, error: `Unknown type: ${type}` };
        }
      } catch (err) {
        result = { success: false, error: err.message };
      }

      parentPort.postMessage({
        type: result.success ? 'RESPONSE_SUCCESS' : 'RESPONSE_ERROR',
        id,
        result
      });
    });
  }

  async readLogs({ filename, lines = 100, offset = 0 }) {
    try {
      let filepath;
      
      if (filename) {
        filepath = path.join(LOG_DIR, filename);
      } else {
        // Get most recent log file
        const files = fs.readdirSync(LOG_DIR)
          .filter(f => f.startsWith('suta-') && f.endsWith('.log'))
          .sort((a, b) => b.localeCompare(a));
        
        if (files.length === 0) {
          return { success: true, logs: [], totalLines: 0 };
        }
        filepath = path.join(LOG_DIR, files[0]);
      }

      if (!fs.existsSync(filepath)) {
        return { success: true, logs: [], totalLines: 0 };
      }

      const content = fs.readFileSync(filepath, 'utf8');
      const allLines = content.split('\n').filter(l => l.trim());
      const totalLines = allLines.length;
      const startLine = Math.max(0, totalLines - lines - offset);
      const selectedLines = allLines.slice(startLine, startLine + lines);

      return { 
        success: true, 
        logs: selectedLines, 
        totalLines,
        filename: path.basename(filepath)
      };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  async getLogFiles() {
    try {
      const files = fs.readdirSync(LOG_DIR)
        .filter(f => f.endsWith('.log'))
        .map(f => {
          const stats = fs.statSync(path.join(LOG_DIR, f));
          return {
            name: f,
            size: stats.size,
            modified: stats.mtime.toISOString()
          };
        })
        .sort((a, b) => new Date(b.modified) - new Date(a.modified));

      return { success: true, files };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }
}

new LoggingWorker();