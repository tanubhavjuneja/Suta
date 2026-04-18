// dashboard.js — Real-time threat dashboard (Email Firewall Edition)
(() => {
  const eventFeed = document.getElementById('eventFeed');
  const scoresList = document.getElementById('scoresList');
  const queryInput = document.getElementById('queryInput');
  const queryBtn = document.getElementById('queryBtn');
  const queryResult = document.getElementById('queryResult');
  const statusDot = document.querySelector('.status-dot');
  const statusText = document.querySelector('.status-text');
  const statActors = document.getElementById('statActors');
  const statBlocked = document.getElementById('statBlocked');
  const statEvents = document.getElementById('statEvents');

  // Email Firewall specific elements
  const statUsers = document.getElementById('statUsers');
  const statEmails = document.getElementById('statEmails');
  const statTrusted = document.getElementById('statTrusted');
  const statMalicious = document.getElementById('statMalicious');
  const userList = document.getElementById('userList');

  // State
  const actors = new Map();
  const users = new Map(); // userId → { reputation, ips, emails, blocked, trusted }
  let totalEvents = 0;
  let totalBlocked = 0;
  let totalEmails = 0;
  let totalTrusted = 0;
  let currentFilter = 'all';
  let ws = null;
  let dashboardMode = 'api'; // 'api' or 'email'

  // ── Mode Toggle ─────────────────────────────────────────────────
  function setMode(mode) {
    dashboardMode = mode;
    const apiPanel = document.querySelector('.api-panel');
    const emailPanel = document.querySelector('.email-panel');
    
    if (mode === 'email') {
      if (apiPanel) apiPanel.style.display = 'none';
      if (emailPanel) emailPanel.style.display = 'block';
    } else {
      if (apiPanel) apiPanel.style.display = 'block';
      if (emailPanel) emailPanel.style.display = 'none';
    }
  }

  // ── WebSocket Connection ──────────────────────────────────────────────
  function connect() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}/ws`);

    ws.onopen = () => {
      statusDot.className = 'status-dot connected';
      statusText.textContent = 'Connected';
    };

    ws.onclose = () => {
      statusDot.className = 'status-dot disconnected';
      statusText.textContent = 'Disconnected';
      setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      statusDot.className = 'status-dot disconnected';
      statusText.textContent = 'Error';
    };

    ws.onmessage = (msg) => {
      const data = JSON.parse(msg.data);
      console.log('WS received:', data.type, data.event?.type, data.event?.action);
      if (data.type === 'history') {
        console.log('History events:', data.events.length);
        data.events.forEach(addEvent);
      } else if (data.type === 'event') {
        addEvent(data.event);
      } else if (data.type === 'email_event') {
        addEmailEvent(data.event);
      }
    };
  }

  // ── Email Event Handling ──────────────────────────────────────────
  function addEmailEvent(event) {
    totalEvents++;
    if (statEvents) statEvents.textContent = totalEvents;

    // Track users
    if (event.userId) {
      if (!users.has(event.userId)) {
        users.set(event.userId, {
          reputation: 50,
          ips: new Set(),
          emailsSent: 0,
          blocked: false,
          trustedByAdmin: false,
          firstSeen: event.timestamp,
        });
        if (statUsers) statUsers.textContent = users.size;
      }

      const user = users.get(event.userId);
      if (event.ip) user.ips.add(event.ip);
      if (event.type === 'email_sent') {
        user.emailsSent++;
        totalEmails++;
        if (statEmails) statEmails.textContent = totalEmails;
      }
      if (event.action === 'block') {
        user.blocked = true;
        totalBlocked++;
        if (statBlocked) statBlocked.textContent = totalBlocked;
      }
      if (event.trustedByAdmin) {
        user.trustedByAdmin = true;
        totalTrusted++;
        if (statTrusted) statTrusted.textContent = totalTrusted;
      }

      user.reputation = event.reputation || user.reputation;
      updateUserList();
    }

    addEvent(event);
  }

  function updateUserList() {
    if (!userList) return;

    const sorted = [...users.entries()]
      .sort(([, a], [, b]) => b.reputation - a.reputation);

    userList.innerHTML = sorted.slice(0, 20).map(([userId, data]) => {
      const repClass = data.reputation >= 70 ? 'safe' : data.reputation >= 40 ? 'monitor' : 'danger';
      const repColor = data.reputation >= 70 ? 'var(--score-safe)' : data.reputation >= 40 ? 'var(--score-monitor)' : 'var(--score-danger)';
      
      return `
        <div class="score-row">
          <span class="score-actor">${userId}</span>
          <span style="color:var(--text-muted);font-size:11px">${data.ips.size} IPs</span>
          <span style="color:var(--text-muted);font-size:11px">${data.emailsSent} emails</span>
          <span class="score-number" style="color:${repColor}">${data.reputation}</span>
          ${data.trustedByAdmin ? '<span style="color:var(--score-safe)">✓</span>' : ''}
          ${data.blocked ? '<span style="color:var(--accent-red)">🚫</span>' : ''}
        </div>
      `;
    }).join('');
  }

  // ── Event Handling ─────────────────────────────────────────
  function addEvent(event) {
    totalEvents++;
    statEvents.textContent = totalEvents;

    // Track actors (API mode)
    if (event.actorId && !actors.has(event.actorId)) {
      actors.set(event.actorId, { score: 0, classification: 'unknown', action: 'allow', lastSeen: event.timestamp });
      statActors.textContent = actors.size;
    }

    if (event.type === 'assessment' && event.actorId) {
      actors.set(event.actorId, {
        score: event.score || 0,
        classification: event.classification || 'unknown',
        action: event.action || 'allow',
        lastSeen: event.timestamp,
      });
      updateScores();
    }

    if (event.type === 'enforcement' && (event.action === 'block' || event.action === 'throttle')) {
      totalBlocked++;
      statBlocked.textContent = totalBlocked;
    }

    if (shouldShow(event)) {
      appendEventToFeed(event);
    }
  }

  function shouldShow(event) {
    if (currentFilter === 'all') return true;
    if (currentFilter === 'enforcement') return event.type === 'enforcement';
    if (currentFilter === 'assessment') return event.type === 'assessment';
    if (currentFilter === 'recall') return event.type === 'recall';
    if (currentFilter === 'email') return event.type?.startsWith('email');
    return true;
  }

  function appendEventToFeed(event) {
    const empty = eventFeed.querySelector('.empty-state');
    if (empty) empty.remove();

    const el = document.createElement('div');
    el.className = 'event-item';
    el.dataset.type = event.type;

    const icon = getEventIcon(event);
    const time = event.timestamp ? event.timestamp.split('T')[1]?.split('.')[0] || '' : '';
    const content = formatEventContent(event);

    el.innerHTML = `
      <span class="event-icon">${icon}</span>
      <span class="event-time">${time}</span>
      <span class="event-content">${content}</span>
    `;

    eventFeed.prepend(el);

    while (eventFeed.children.length > 200) {
      eventFeed.lastChild.remove();
    }
  }

  function getEventIcon(event) {
    const icons = {
      request: '📡',
      email_sent: '📧',
      email_blocked: '🚫',
      email_allowed: '✓',
      fingerprint: '🔑',
      recall: event.found ? '🧠' : '🔍',
      assessment: getScoreEmoji(event.score),
      enforcement: { block: '🚫', throttle: '⏳', monitor: '👁️', allow: '✅' }[event.action] || '❓',
      retained: '💾',
      error: '❌',
      trusted: '⭐',
      untrusted: '⚠️',
    };
    return icons[event.type] || icons[event.type] || '📋';
  }

  function getScoreEmoji(score) {
    if (score >= 85) return '🔴';
    if (score >= 70) return '🟠';
    if (score >= 40) return '🟡';
    return '🟢';
  }

  function getScoreClass(score) {
    if (score >= 85) return 'danger';
    if (score >= 70) return 'monitor';
    if (score >= 40) return 'warning';
    return 'safe';
  }

  function formatEventContent(event) {
    switch (event.type) {
      case 'email_sent':
        return `<span class="actor-tag">${event.userId}</span> → 📧 ${event.subject || '(no subject)'} (${event.ip})`;
      case 'email_blocked':
        return `<span class="action-badge block">BLOCKED</span> <span class="actor-tag">${event.userId}</span> — ${event.reason || event.action}`;
      case 'email_allowed':
        return `<span class="action-badge allow">ALLOWED</span> <span class="actor-tag">${event.userId}</span> — score: ${event.reputation}`;
      case 'trusted':
        return `<span class="action-badge safe">TRUSTED</span> ${event.userId || event.actorId} by admin`;
      case 'untrusted':
        return `<span class="action-badge danger">UNTRUSTED</span> ${event.userId || event.actorId}`;
      case 'request':
        return `<span class="actor-tag">${event.actorId}</span> → ${event.method} ${event.path}`;
      case 'recall':
        if (event.found) return `<strong>KNOWN</strong> <span class="actor-tag">${event.actorId}</span>`;
        return `No history for <span class="actor-tag">${event.actorId}</span>`;
      case 'assessment': {
        const cls = getScoreClass(event.score);
        return `<span class="actor-tag">${event.actorId}</span> <span class="score-tag ${cls}">${event.score}</span> ${event.classification}`;
      }
      case 'enforcement':
        return `<span class="action-badge ${event.action}">${event.action}</span> <span class="actor-tag">${event.actorId}</span>`;
      default:
        return JSON.stringify(event).substring(0, 100);
    }
  }

  // ── Scores Panel ───────────────────────────────────────────────
  function updateScores() {
    const sorted = [...actors.entries()].sort(([, a], [, b]) => b.score - a.score);
    if (sorted.length === 0) return;

    scoresList.innerHTML = sorted.map(([actorId, data]) => {
      const cls = getScoreClass(data.score);
      return `
        <div class="score-row">
          <span class="score-actor">${actorId}</span>
          <div class="score-bar-container">
            <div class="score-bar" style="width:${data.score}%;background:var(--score-${cls})"></div>
          </div>
          <span class="score-number" style="color:var(--score-${cls})">${data.score}</span>
        </div>
      `;
    }).join('');
  }

  // ── Filter Buttons ─────────────────────────────────────────
  document.querySelectorAll('.filter-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      eventFeed.innerHTML = '<div class="empty-state">Filter changed</div>';
    });
  });

  // Mode buttons
  document.querySelectorAll('.mode-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const mode = btn.dataset.mode;
      setMode(mode);
    });
  });

  // ── Admin Trust Panel ─────────────────────────────────────────
  window.trustUser = async function(userId, trust) {
    try {
      const res = await fetch('/admin/email/trust', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, trust }),
      });
      const data = await res.json();
      console.log('Trust update:', data);
    } catch (e) {
      console.error('Trust update failed:', e);
    }
  };

  // ── Hindsight Query ─────────────────────────────────────────
  queryBtn.addEventListener('click', async () => {
    const question = queryInput.value.trim();
    if (!question) return;

    queryBtn.disabled = true;
    queryBtn.textContent = 'Thinking...';
    queryResult.innerHTML = '<div class="empty-state">Analyzing...</div>';

    try {
      const res = await fetch('/admin/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question }),
      });
      const data = await res.json();
      queryResult.innerHTML = `<div class="answer">${data.answer || data.error}</div>`;
    } catch (e) {
      queryResult.innerHTML = `<div class="answer" style="color:var(--accent-red)">Error: ${e.message}</div>`;
    } finally {
      queryBtn.disabled = false;
      queryBtn.textContent = 'Ask';
    }
  });

  queryInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') queryBtn.click();
  });

  // ── Boot ────────────────────────────────────────────────
  connect();
  setMode('api');
})();