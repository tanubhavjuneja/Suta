// dashboard.js — Real-time threat dashboard
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

  // State
  const actors = new Map(); // actorId → { score, classification, action, lastSeen }
  let totalEvents = 0;
  let totalBlocked = 0;
  let currentFilter = 'all';
  let ws = null;

  // ── WebSocket Connection ──────────────────────────────────
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
      if (data.type === 'history') {
        data.events.forEach(addEvent);
      } else if (data.type === 'event') {
        addEvent(data.event);
      }
    };
  }

  // ── Event Handling ────────────────────────────────────────
  function addEvent(event) {
    totalEvents++;
    statEvents.textContent = totalEvents;

    // Track actors
    if (event.actorId && !actors.has(event.actorId)) {
      actors.set(event.actorId, { score: 0, classification: 'unknown', action: 'allow', lastSeen: event.timestamp });
      statActors.textContent = actors.size;
    }

    // Update actor data from assessments
    if (event.type === 'assessment' && event.actorId) {
      actors.set(event.actorId, {
        score: event.score || 0,
        classification: event.classification || 'unknown',
        action: event.action || 'allow',
        lastSeen: event.timestamp,
      });
      updateScores();
    }

    // Track blocks
    if (event.type === 'enforcement' && (event.action === 'block' || event.action === 'throttle')) {
      totalBlocked++;
      statBlocked.textContent = totalBlocked;
    }

    // Add to feed
    if (shouldShow(event)) {
      appendEventToFeed(event);
    }
  }

  function shouldShow(event) {
    if (currentFilter === 'all') return true;
    if (currentFilter === 'enforcement') return event.type === 'enforcement';
    if (currentFilter === 'assessment') return event.type === 'assessment';
    if (currentFilter === 'recall') return event.type === 'recall';
    return true;
  }

  function appendEventToFeed(event) {
    // Remove empty state
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

    // Keep feed size manageable
    while (eventFeed.children.length > 200) {
      eventFeed.lastChild.remove();
    }
  }

  function getEventIcon(event) {
    const icons = {
      request: '📡',
      fingerprint: '🔑',
      recall: event.found ? '🧠' : '🔍',
      assessment: getScoreEmoji(event.score),
      enforcement: { block: '🚫', throttle: '⏳', monitor: '👁️', allow: '✅' }[event.action] || '❓',
      retained: '💾',
      error: '❌',
    };
    return icons[event.type] || '📋';
  }

  function getScoreEmoji(score) {
    if (score >= 85) return '🔴';
    if (score >= 70) return '🟠';
    if (score >= 40) return '🟡';
    return '🟢';
  }

  function getScoreClass(score) {
    if (score >= 85) return 'block';
    if (score >= 70) return 'throttle';
    if (score >= 40) return 'monitor';
    return 'safe';
  }

  function formatEventContent(event) {
    switch (event.type) {
      case 'request':
        return `<span class="actor-tag">${event.actorId}</span> → ${event.method} ${event.path} <span style="color:var(--text-muted)">(${event.ip})</span>`;
      case 'recall':
        if (event.found) {
          return `<strong>KNOWN ACTOR</strong> <span class="actor-tag">${event.actorId}</span> — ${event.resultCount} memories found`;
        }
        return `No history for <span class="actor-tag">${event.actorId}</span>`;
      case 'assessment': {
        const cls = getScoreClass(event.score);
        return `<span class="actor-tag">${event.actorId}</span> <span class="score-tag ${cls}">${event.score}/100</span> ${event.classification} <span class="action-badge ${event.action}">${event.action}</span>`;
      }
      case 'enforcement': {
        return `<span class="action-badge ${event.action}">${event.action}</span> <span class="actor-tag">${event.actorId}</span> — score: ${event.score}`;
      }
      case 'retained':
        return `Stored session <span style="color:var(--text-muted)">${event.sessionId}</span> (${event.requestCount} requests)`;
      case 'error':
        return `<span style="color:var(--accent-red)">${event.message}</span>`;
      default:
        return JSON.stringify(event);
    }
  }

  // ── Scores Panel ──────────────────────────────────────────
  function updateScores() {
    const sorted = [...actors.entries()]
      .sort(([, a], [, b]) => b.score - a.score);

    if (sorted.length === 0) return;

    scoresList.innerHTML = sorted.map(([actorId, data]) => {
      const cls = getScoreClass(data.score);
      const color = getComputedStyle(document.documentElement).getPropertyValue(`--score-${cls}`).trim();
      return `
        <div class="score-row">
          <span class="score-actor">${actorId}</span>
          <div class="score-bar-container">
            <div class="score-bar" style="width: ${data.score}%; background: ${color}"></div>
          </div>
          <span class="score-number" style="color: ${color}">${data.score}</span>
        </div>
      `;
    }).join('');
  }

  // ── Filter Buttons ────────────────────────────────────────
  document.querySelectorAll('.filter-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;

      // Re-render feed (simplified: just clear and note filter changed)
      eventFeed.innerHTML = '<div class="empty-state">Filter changed — new events will appear here</div>';
    });
  });

  // ── Hindsight Query ───────────────────────────────────────
  queryBtn.addEventListener('click', async () => {
    const question = queryInput.value.trim();
    if (!question) return;

    queryBtn.disabled = true;
    queryBtn.textContent = 'Asking...';
    queryResult.innerHTML = '<div class="empty-state">Thinking...</div>';

    try {
      const res = await fetch('/admin/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question }),
      });

      const data = await res.json();
      queryResult.innerHTML = `<div class="answer">${data.answer || data.error || 'No answer'}</div>`;
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

  // ── Boot ──────────────────────────────────────────────────
  connect();
})();
