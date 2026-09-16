/* ─── settings.js — logger config editor + remote proxy control ─── */

const loggerContent = document.getElementById('loggerConfigContent');
const btnSaveLogger = document.getElementById('btnSaveLogger');
const loggerMsg     = document.getElementById('loggerConfigMsg');

const proxyDot        = document.getElementById('proxyDot');
const proxyStatusLabel = document.getElementById('proxyStatusLabel');
const btnProxyStart   = document.getElementById('btnProxyStart');
const btnProxyStop    = document.getElementById('btnProxyStop');
const proxyOutput     = document.getElementById('proxyOutput');

// ── load on view activation ───────────────────────────────────────────────────
document.querySelector('[data-view="settings"]').addEventListener('click', () => {
  loadLoggerConfig();
  pollProxyStatus();
});

// ── Logger config ─────────────────────────────────────────────────────────────
async function loadLoggerConfig() {
  try {
    const res = await API.get('/api/config/logger');
    loggerContent.value = res.content || '';
    showLoggerMsg('');
  } catch {
    showLoggerMsg('Could not load emv_logger.yaml', true);
  }
}

btnSaveLogger.addEventListener('click', async () => {
  const res = await API.post('/api/config/logger', { content: loggerContent.value }, 'PUT');
  showLoggerMsg(
    res.ok ? '✓ Saved — restart the relay session for changes to take effect.' : (res.detail || 'Save failed'),
    !res.ok,
  );
});

function showLoggerMsg(text, isError = false) {
  loggerMsg.textContent = text;
  loggerMsg.className   = 'pb-msg' + (isError ? ' pb-msg-error' : ' pb-msg-ok');
}

// ── Remote proxy ──────────────────────────────────────────────────────────────
btnProxyStart.addEventListener('click', async () => {
  const host   = document.getElementById('proxyHost').value.trim() || '0.0.0.0';
  const port   = parseInt(document.getElementById('proxyPort').value, 10) || 7654;
  const reader = parseInt(document.getElementById('proxyReader').value, 10) || 0;

  const res = await API.post('/api/proxy/start', { host, port, reader });
  if (res.ok) {
    setProxyState(true);
    proxyOutput.textContent = `Proxy started (PID ${res.pid})\nListening on ${host}:${port}  reader=${reader}`;
  } else {
    proxyOutput.textContent = '✗ ' + (res.error || 'Failed to start proxy');
  }
});

btnProxyStop.addEventListener('click', async () => {
  await API.post('/api/proxy/stop', {});
  setProxyState(false);
  proxyOutput.textContent += '\n[Stopped]';
});

function setProxyState(running) {
  btnProxyStart.disabled = running;
  btnProxyStop.disabled  = !running;
  proxyDot.className     = 'proxy-status-dot' + (running ? ' active' : '');
  proxyStatusLabel.textContent = running ? 'Running' : 'Stopped';
}

async function pollProxyStatus() {
  try {
    const res = await API.get('/api/proxy/status');
    setProxyState(res.running);
    if (res.output && res.output.length) {
      proxyOutput.textContent = res.output.join('\n');
    }
  } catch { /* server unreachable */ }
}

// Poll proxy status every 4 s only while Settings view is visible
function _settingsViewActive() {
  return document.getElementById('view-settings')?.classList.contains('active');
}
setInterval(async () => {
  if (!_settingsViewActive()) return;
  try {
    const res = await API.get('/api/proxy/status');
    setProxyState(res.running);
    if (res.output && res.output.length) {
      const tail = res.output.slice(-30).join('\n');
      if (proxyOutput.textContent !== tail) proxyOutput.textContent = tail;
    }
  } catch { /* ignore */ }
}, 4000);
