/* ─── ATRIUM app.js — router, session control, shared helpers ─── */

// The server only demands a token when it was started with ATRIUM_API_TOKEN
// (required for non-loopback binds). Loopback users never see this.
const TOKEN_KEY = 'atrium-api-token';
const getToken = () => { try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; } };

function authHeaders(extra = {}) {
  const t = getToken();
  return t ? { ...extra, 'X-Atrium-Token': t } : extra;
}

async function handle(res) {
  if (res.status === 401) {
    const t = window.prompt('This ATRIUM server requires an API token (ATRIUM_API_TOKEN):');
    if (t) { try { localStorage.setItem(TOKEN_KEY, t); } catch {} location.reload(); }
    return { ok: false, error: 'Authentication required' };
  }
  return res.json();
}

const API = {
  get:  (url)                  => fetch(url, { headers: authHeaders() }).then(handle),
  post: (url, body, method = 'POST') => fetch(url, {
    method,
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  }).then(handle),
  del:  (url)                  => fetch(url, { method: 'DELETE', headers: authHeaders() }).then(handle),
};

// ── Mobile off-canvas sidebar ─────────────────────────────────────────────────
const sidebarEl = document.querySelector('.sidebar');
const navScrim  = document.getElementById('navScrim');

function closeMobileNav() {
  sidebarEl?.classList.remove('open');
  navScrim?.classList.remove('show');
}

document.getElementById('btnMobileNav')?.addEventListener('click', () => {
  const open = sidebarEl.classList.toggle('open');
  navScrim?.classList.toggle('show', open);
});

navScrim?.addEventListener('click', closeMobileNav);
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMobileNav(); });

// ── View router ───────────────────────────────────────────────────────────────
function navigate(viewName) {
  document.querySelectorAll('.nav-links a').forEach(l => l.classList.remove('active'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const link = document.querySelector(`.nav-links a[data-view="${viewName}"]`);
  if (link) {
    link.classList.add('active');
    link.dispatchEvent(new Event('click', { bubbles: false }));
  }
  const view = document.getElementById(`view-${viewName}`);
  if (view) view.classList.add('active');
  closeMobileNav();          // collapse the drawer after navigating on mobile
}

document.querySelectorAll('.nav-links a').forEach(link => {
  link.addEventListener('click', e => {
    if (e.isTrusted) {
      e.preventDefault();
      navigate(link.dataset.view);
    }
  });
});

// ── Remote mode toggle ────────────────────────────────────────────────────────
const remoteCheck   = document.getElementById('remoteMode');
const remoteOptions = document.getElementById('remoteOptions');

remoteCheck.addEventListener('change', () => {
  remoteOptions.style.display = remoteCheck.checked ? 'flex' : 'none';
});

// ── Session control ───────────────────────────────────────────────────────────
const btnStart     = document.getElementById('btnStart');
const btnStop      = document.getElementById('btnStop');
const sessionDot   = document.getElementById('sessionDot');
const sessionLabel = document.getElementById('sessionLabel');
const atrDisplay   = document.getElementById('atrDisplay');

// One field takes either a pairing string or a plain host:port, so the
// operator does not have to pick a mode before knowing what they were given.
const remoteLink      = document.getElementById('remoteLink');
const remoteLinkBadge = document.getElementById('remoteLinkBadge');

function parseRemoteLink(raw) {
  const v = (raw || '').trim();
  if (!v) return { kind: 'none' };
  if (v.startsWith('atrium1:')) return { kind: 'paired', pairing: v };
  const m = v.match(/^\[?([^\]]+?)\]?(?::(\d+))?$/);
  if (!m) return { kind: 'invalid' };
  return { kind: 'plain', host: m[1], port: parseInt(m[2] || '7654', 10) };
}

function refreshLinkBadge() {
  const { kind } = parseRemoteLink(remoteLink?.value);
  if (!remoteLinkBadge) return;
  const label = { none: 'no link', paired: 'encrypted + pinned',
                  plain: 'plaintext — tunnel only', invalid: 'unreadable' }[kind];
  remoteLinkBadge.textContent = label;
  remoteLinkBadge.className = `link-badge link-badge--${kind}`;
}
remoteLink?.addEventListener('input', refreshLinkBadge);
refreshLinkBadge();

btnStart.addEventListener('click', async () => {
  const readerIndex = currentReader();
  const remote      = remoteCheck.checked;
  const link        = parseRemoteLink(remoteLink?.value);

  if (remote && link.kind === 'none') {
    alert('Remote mode needs a pairing string from the card host (atrium pair), '
        + 'or a host:port reachable over a tunnel.');
    return;
  }
  if (remote && link.kind === 'invalid') {
    alert('Could not read that as a pairing string or a host:port.');
    return;
  }

  const res = await API.post('/api/session/start', {
    reader_index: readerIndex,
    remote,
    pairing:     link.kind === 'paired' ? link.pairing : null,
    remote_host: link.kind === 'plain'  ? link.host : '127.0.0.1',
    remote_port: link.kind === 'plain'  ? link.port : 7654,
  });

  if (res.ok) {
    setSessionState(true);
  } else {
    alert(res.error || 'Failed to start session');
  }
});

btnStop.addEventListener('click', async () => {
  await API.post('/api/session/stop', {});   // also cascades agent stop server-side
  setSessionState(false);
});

function setSessionState(active) {
  btnStart.disabled  = active;
  btnStop.disabled   = !active;
  sessionDot.className        = 'status-dot' + (active ? ' active' : '');
  sessionLabel.textContent    = active ? 'Session active' : 'No session';
  // The bar carries its own "ATR" chip — repeating it here rendered
  // "ATR  ATR: —" and pushed the value past the right edge.
  if (!active) atrDisplay.textContent = '—';
}

// Poll session status every 3 s
setInterval(async () => {
  try {
    const s = await API.get('/api/session/status');
    setSessionState(s.active);
    if (s.atr) atrDisplay.textContent = s.atr;
    if (s.error) {
      sessionDot.classList.add('error');
      sessionLabel.textContent = 'Error';
    }
  } catch (_) { /* server not running */ }
}, 3000);
