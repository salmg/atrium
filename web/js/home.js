/* ─── home.js — Mission Control pipeline: live stage state ─── */

const byId = id => document.getElementById(id);

// ── Navigation from stage buttons and stepper nodes ──────────────────────────
document.querySelectorAll('[data-goto]').forEach(btn => {
  btn.addEventListener('click', () => navigate(btn.dataset.goto));
});

document.querySelectorAll('.stepper-node[data-view]').forEach(node => {
  const go = () => navigate(node.dataset.view);
  node.addEventListener('click', go);
  node.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); }
  });
});

// Stage action buttons delegate to the existing toolbar / view controls
byId('stageStartBtn')?.addEventListener('click', () => byId('btnStart').click());

byId('stageScanBtn')?.addEventListener('click', () => {
  navigate('profile');
  byId('btnScanCard')?.click();
});

byId('btnRefreshPipeline')?.addEventListener('click', refreshPipeline);

// ── Helpers ──────────────────────────────────────────────────────────────────
function setText(id, value, dim = false) {
  const el = byId(id);
  if (!el) return;
  el.textContent = value;
  el.classList.toggle('dim', dim);
}

function setPill(id, text, variant) {
  const el = byId(id);
  if (!el) return;
  el.textContent = text;
  el.className   = `pill pill--${variant}`;
}

/** state: 'locked' | 'active' | 'done' */
function setStage(n, state) {
  const card = byId(`stage${n}`);
  if (card) {
    card.classList.remove('stage-card--locked', 'stage-card--active', 'stage-card--done');
    card.classList.add(`stage-card--${state === 'locked' ? 'locked' : state}`);
  }
  const node = document.querySelector(`.stepper-node[data-stage="${n}"]`);
  if (node) {
    node.classList.remove('stepper-node--active', 'stepper-node--done');
    if (state === 'active') node.classList.add('stepper-node--active');
    if (state === 'done')   node.classList.add('stepper-node--done');
  }
}

function setStat(key, { value, sub, dot }) {
  setText(`stat${key}Value`, value);
  setText(`stat${key}Sub`, sub);
  const dotEl  = byId(`stat${key}Dot`);
  const tileEl = byId(`stat${key}Tile`);
  if (dotEl)  dotEl.className  = 'stat-dot' + (dot ? ` stat-dot--${dot}` : '');
  if (tileEl) {
    tileEl.classList.toggle('stat-tile--live', dot === 'live');
    tileEl.classList.toggle('stat-tile--warn', dot === 'warn');
  }
}

const jget = url => API.get(url).catch(() => null);

// ── Pipeline refresh ─────────────────────────────────────────────────────────
async function refreshPipeline() {
  const [session, simtrace, devices, profile, mutCfg, logs, cards, agent, llm] = await Promise.all([
    jget('/api/session/status'),
    jget('/api/simtrace/status'),
    jget('/api/simtrace/devices'),
    jget('/api/fingerprint'),
    jget('/api/mutations/config'),
    jget('/api/logs'),
    jget('/api/intel/cards'),
    jget('/api/agent/status'),
    jget('/api/agent/providers'),
  ]);

  // ── Stage 1 — Hardware ─────────────────────────────────────────────────────
  const devList     = devices?.devices || [];
  const daemonUp    = !!simtrace?.running;
  const readerEl = byId('readerIndex');
  const readerName = readerEl?.selectedOptions?.[0]?.textContent?.trim() || '—';

  setText('roDevice', devList.length ? devList.map(d => d.usb_path).join(', ') : 'Not detected',
          !devList.length);
  setText('roDaemon', daemonUp ? `Running (PID ${simtrace.pid})` : 'Not started', !daemonUp);
  setText('roReader', readerName);

  const hwReady = devList.length > 0;
  if (daemonUp)      { setStage(1, 'done');   setPill('stage1Pill', 'Running', 'done'); }
  else if (hwReady)  { setStage(1, 'active'); setPill('stage1Pill', 'Ready', 'active'); }
  else               { setStage(1, 'active'); setPill('stage1Pill', 'No device', 'warn'); }

  // ── Stage 2 — Relay session ────────────────────────────────────────────────
  const active = !!session?.active;
  const hasErr = !!session?.error;

  setText('roSession', hasErr ? 'Error' : active ? 'Active' : 'Stopped', !active && !hasErr);
  setText('roAtr', session?.atr || '—', !session?.atr);

  if (hasErr)      { setStage(2, 'active'); setPill('stage2Pill', 'Error', 'error'); }
  else if (active) { setStage(2, 'done');   setPill('stage2Pill', 'Live', 'done'); }
  else             { setStage(2, 'active'); setPill('stage2Pill', 'Ready', 'active'); }

  const startBtn = byId('stageStartBtn');
  if (startBtn) {
    startBtn.disabled    = active;
    startBtn.textContent = active ? 'Session Running' : 'Start Session';
  }

  setStat('Relay', {
    value: hasErr ? 'Error' : active ? 'Live' : 'Offline',
    sub:   hasErr ? (session.error || '').slice(0, 48)
                  : active ? 'Relaying APDUs' : 'No session',
    dot:   hasErr ? 'warn' : active ? 'live' : null,
  });

  // ── Stage 3 — Fingerprint ──────────────────────────────────────────────────
  const data  = profile?.ok ? (profile.data || {}) : {};
  const hasProfile = Object.keys(data).length > 0;
  const profiles   = data.profiles || [];
  const aidSet     = new Set([
    ...(data.aids_from_pse  || []),
    ...(data.aids_from_ppse || []),
    ...profiles.map(p => p.aid).filter(Boolean),
  ]);
  const nAids  = aidSet.size;
  const scheme = profiles.find(p => p.label)?.label || (hasProfile ? 'Unknown scheme' : '—');

  setText('roAids', nAids ? String(nAids) : (hasProfile ? '—' : 'Not scanned'), !hasProfile);
  setText('roScheme', hasProfile ? scheme : '—', !hasProfile);

  if (hasProfile)   { setStage(3, 'done');   setPill('stage3Pill', 'Profiled', 'done'); }
  else if (active)  { setStage(3, 'active'); setPill('stage3Pill', 'Ready', 'active'); }
  else              { setStage(3, 'locked'); setPill('stage3Pill', 'Needs session', 'idle'); }

  setStat('Card', {
    value: hasProfile ? (nAids ? `${nAids} AID${nAids === 1 ? '' : 's'}` : 'Profiled') : '—',
    sub:   hasProfile ? scheme : 'Not fingerprinted',
    dot:   hasProfile ? 'live' : null,
  });

  // ── Stage 4 — Attack surface ───────────────────────────────────────────────
  const yaml       = mutCfg?.content || '';
  // Anchored at column 0: rule-level "enabled:" lines are indented, and
  // matching one of those reported the engine as armed while it was off.
  const engineOn   = /^enabled:\s*true/mi.test(yaml);
  const ruleCount  = (yaml.match(/^\s*-\s+(tag|target|type|mode|sfi):/gmi) || []).length;

  setText('roRules', String(ruleCount), ruleCount === 0);
  setText('roEngine', engineOn ? 'Enabled' : 'Disabled', !engineOn);

  if (engineOn && ruleCount) { setStage(4, 'done');   setPill('stage4Pill', 'Armed', 'done'); }
  else if (hasProfile)       { setStage(4, 'active'); setPill('stage4Pill', 'Ready', 'active'); }
  else                       { setStage(4, 'locked'); setPill('stage4Pill', 'Needs profile', 'idle'); }

  setStat('Mut', {
    value: String(ruleCount),
    sub:   engineOn ? (ruleCount ? 'Engine armed' : 'Engine on, no rules') : 'Engine disabled',
    dot:   engineOn && ruleCount ? 'warn' : null,
  });

  // ── Stage 5 — AI agent ─────────────────────────────────────────────────────
  const agentRunning = !!agent?.active;
  const llmReady     = llm?.agent_available !== false;   // absent API => assume ok
  const backEnd      = llm?.active && llm.active !== 'none' ? llm.active : null;

  setText('roAgent', agentRunning ? 'Running' : (llmReady ? 'Idle' : 'No model'), !agentRunning);
  setText('roBackend', backEnd || 'Not configured', !backEnd);

  if (!llmReady)         { setStage(5, 'locked'); setPill('stage5Pill', 'Needs model', 'warn'); }
  else if (agentRunning) { setStage(5, 'active'); setPill('stage5Pill', 'Running', 'active'); }
  else if (active)       { setStage(5, 'active'); setPill('stage5Pill', 'Ready', 'active'); }
  else                   { setStage(5, 'locked'); setPill('stage5Pill', 'Optional', 'idle'); }

  setStat('Agent', {
    value: !llmReady ? 'No model' : (agentRunning ? 'Running' : 'Idle'),
    sub:   !llmReady ? 'Set an API key or local URL'
                     : (agentRunning ? (agent.status || 'Probing card')
                                     : `${backEnd} \u00b7 optional`),
    dot:   !llmReady ? 'warn' : (agentRunning ? 'busy' : null),
  });

  // ── Stage 6 — Results ──────────────────────────────────────────────────────
  const nLogs  = (logs?.data  || []).length;
  const nCards = (cards?.data || []).length;

  setText('roLogs', String(nLogs), nLogs === 0);
  setText('roCards', String(nCards), nCards === 0);

  if (nLogs || nCards) { setStage(6, 'done');   setPill('stage6Pill', `${nLogs} capture${nLogs === 1 ? '' : 's'}`, 'done'); }
  else                 { setStage(6, 'locked'); setPill('stage6Pill', 'No data yet', 'idle'); }
}

// ── Poll only while the home view is visible ─────────────────────────────────
const homeVisible = () => byId('view-home')?.classList.contains('active');

refreshPipeline();
setInterval(() => { if (homeVisible()) refreshPipeline(); }, 4000);
