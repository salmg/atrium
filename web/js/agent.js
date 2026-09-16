/* ─── agent.js — AI agent panel: start, stop, stream, status ─── */

const agentLog       = document.getElementById('agentLog');
const btnStartAgent  = document.getElementById('btnStartAgent');
const btnStopAgent   = document.getElementById('btnStopAgent');
const agentTask      = document.getElementById('agentTask');
const agentModel     = document.getElementById('agentModel');
const agentProvider  = document.getElementById('agentProvider');
const agentModelCustom = document.getElementById('agentModelCustom');
const agentSetup     = document.getElementById('agentSetup');
const agentSetupTitle = document.getElementById('agentSetupTitle');
const agentSetupText = document.getElementById('agentSetupText');
const agentBruteSfi  = document.getElementById('agentBruteSfi');
const agentSysExtra  = document.getElementById('agentSystemExtra');
const agentViewDot   = document.getElementById('agentViewDot');
const agentViewStatus = document.getElementById('agentViewStatus');

// ── Start ─────────────────────────────────────────────────────────────────────
btnStartAgent.addEventListener('click', async () => {
  const task        = agentTask.value.trim() || null;
  // A typed model id wins over the dropdown; empty means "provider default"
  const model       = agentModelCustom.value.trim() || agentModel.value || null;
  const provider    = agentProvider.value || null;
  const bruteSfi    = agentBruteSfi.checked;
  const systemExtra = agentSysExtra.value.trim() || null;
  const readerIndex = currentReader();

  const res = await API.post('/api/agent/start', {
    reader_index: readerIndex,
    task,
    model,
    provider,
    brute_sfi:    bruteSfi,
    system_extra: systemExtra,
  });

  if (!res.ok) {
    appendAgentLine('error', res.error || 'Failed to start agent');
    if (res.needs_setup) showSetup(res.error);
    return;
  }
  appendAgentLine('text', `▶ Agent started  [model: ${model || 'provider default'}${bruteSfi ? '  brute-sfi: on' : ''}]\n`);
  setAgentRunning(true);
});

// ── Stop ──────────────────────────────────────────────────────────────────────
btnStopAgent.addEventListener('click', async () => {
  await API.post('/api/agent/stop', {});
  appendAgentLine('text', '⏹ Stop requested — finishing current operation…\n');
  btnStopAgent.disabled = true;
});

// ── WebSocket stream ──────────────────────────────────────────────────────────
(function connectAgentStream() {
  const ws = new WebSocket(`ws://${location.host}/ws/agent`);

  ws.onmessage = (evt) => {
    let event;
    try { event = JSON.parse(evt.data); } catch { return; }
    handleAgentEvent(event);
  };

  ws.onclose = () => setTimeout(connectAgentStream, 2000);
})();

function handleAgentEvent(event) {
  switch (event.type) {
    case 'text':
      appendAgentLine('text', event.text);
      break;
    case 'tool':
      appendAgentLine('tool', `⚙ ${event.name}(${JSON.stringify(event.input || {})})`);
      break;
    case 'done':
      appendAgentLine('done', '✓ Agent session complete');
      setAgentRunning(false);
      break;
    case 'error':
      appendAgentLine('error', '✗ ' + event.message);
      setAgentRunning(false);
      break;
  }
}

// ── State helpers ─────────────────────────────────────────────────────────────
function setAgentRunning(running) {
  btnStartAgent.disabled = running;
  btnStopAgent.disabled  = !running;
  agentViewDot.className  = 'status-dot' + (running ? ' active' : '');
  agentViewStatus.textContent = running
    ? 'Agent running — relay and agent are independent; you can stop either separately'
    : 'Idle — relay runs independently, agent is optional';

  // Sidebar status card
  const card = document.getElementById('agentStatusCard');
  const dot  = document.getElementById('agentDot');
  const lbl  = document.getElementById('agentLabel');
  const hint = document.getElementById('agentHint');
  if (card) {
    card.style.display = running ? 'flex' : 'none';
    if (dot) dot.className = 'status-dot agent-dot' + (running ? ' active' : '');
    if (lbl) lbl.textContent = running ? 'Agent running' : 'Agent idle';
    if (hint) hint.textContent = running ? 'Click Stop Agent to cancel' : 'AI research agent';
  }
}

// ── Poll agent status every 3 s (catches external resets / errors) ────────────
setInterval(async () => {
  try {
    const s = await API.get('/api/agent/status');
    const running = s.active || s.status === 'running';
    setAgentRunning(running);
    if (s.status === 'stopping') {
      agentViewStatus.textContent = 'Stopping — waiting for current operation to finish…';
    }
  } catch (_) { /* server not running */ }
}, 3000);

function appendAgentLine(cls, text) {
  const span = document.createElement('span');
  span.className   = `agent-${cls}`;
  span.textContent = text + '\n';
  agentLog.appendChild(span);
  agentLog.scrollTop = agentLog.scrollHeight;
}


// ── Provider discovery ───────────────────────────────────────────────────────
let _providerInfo = null;

function showSetup(message) {
  agentSetupText.textContent = message || '';
  agentSetup.hidden = false;
  btnStartAgent.disabled = true;
}

function hideSetup() {
  agentSetup.hidden = true;
  btnStartAgent.disabled = false;
}

function fillModelChoices(providerId) {
  const info = _providerInfo?.providers?.find(p => p.id === providerId);
  agentModel.innerHTML = '';

  const dflt = document.createElement('option');
  dflt.value = '';
  dflt.textContent = info?.default_model
    ? `Provider default (${info.default_model})`
    : 'Provider default';
  agentModel.appendChild(dflt);

  (info?.models || []).forEach(m => {
    const o = document.createElement('option');
    o.value = m; o.textContent = m;
    agentModel.appendChild(o);
  });

  // A local server with no discoverable models needs a typed id
  const needsTyping = providerId === 'local' && !(info?.models || []).length;
  agentModelCustom.placeholder = needsTyping
    ? 'model id required, e.g. qwen2.5:14b'
    : 'or type a model id…';
}

async function loadProviders() {
  let info;
  try {
    info = await API.get('/api/agent/providers');
  } catch {
    return;
  }
  _providerInfo = info;

  // Back-end picker: auto-detect plus every configured provider
  const prev = agentProvider.value;
  agentProvider.innerHTML = '';
  const auto = document.createElement('option');
  auto.value = '';
  auto.textContent = info.agent_available
    ? `Auto-detect (${info.active})`
    : 'Auto-detect';
  agentProvider.appendChild(auto);

  (info.providers || []).forEach(p => {
    const o = document.createElement('option');
    o.value = p.id;
    o.textContent = p.configured ? p.label : `${p.label} — not configured`;
    o.disabled = !p.configured;
    agentProvider.appendChild(o);
  });
  if (prev && [...agentProvider.options].some(o => o.value === prev && !o.disabled)) {
    agentProvider.value = prev;
  }

  fillModelChoices(agentProvider.value || info.active);

  if (info.agent_available) {
    hideSetup();
  } else {
    agentSetupTitle.textContent = 'No language model configured';
    showSetup(
      'The agent needs a model back end. Everything else in ATRIUM — relay,\n' +
      'fingerprinting, mutations, logs and card intel — works without one.\n\n' +
      'Set one of these in the environment, then restart the server:\n\n' +
      '  ANTHROPIC_API_KEY=sk-ant-...          Claude\n' +
      '  OPENAI_API_KEY=sk-...                 OpenAI\n' +
      '  ATRIUM_LLM_BASE_URL=http://localhost:11434/v1\n' +
      '  ATRIUM_LLM_MODEL=llama3.1             local model (Ollama, LM Studio, vLLM)'
    );
  }
}

agentProvider.addEventListener('change', () => fillModelChoices(agentProvider.value || _providerInfo?.active));

document.querySelector('[data-view="agent"]').addEventListener('click', loadProviders);
loadProviders();
