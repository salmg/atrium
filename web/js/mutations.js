/* ─── mutations.js — mutation engine UI ─── */

const btnRunMutations = document.getElementById('btnRunMutations');
const mutRules        = document.getElementById('mutRules');
const mutationResults = document.getElementById('mutationResults');
const mutYamlEditor   = document.getElementById('mutYamlEditor');
const mutEditorMsg    = document.getElementById('mutEditorMsg');
const btnSaveYaml     = document.getElementById('btnSaveYaml');

// ── Tab routing ───────────────────────────────────────────────────────────────

const _tabs = document.querySelectorAll('.mut-tab');
const _panes = {
  rules:   document.getElementById('mutTab-rules'),
  editor:  document.getElementById('mutTab-editor'),
  results: document.getElementById('mutTab-results'),
};

_tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    _tabs.forEach(t => t.classList.remove('mut-tab--active'));
    tab.classList.add('mut-tab--active');
    const name = tab.dataset.tab;
    Object.entries(_panes).forEach(([k, el]) => el.hidden = (k !== name));
    if (name === 'editor') loadYamlEditor();
    if (name === 'results') pollResults();
  });
});

// ── Load on view activation ───────────────────────────────────────────────────

document.querySelector('[data-view="mutations"]').addEventListener('click', loadRules);

// ── Section metadata ──────────────────────────────────────────────────────────

const SECTIONS = [
  { key: 'pdol_mutations',     label: 'PDOL Field Mutations',    icon: '↑' },
  { key: 'afl_mutations',      label: 'AFL Mutations',            icon: '📂' },
  { key: 'dol_mutations',      label: 'DOL Mutations (CDOL)',     icon: '🔗' },
  { key: 'response_mutations', label: 'Response TLV Mutations',  icon: '↓' },
  { key: 'injected_commands',  label: 'Injected Commands',        icon: '💉' },
];

// ── Rule display helpers ──────────────────────────────────────────────────────

function ruleTitle(section, rule) {
  if (rule.comment) return rule.comment;
  if (rule.tag)        return `Tag ${rule.tag}`;
  if (rule.target_tag) return `DOL ${rule.target_tag} → ${rule.mode} ${rule.field_tag || ''}`;
  if (rule.mode)       return `Mode: ${rule.mode}`;
  if (rule.apdu)       return `Inject ${rule.apdu}`;
  return 'Rule';
}

function ruleMeta(rule) {
  const parts = [];
  if (rule.tag)         parts.push(`<span class="mut-badge">tag ${rule.tag}</span>`);
  if (rule.target_tag)  parts.push(`<span class="mut-badge">DOL ${rule.target_tag}</span>`);
  if (rule.mode)        parts.push(`<span class="mut-badge">${rule.mode}</span>`);
  if (rule.value)       parts.push(`<span class="mut-badge mono">${rule.value}</span>`);
  if (rule.trigger_ins) parts.push(`<span class="mut-badge">INS ${rule.trigger_ins}</span>`);
  if (rule.apdu)        parts.push(`<span class="mut-badge mono">${rule.apdu}</span>`);
  if (rule.when)        parts.push(`<span class="mut-badge">${rule.when}</span>`);
  if (rule.truncate_to != null) parts.push(`<span class="mut-badge">keep ${rule.truncate_to}</span>`);
  if (rule.target_sfi  != null) parts.push(`<span class="mut-badge">SFI ${rule.target_sfi}</span>`);
  return parts.join('');
}

// ── Load and render rules ─────────────────────────────────────────────────────

async function loadRules() {
  mutRules.innerHTML = '<span class="text-dim">Loading…</span>';
  try {
    const res = await API.get('/api/mutations');
    if (!res.ok) {
      mutRules.innerHTML = `<p class="text-dim">${escHtml(res.error || 'Failed to load mutations')}</p>`;
      return;
    }
    renderRules(res.rules || {});
  } catch {
    mutRules.innerHTML = '<p class="text-dim">Server unreachable</p>';
  }
}

function renderRules(config) {
  const enabledCount = SECTIONS.reduce((n, s) => {
    const arr = config[s.key] || [];
    return n + arr.filter(r => r.enabled).length;
  }, 0);

  let html = `<div class="mut-status-bar">
    <span class="text-dim">${enabledCount} rule${enabledCount !== 1 ? 's' : ''} active</span>
  </div>`;

  for (const { key, label } of SECTIONS) {
    const rules = config[key] || [];
    if (!rules.length) continue;
    const activeInSection = rules.filter(r => r.enabled).length;

    html += `<div class="mut-section">
      <div class="mut-section-head">
        <span class="mut-section-label">${escHtml(label)}</span>
        <span class="text-dim" style="font-size:11px">${activeInSection}/${rules.length} active</span>
      </div>
      <div class="mut-rule-list">`;

    rules.forEach((rule, idx) => {
      const on = !!rule.enabled;
      html += `
        <div class="mut-rule ${on ? 'mut-rule--on' : ''}" data-section="${key}" data-index="${idx}">
          <label class="mut-toggle" title="${on ? 'Disable' : 'Enable'} rule">
            <input type="checkbox" class="mut-toggle-input" ${on ? 'checked' : ''}
              data-section="${escHtml(key)}" data-index="${idx}">
            <span class="mut-toggle-track"></span>
          </label>
          <div class="mut-rule-body">
            <div class="mut-rule-title">${escHtml(ruleTitle(key, rule))}</div>
            <div class="mut-rule-meta">${ruleMeta(rule)}</div>
          </div>
        </div>`;
    });

    html += `</div></div>`;
  }

  mutRules.innerHTML = html;

  // Wire toggles
  mutRules.querySelectorAll('.mut-toggle-input').forEach(cb => {
    cb.addEventListener('change', async () => {
      const section = cb.dataset.section;
      const index   = parseInt(cb.dataset.index, 10);
      const enabled = cb.checked;
      const row     = cb.closest('.mut-rule');

      cb.disabled = true;
      const res = await API.post('/api/mutations/rule', { section, index, enabled }, 'PATCH');
      cb.disabled = false;

      if (res.ok) {
        row.classList.toggle('mut-rule--on', enabled);
        // Refresh status bar count
        const totalOn = mutRules.querySelectorAll('.mut-toggle-input:checked').length;
        const bar = mutRules.querySelector('.mut-status-bar');
        if (bar) bar.innerHTML = `<span class="text-dim">${totalOn} rule${totalOn !== 1 ? 's' : ''} active</span>`;
        // Refresh section count
        const sectionEl = row.closest('.mut-section');
        if (sectionEl) {
          const sOn = sectionEl.querySelectorAll('.mut-toggle-input:checked').length;
          const sTotal = sectionEl.querySelectorAll('.mut-toggle-input').length;
          const counter = sectionEl.querySelector('.mut-section-head .text-dim');
          if (counter) counter.textContent = `${sOn}/${sTotal} active`;
        }
      } else {
        cb.checked = !enabled; // revert
        alert(res.error || 'Failed to update rule');
      }
    });
  });
}

// ── YAML Editor ───────────────────────────────────────────────────────────────

async function loadYamlEditor() {
  if (mutYamlEditor.dataset.loaded) return;
  const res = await API.get('/api/mutations/config');
  if (res.ok) {
    mutYamlEditor.value = res.content;
    mutYamlEditor.dataset.loaded = '1';
  }
}

btnSaveYaml.addEventListener('click', async () => {
  mutEditorMsg.textContent = '';
  mutEditorMsg.className = 'pb-msg';
  const res = await API.post('/api/mutations/config', { content: mutYamlEditor.value }, 'PUT');
  if (res.ok) {
    mutEditorMsg.textContent = '✓ Saved';
    mutEditorMsg.className = 'pb-msg pb-msg-ok';
    // Force reload of rules tab on next visit
    delete mutYamlEditor.dataset.loaded;
  } else {
    mutEditorMsg.textContent = res.error || 'Save failed';
    mutEditorMsg.className = 'pb-msg pb-msg-error';
  }
});

// Invalidate editor cache when rules are toggled so it reloads fresh YAML
function _invalidateEditorCache() {
  delete mutYamlEditor.dataset.loaded;
}

// ── Run + Results ─────────────────────────────────────────────────────────────

btnRunMutations.addEventListener('click', async () => {
  // Switch to results tab
  _tabs.forEach(t => t.classList.remove('mut-tab--active'));
  const resultsTab = document.querySelector('.mut-tab[data-tab="results"]');
  if (resultsTab) resultsTab.classList.add('mut-tab--active');
  Object.entries(_panes).forEach(([k, el]) => el.hidden = (k !== 'results'));

  btnRunMutations.disabled = true;
  btnRunMutations.textContent = 'Running…';
  mutationResults.innerHTML = '<span class="text-dim">Running mutations…</span>';

  try {
    const res = await API.post('/api/mutations/run', {});
    if (!res.ok) {
      mutationResults.innerHTML = `<p class="text-dim">${escHtml(res.error || 'Run failed')}</p>`;
    } else {
      pollResults();
    }
  } finally {
    btnRunMutations.disabled = false;
    btnRunMutations.textContent = 'Run All Mutations';
  }
});

async function pollResults() {
  const res = await API.get('/api/mutations/results');
  if (res.ok) renderResults(res.results);
}

function renderResults(results) {
  if (!results || !results.length) {
    mutationResults.innerHTML = '<p class="text-dim">No results yet — run mutations during an active relay session.</p>';
    return;
  }
  mutationResults.innerHTML = results.map(r => `
    <div class="result-item ${escHtml(r.status || 'skip')}">
      <strong>${escHtml(r.name || 'Unknown')}</strong>
      <span class="text-dim"> — ${escHtml(r.status || '')}</span>
      ${r.detail ? `<br><span>${escHtml(r.detail)}</span>` : ''}
    </div>
  `).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
