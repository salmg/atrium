/* ─── playbooks.js — playbook manager + active config editor ───

   "Applying" a playbook copies it over mutations.yaml. That used to be shown
   as a 1.2-second flash on the card, which read as the selection undoing
   itself — there was no persistent notion of which playbook was live at all.

   The active one is now derived by asking the server which saved playbook
   matches mutations.yaml, so it survives a reload and self-corrects: edit the
   active config by hand and no card claims to be active, because none is.

   Applying was also a one-way door: nothing here could turn the mutations back
   off. Deactivating is a separate fact from which playbook is loaded — the
   engine switch below disarms the rules without discarding them, so the same
   playbook can be switched back on without re-applying it. */

const playbookList        = document.getElementById('playbookList');
const pbActiveNote        = document.getElementById('pbActiveNote');
const playbookEditorPanel = document.getElementById('playbookEditorPanel');
const pbEditorName        = document.getElementById('pbEditorName');
const pbEditorContent     = document.getElementById('pbEditorContent');
const pbEditorMsg         = document.getElementById('pbEditorMsg');
const btnNewPlaybook      = document.getElementById('btnNewPlaybook');
const btnEditActive       = document.getElementById('btnEditActive');
const btnSavePb           = document.getElementById('btnSavePb');
const btnApplyPb          = document.getElementById('btnApplyPb');
const btnDeletePb         = document.getElementById('btnDeletePb');
const btnCancelPb         = document.getElementById('btnCancelPb');

const engineBanner   = document.getElementById('engineBanner');
const engineDot      = document.getElementById('engineDot');
const engineLabel    = document.getElementById('engineLabel');
const engineSub      = document.getElementById('engineSub');
const btnEngineToggle = document.getElementById('btnEngineToggle');

// ── state ─────────────────────────────────────────────────────────────────────
let _currentName = null;   // null = new playbook, string = existing name
let _isActiveConfig = false;
let _activeName = null;    // the playbook currently copied into mutations.yaml
let _engineOn = false;     // whether those rules are actually being applied

// ── load on view activation ───────────────────────────────────────────────────
document.querySelector('[data-view="playbooks"]').addEventListener('click', loadPlaybooks);

// ── list ──────────────────────────────────────────────────────────────────────
async function loadPlaybooks() {
  playbookList.innerHTML = '<p class="text-dim" style="padding:4px 0">Loading…</p>';
  try {
    const [res, active] = await Promise.all([
      API.get('/api/playbooks'),
      API.get('/api/playbooks/active').catch(() => ({ active: null })),
    ]);
    if (!res.ok) { playbookList.innerHTML = `<p class="text-dim">${escHtml(res.detail || 'Error')}</p>`; return; }
    _activeName = active?.active ?? null;
    _engineOn   = !!active?.engine_enabled;
    renderEngine();
    renderActiveNote(active?.reason || '');
    renderList(res.data);
  } catch {
    playbookList.innerHTML = '<p class="text-dim">Server unreachable</p>';
  }
}

/** Re-read which playbook is live and repaint the cards, without a full reload. */
async function refreshActive() {
  try {
    const res = await API.get('/api/playbooks/active');
    _activeName = res?.active ?? null;
    _engineOn   = !!res?.engine_enabled;
    renderEngine();
    renderActiveNote(res?.reason || '');
  } catch {
    return;
  }
  playbookList.querySelectorAll('.pb-card').forEach(card => {
    const isActive = card.dataset.name === _activeName;
    card.classList.toggle('pb-card--active', isActive);
    const tag = card.querySelector('.pb-card-active-tag');
    if (tag) {
      tag.style.display = isActive ? '' : 'none';
      tag.textContent   = activeTagText();
    }
    const applyBtn = card.querySelector('.pb-btn-apply');
    if (applyBtn) applyBtn.textContent = isActive ? 'Re-apply' : 'Apply';
  });
}

/** A loaded playbook whose engine is off is loaded, not active — say so. */
function activeTagText() {
  return _engineOn ? 'active' : 'loaded \u00b7 off';
}

function renderEngine() {
  if (!engineBanner) return;
  engineBanner.classList.toggle('status-banner--active', _engineOn);
  engineDot.className = _engineOn
    ? 'status-banner-dot status-banner-dot--active'
    : 'status-banner-dot';
  engineLabel.textContent = _engineOn ? 'Mutation engine armed' : 'Mutation engine disarmed';
  engineSub.textContent = _engineOn
    ? (_activeName
        ? `Applying ${_activeName.replace(/_/g, ' ')} to every matching exchange`
        : 'Applying the rules in mutations.yaml to every matching exchange')
    : 'Rules stay loaded — nothing is being changed on the wire';
  btnEngineToggle.textContent = _engineOn ? 'Deactivate' : 'Activate';
  btnEngineToggle.className   = 'btn btn-sm ' + (_engineOn ? 'btn-ghost' : 'btn-warning');
}

btnEngineToggle?.addEventListener('click', async () => {
  btnEngineToggle.disabled = true;
  try {
    const res = await API.post('/api/playbooks/engine', { enabled: !_engineOn });
    if (res.ok) {
      _engineOn = !!res.enabled;
      renderEngine();
      // The card tags say "active" or "loaded · off"; repaint them too.
      await refreshActive();
    } else {
      engineSub.textContent = res.detail || res.error || 'Could not change the engine state';
    }
  } catch {
    engineSub.textContent = 'Server unreachable';
  } finally {
    btnEngineToggle.disabled = false;
  }
});

/** Why no card is claiming to be active — above the grid, never inside it. */
function renderActiveNote(reason) {
  if (!pbActiveNote) return;
  const show = !_activeName && !!reason;
  pbActiveNote.hidden = !show;
  pbActiveNote.textContent = show ? `No playbook is active — ${reason}.` : '';
}

function renderList(books) {
  if (!books.length) {
    playbookList.innerHTML = '<p class="text-dim" style="padding:4px 0">No playbooks saved yet. Click <strong>New Playbook</strong> to create one.</p>';
    return;
  }

  playbookList.innerHTML = books.map(b => {
    const isActive = b.name === _activeName;
    return `
    <div class="pb-card${isActive ? ' pb-card--active' : ''}" data-name="${escHtml(b.name)}">
      <div class="pb-card-name">
        ${escHtml(b.name.replace(/_/g, ' '))}
        <span class="pb-card-active-tag"${isActive ? '' : ' style="display:none"'}>${activeTagText()}</span>
      </div>
      <div class="pb-card-desc">${escHtml(b.description || '')}</div>
      <div class="pb-card-actions">
        <button class="btn btn-ghost btn-sm pb-btn-edit" data-name="${escHtml(b.name)}">Edit</button>
        <button class="btn btn-soft btn-sm pb-btn-apply" data-name="${escHtml(b.name)}">${isActive ? 'Re-apply' : 'Apply'}</button>
      </div>
    </div>`;
  }).join('');

  playbookList.querySelectorAll('.pb-btn-edit').forEach(btn =>
    btn.addEventListener('click', e => { e.stopPropagation(); openEditor(btn.dataset.name); })
  );
  playbookList.querySelectorAll('.pb-btn-apply').forEach(btn =>
    btn.addEventListener('click', e => { e.stopPropagation(); applyPlaybook(btn.dataset.name); })
  );
}

// ── editor controls ───────────────────────────────────────────────────────────
btnNewPlaybook.addEventListener('click', () => {
  _currentName = null;
  _isActiveConfig = false;
  pbEditorName.value = '';
  pbEditorName.disabled = false;
  pbEditorContent.value = defaultTemplate();
  btnDeletePb.style.display = 'none';
  btnApplyPb.style.display = '';
  showMsg('');
  showEditor();
  pbEditorName.focus();
});

btnEditActive.addEventListener('click', async () => {
  _isActiveConfig = true;
  _currentName = null;
  pbEditorName.value = 'mutations.yaml  (active config)';
  pbEditorName.disabled = true;
  btnDeletePb.style.display = 'none';
  btnApplyPb.style.display = 'none';
  pbEditorContent.value = 'Loading…';
  showEditor();
  try {
    const res = await API.get('/api/mutations/config');
    pbEditorContent.value = res.content || '';
    showMsg('');
  } catch {
    pbEditorContent.value = '';
    showMsg('Could not load mutations.yaml', true);
  }
});

async function openEditor(name) {
  _currentName = name;
  _isActiveConfig = false;
  pbEditorName.value = name;
  pbEditorName.disabled = false;
  pbEditorContent.value = 'Loading…';
  btnDeletePb.style.display = '';
  btnApplyPb.style.display = '';
  showMsg('');
  showEditor();
  try {
    const res = await API.get(`/api/playbooks/${encodeURIComponent(name)}`);
    if (!res.ok) { showMsg(res.detail || 'Failed to load', true); return; }
    pbEditorContent.value = res.content;
  } catch {
    showMsg('Server unreachable', true);
  }
}

btnSavePb.addEventListener('click', async () => {
  const content = pbEditorContent.value;

  if (_isActiveConfig) {
    const res = await API.post('/api/mutations/config', { content }, 'PUT');
    showMsg(res.ok ? 'Active config saved.' : (res.error || 'Save failed'), !res.ok);
    // Hand-editing the live config can stop it matching any playbook.
    if (res.ok) refreshActive();
    return;
  }

  const name = pbEditorName.value.trim();
  if (!name) { showMsg('Enter a name first.', true); return; }

  let res;
  if (_currentName) {
    res = await API.post(`/api/playbooks/${encodeURIComponent(_currentName)}`, { name, content }, 'PUT');
    showMsg(res.ok ? 'Saved.' : (res.detail || 'Save failed'), !res.ok);
  } else {
    res = await API.post('/api/playbooks', { name, content });
    if (res.ok) {
      _currentName = res.name;
      pbEditorName.disabled = false;
      btnDeletePb.style.display = '';
      showMsg('Playbook created.');
      loadPlaybooks();
    } else {
      showMsg(res.detail || 'Create failed', true);
    }
  }
});

btnApplyPb.addEventListener('click', async () => {
  const name = _currentName || pbEditorName.value.trim();
  if (!name) { showMsg('Save the playbook first.', true); return; }
  await applyPlaybook(name);
});

btnDeletePb.addEventListener('click', async () => {
  if (!_currentName) return;
  if (!confirm(`Delete playbook "${_currentName}"?`)) return;
  const res = await API.post(`/api/playbooks/${encodeURIComponent(_currentName)}`, {}, 'DELETE');
  if (res.ok) {
    hideEditor();
    loadPlaybooks();
  } else {
    showMsg(res.detail || 'Delete failed', true);
  }
});

btnCancelPb.addEventListener('click', hideEditor);

// ── apply ──────────────────────────────────────────────────────────────────────
async function applyPlaybook(name) {
  try {
    const res = await API.post(`/api/playbooks/${encodeURIComponent(name)}/apply`, {});
    if (res.ok) {
      showMsg(`✓ ${res.message || 'Applied'}`, false);
      // A brief flash confirms the click landed; the persistent "active" mark
      // is what says which playbook is live, and it is re-derived from the
      // server rather than assumed.
      const card = playbookList.querySelector(`[data-name="${escHtml(name)}"]`);
      if (card) {
        card.classList.add('pb-card-applied');
        setTimeout(() => card.classList.remove('pb-card-applied'), 1200);
      }
      await refreshActive();
    } else {
      showMsg(res.detail || 'Apply failed', true);
    }
  } catch {
    showMsg('Server unreachable', true);
  }
}

// ── helpers ───────────────────────────────────────────────────────────────────
function showEditor() {
  playbookEditorPanel.style.display = 'flex';
  playbookEditorPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideEditor() {
  playbookEditorPanel.style.display = 'none';
  _currentName = null;
  _isActiveConfig = false;
  pbEditorName.disabled = false;
}

function showMsg(text, isError = false) {
  pbEditorMsg.textContent = text;
  pbEditorMsg.className = 'pb-msg' + (isError ? ' pb-msg-error' : ' pb-msg-ok');
}

function defaultTemplate() {
  return `# My Playbook\nenabled: true\nlog_mutations: true\nlog_path: "logs/mutations.jsonl"\n\npdol_mutations: []\nafl_mutations: []\ndol_mutations: []\nresponse_mutations: []\ninjected_commands: []\n`;
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
