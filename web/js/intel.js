/* ─── intel.js — card intelligence browser (CardIntelDB) ─── */

const intelQuery  = document.getElementById('intelQuery');
const btnSearch   = document.getElementById('btnIntelSearch');
const intelResult = document.getElementById('intelResult');

let _allCards = [];

document.querySelector('[data-view="intel"]').addEventListener('click', loadCards);

btnSearch.addEventListener('click', doSearch);
intelQuery.addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });
intelQuery.addEventListener('input', () => {
  const q = intelQuery.value.trim().toLowerCase();
  if (!q) { renderCardList(_allCards); return; }
  const filtered = _allCards.filter(c =>
    c.fingerprint_hash.toLowerCase().includes(q) ||
    (c.aids || []).some(a => a.toLowerCase().includes(q))
  );
  if (filtered.length) renderCardList(filtered);
});

// ── list all cards ────────────────────────────────────────────────────────────

async function loadCards() {
  intelResult.innerHTML = '<span class="text-dim">Loading…</span>';
  try {
    const res = await API.get('/api/intel/cards');
    if (!res.ok) {
      intelResult.textContent = res.detail || 'Error loading cards';
      return;
    }
    _allCards = res.data || [];
    if (!_allCards.length) {
      intelResult.innerHTML = '<span class="text-dim">No cards recorded yet — run a scan or relay session to fingerprint a card.</span>';
      return;
    }
    renderCardList(_allCards);
  } catch {
    intelResult.textContent = 'Server unreachable';
  }
}

// ── search / detail ───────────────────────────────────────────────────────────

async function doSearch() {
  const q = intelQuery.value.trim();
  if (!q) { loadCards(); return; }

  intelResult.innerHTML = '<span class="text-dim">Looking up…</span>';
  try {
    const res = await API.get(`/api/intel/card/${encodeURIComponent(q)}`);
    if (!res.ok) {
      intelResult.textContent = res.detail || 'Not found';
      return;
    }
    renderCardDetail(res.data);
  } catch {
    intelResult.textContent = 'Server unreachable';
  }
}

// ── delete card ───────────────────────────────────────────────────────────────

async function deleteCard(fingerprint_hash, e) {
  e.stopPropagation();
  if (!confirm('Delete this card record and ALL its attack history? This cannot be undone.')) return;
  const res = await API.del(`/api/intel/card/${encodeURIComponent(fingerprint_hash.slice(0, 16))}`);
  if (res.ok) {
    _allCards = _allCards.filter(c => c.fingerprint_hash !== fingerprint_hash);
    renderCardList(_allCards);
    if (!_allCards.length) {
      intelResult.innerHTML = '<span class="text-dim">No cards recorded yet — run a scan or relay session to fingerprint a card.</span>';
    }
  } else {
    alert(res.detail || 'Delete failed');
  }
}

// ── delete attack ─────────────────────────────────────────────────────────────

async function deleteAttack(attackId, rowEl) {
  if (!confirm('Delete this attack record? The agent will treat this attack as untried.')) return;
  const res = await API.del(`/api/intel/attack/${attackId}`);
  if (res.ok) {
    rowEl.remove();
  } else {
    alert(res.detail || 'Delete failed');
  }
}

// ── card list renderer ────────────────────────────────────────────────────────

function renderCardList(cards) {
  if (!cards.length) {
    intelResult.innerHTML = '<span class="text-dim">No cards match the filter.</span>';
    return;
  }

  intelResult.innerHTML = cards.map(c => {
    const shortHash = c.fingerprint_hash.slice(0, 20) + '…';
    const aids = (c.aids || []).join(', ') || '—';
    const attacks = Object.entries(c.attacks_run || {})
      .map(([k, v]) => `<span class="intel-tag intel-tag-${k}">${v} ${k}</span>`)
      .join(' ');
    return `
      <div class="intel-card" data-hash="${escHtml(c.fingerprint_hash)}">
        <div class="intel-card-top">
          <span class="intel-hash mono">${escHtml(shortHash)}</span>
          <div class="intel-card-actions">
            <span class="intel-seen">Seen ${c.times_seen}×</span>
            <button class="btn btn-ghost btn-sm intel-del-btn" data-hash="${escHtml(c.fingerprint_hash)}" title="Delete card record">✕</button>
          </div>
        </div>
        <div class="intel-card-meta">
          <span class="intel-label">AIDs</span>
          <span class="mono">${escHtml(aids)}</span>
        </div>
        <div class="intel-card-meta">
          <span class="intel-label">AIP</span>
          <span class="mono">${escHtml(c.aip || '—')}</span>
        </div>
        ${attacks ? `<div class="intel-attacks">${attacks}</div>` : ''}
      </div>
    `;
  }).join('');

  intelResult.querySelectorAll('.intel-card').forEach(card => {
    card.addEventListener('click', e => {
      if (e.target.closest('.intel-del-btn')) return;
      intelQuery.value = card.dataset.hash.slice(0, 16);
      doSearch();
    });
  });

  intelResult.querySelectorAll('.intel-del-btn').forEach(btn => {
    btn.addEventListener('click', e => deleteCard(btn.dataset.hash, e));
  });
}

// ── card detail renderer ──────────────────────────────────────────────────────

function renderCardDetail(data) {
  const card = data.card;
  if (!card) {
    intelResult.textContent = 'Card not found in database.';
    return;
  }

  const rows = (entries) => entries.map(([k, v]) =>
    `<div class="intel-row"><span class="intel-label">${escHtml(k)}</span><span class="mono">${escHtml(String(v ?? '—'))}</span></div>`
  ).join('');

  const attackList = (names) =>
    names.length ? names.map(n => `<code class="intel-atk">${escHtml(n)}</code>`).join(' ') : '<span class="text-dim">—</span>';

  const historyRows = data.attack_history.map(a => `
    <div class="intel-history-row" data-attack-id="${a.id}">
      <span class="intel-atk intel-atk-${a.result}">${escHtml(a.attack_name)}</span>
      <span class="intel-hist-result intel-tag-${a.result}">${escHtml(a.result)}</span>
      <span class="text-dim mono" style="font-size:11px">${new Date(a.ts).toLocaleString()}</span>
      ${a.notes ? `<span class="text-dim" style="font-size:11px">${escHtml(a.notes)}</span>` : ''}
      <button class="btn btn-ghost btn-sm intel-del-atk-btn" data-id="${a.id}" title="Delete this attack record">✕</button>
    </div>
  `).join('');

  intelResult.innerHTML = `
    <div class="intel-detail-header">
      <button class="btn btn-ghost btn-sm" id="btnIntelBack">← Back to list</button>
      <button class="btn btn-ghost btn-sm intel-del-card-btn" data-hash="${escHtml(card.fingerprint_hash)}">Delete card</button>
    </div>

    <div class="intel-section-title">Card Record</div>
    <div class="intel-detail-grid">
      ${rows([
        ['Hash',         card.fingerprint_hash],
        ['First seen',   new Date(card.first_seen_ts).toLocaleString()],
        ['Last seen',    new Date(card.last_seen_ts).toLocaleString()],
        ['Times seen',   card.times_seen],
        ['AIDs',         (card.aids || []).join(', ') || '—'],
        ['AIP',          card.aip || '—'],
        ['AIP Flags',    (card.aip_flags || []).join(', ') || '—'],
        ['PDOL Tags',    (card.pdol_tags || []).join(' ') || '—'],
        ['CDOL1 Tags',   (card.cdol1_tags || []).join(' ') || '—'],
        ['CDOL2 Tags',   (card.cdol2_tags || []).join(' ') || '—'],
        ['Service Code', card.service_code || '—'],
        ['PIN Retry',    card.pin_retry || '—'],
        ['ATC (first)',  card.atc_first || '—'],
        ['ATC (last)',   card.atc_last || '—'],
      ])}
    </div>

    <div class="intel-section-title" style="margin-top:16px">Attack Intelligence</div>
    <div class="intel-detail-grid">
      <div class="intel-row"><span class="intel-label">Succeeded</span><span>${attackList(data.succeeded)}</span></div>
      <div class="intel-row"><span class="intel-label">Partial</span><span>${attackList(data.partial)}</span></div>
      <div class="intel-row"><span class="intel-label">Failed</span><span>${attackList(data.failed)}</span></div>
      <div class="intel-row"><span class="intel-label">Untried</span><span>${attackList(data.untried)}</span></div>
      <div class="intel-row"><span class="intel-label">Recommended</span><span>${attackList(data.recommended)}</span></div>
    </div>

    ${data.attack_history.length ? `
      <div class="intel-section-title" style="margin-top:16px">Attack History (${data.attack_history.length})</div>
      <div class="intel-history">${historyRows}</div>
    ` : ''}

    <div class="intel-section-title" style="margin-top:16px">Add Note</div>
    <div class="intel-note-form">
      <textarea id="intelNoteText" class="intel-note-input" rows="2"
        placeholder="Write a note about this card…"></textarea>
      <button id="btnAddNote" class="btn btn-primary btn-sm">Add Note</button>
    </div>
    <p id="intelNoteMsg" class="pb-msg"></p>
  `;

  document.getElementById('btnIntelBack').addEventListener('click', () => {
    intelQuery.value = '';
    loadCards();
  });

  intelResult.querySelector('.intel-del-card-btn').addEventListener('click', async (e) => {
    if (!confirm('Delete this card record and ALL its attack history? This cannot be undone.')) return;
    const hash = card.fingerprint_hash;
    const res = await API.del(`/api/intel/card/${encodeURIComponent(hash.slice(0, 16))}`);
    if (res.ok) {
      _allCards = _allCards.filter(c => c.fingerprint_hash !== hash);
      intelQuery.value = '';
      loadCards();
    } else {
      alert(res.detail || 'Delete failed');
    }
  });

  intelResult.querySelectorAll('.intel-del-atk-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const row = btn.closest('.intel-history-row');
      deleteAttack(parseInt(btn.dataset.id, 10), row);
    });
  });

  document.getElementById('btnAddNote').addEventListener('click', async () => {
    const note = document.getElementById('intelNoteText').value.trim();
    const msg  = document.getElementById('intelNoteMsg');
    if (!note) { msg.textContent = 'Enter a note first.'; msg.className = 'pb-msg pb-msg-error'; return; }
    const hash = card.fingerprint_hash.slice(0, 16);
    const res  = await API.post(`/api/intel/card/${encodeURIComponent(hash)}/note`, { note });
    if (res.ok) {
      document.getElementById('intelNoteText').value = '';
      msg.textContent = '✓ Note saved.';
      msg.className   = 'pb-msg pb-msg-ok';
    } else {
      msg.textContent = res.detail || 'Failed to save note.';
      msg.className   = 'pb-msg pb-msg-error';
    }
  });
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
