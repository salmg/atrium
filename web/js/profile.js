/* ─── profile.js — card fingerprint display ─── */

const profileContent  = document.getElementById('profileContent');
const btnScanCard     = document.getElementById('btnScanCard');
const scanMsg         = document.getElementById('scanMsg');

// Load on view activation
document.querySelector('[data-view="profile"]').addEventListener('click', loadProfile);

async function loadProfile() {
  try {
    const res = await API.get('/api/fingerprint');
    if (!res.ok) {
      profileContent.innerHTML = `
        <div class="profile-empty">
          <p class="text-dim">No fingerprint yet — click <strong>Scan Card</strong> to read the card directly, or run the AI Agent which fingerprints automatically.</p>
        </div>`;
      return;
    }
    renderProfile(res.data);
  } catch {
    profileContent.innerHTML = '<p class="text-dim">Server unreachable</p>';
  }
}

// ── Scan button ───────────────────────────────────────────────────────────────
btnScanCard.addEventListener('click', async () => {
  const readerIndex = currentReader();
  btnScanCard.disabled = true;
  btnScanCard.textContent = 'Scanning…';
  scanMsg.textContent = '';
  profileContent.innerHTML = '<p class="text-dim" style="padding:8px 0">Contacting card…</p>';

  try {
    const res = await API.post('/api/fingerprint/run', {
      reader_index: readerIndex,
      brute_sfi: false,
    });
    if (res.ok) {
      scanMsg.textContent = '';
      renderProfile(res.data);
    } else {
      scanMsg.textContent = res.error || 'Scan failed';
      scanMsg.className = 'pb-msg pb-msg-error';
      profileContent.innerHTML = '<p class="text-dim">Scan failed — is a card inserted?</p>';
    }
  } catch {
    scanMsg.textContent = 'Server unreachable';
    scanMsg.className = 'pb-msg pb-msg-error';
  } finally {
    btnScanCard.disabled = false;
    btnScanCard.textContent = 'Scan Card';
  }
});

// ── Renderer ──────────────────────────────────────────────────────────────────
function renderProfile(data) {
  if (!data) {
    profileContent.innerHTML = '<p class="text-dim">No data</p>';
    return;
  }

  const atr       = data.atr        || '—';
  const hash      = data.fingerprint_hash || '—';
  const reader    = data.reader_name || data.reader || '—';
  const ts        = data.timestamp   ? new Date(data.timestamp).toLocaleString() : '—';
  const pse       = data.pse_present  ? 'Yes' : 'No';
  const ppse      = data.ppse_present ? 'Yes' : 'No';
  const aidsPse   = (data.aids_from_pse  || []).join(', ')  || '—';
  const aidsPpse  = (data.aids_from_ppse || []).join(', ')  || '—';
  const profiles  = data.profiles || [];

  let html = `
    <div class="pf-section">
      <div class="pf-section-title">Card Identity</div>
      <div class="pf-grid">
        ${pf('Fingerprint', hash, 'mono')}
        ${pf('ATR', atr, 'mono')}
        ${pf('Reader', reader)}
        ${pf('Scanned', ts)}
        ${pf('PSE present', pse)}
        ${pf('PPSE present', ppse)}
        ${aidsPse !== '—' ? pf('AIDs (PSE)', aidsPse, 'mono') : ''}
        ${aidsPpse !== '—' ? pf('AIDs (PPSE)', aidsPpse, 'mono') : ''}
      </div>
    </div>`;

  for (const p of profiles) {
    const aipFlags  = (p.aip_flags  || []).join(' · ') || '—';
    const pdolTags  = (p.pdol_entries  || []).map(e => e.tag).join(' ') || '—';
    const cdol1Tags = (p.cdol1_entries || []).map(e => e.tag).join(' ') || '—';
    const cdol2Tags = (p.cdol2_entries || []).map(e => e.tag).join(' ') || '—';
    const offlineAuthRecs = (p.afl_entries || []).reduce((s, e) => s + (e.offline_auth_records || 0), 0);

    const cvmRules = (p.cvm_rules || []).map(r =>
      `<div class="pf-cvm-rule">
        <span class="mono pf-cvm-code">${escHtml(String(r.code ?? ''))}</span>
        <span class="pf-cvm-method">${escHtml(r.code_name || '—')}</span>
        <span class="text-dim pf-cvm-sep">if</span>
        <span class="pf-cvm-cond">${escHtml(r.condition_name || '—')}</span>
        ${r.continue_if_fail ? '<span class="pf-cvm-flag">continue-if-fail</span>' : ''}
      </div>`
    ).join('') || '<span class="text-dim">—</span>';

    const getDataRows = Object.entries(p.get_data || {})
      .filter(([, v]) => v !== null && v !== undefined)
      .map(([tag, val]) => `<div class="pf-row"><span class="pf-label mono">${escHtml(tag)}</span><span class="mono pf-val">${escHtml(String(val))}</span></div>`)
      .join('') || '<span class="text-dim">—</span>';

    const allTagRows = Object.entries(p.all_tags || {})
      .map(([tag, val]) => `<div class="pf-row"><span class="pf-label mono">${escHtml(tag)}</span><span class="mono pf-val">${escHtml(String(val))}</span></div>`)
      .join('') || '<span class="text-dim">—</span>';

    html += `
      <div class="pf-section">
        <div class="pf-section-title">
          <span class="mono">${escHtml(p.aid || '')}</span>
          ${p.label ? `<span class="pf-aid-label">${escHtml(p.label)}</span>` : ''}
        </div>
        <div class="pf-grid">
          ${pf('AIP',          p.aip || '—',     'mono')}
          ${pf('AIP flags',    aipFlags)}
          ${pf('Service code', p.service_code || '—', 'mono')}
          ${pf('Offline auth recs', offlineAuthRecs)}
          ${pf('PDOL tags',    pdolTags,  'mono')}
          ${pf('CDOL1 tags',   cdol1Tags, 'mono')}
          ${pf('CDOL2 tags',   cdol2Tags, 'mono')}
        </div>

        <details class="pf-detail">
          <summary class="pf-detail-summary">CVM Rules (${(p.cvm_rules || []).length})</summary>
          <div class="pf-cvm-list">${cvmRules}</div>
        </details>

        <details class="pf-detail">
          <summary class="pf-detail-summary">GET DATA tags (${Object.values(p.get_data || {}).filter(v => v != null).length})</summary>
          <div class="pf-tag-grid">${getDataRows}</div>
        </details>

        <details class="pf-detail">
          <summary class="pf-detail-summary">All TLV tags (${Object.keys(p.all_tags || {}).length})</summary>
          <div class="pf-tag-grid">${allTagRows}</div>
        </details>
      </div>`;
  }

  if (!profiles.length) {
    html += `<div class="pf-section"><p class="text-dim">No AID profiles captured — card may not have responded to any AID.</p></div>`;
  }

  profileContent.innerHTML = html;
}

function pf(label, value, cls = '') {
  return `<div class="pf-field">
    <div class="pf-field-label">${escHtml(label)}</div>
    <div class="pf-field-value ${cls}">${escHtml(String(value))}</div>
  </div>`;
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
