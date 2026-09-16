/* ─── host.js — ISO 8583 host layer: proxy, captures, replay, cryptograms ───

   The CLI stays the primary interface for this half of the toolkit. This view
   exists so an operator already watching a card session can drive the link
   above it without changing terminals.

   Two things it deliberately does not make easy: starting a mutating proxy or
   a replay without confirming, and supplying an issuer master key. The first
   goes through a confirm dialog; the second is server-side configuration only,
   because a key sent from a browser ends up in logs and history. */

const hostEls = id => document.getElementById(id);

const hostHero      = hostEls('hostHero');
const hostHeroDot   = hostEls('hostHeroDot');
const hostHeroLabel = hostEls('hostHeroLabel');
const hostHeroSub   = hostEls('hostHeroSub');

let hostCatalogue = { dialects: [], playbooks: [], profiles: [], captures: [],
                      imk_configured: false };

// ── Tabs ──────────────────────────────────────────────────────────────────────
document.querySelectorAll('[data-host-tab]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-host-tab]').forEach(b =>
      b.classList.toggle('host-tab--active', b === btn));
    document.querySelectorAll('.host-panel').forEach(p =>
      p.classList.toggle('host-panel--active',
        p.id === `hostPanel-${btn.dataset.hostTab}`));
  });
});

// ── Catalogue ─────────────────────────────────────────────────────────────────
function fillSelect(el, items, { valueKey = 'name', label = null, blank = null } = {}) {
  if (!el) return;
  const previous = el.value;
  el.innerHTML = '';
  if (blank !== null) {
    const opt = document.createElement('option');
    opt.value = ''; opt.textContent = blank;
    el.appendChild(opt);
  }
  items.forEach(item => {
    const opt = document.createElement('option');
    opt.value = item[valueKey];
    opt.textContent = label ? label(item) : item[valueKey];
    el.appendChild(opt);
  });
  if (previous && [...el.options].some(o => o.value === previous)) el.value = previous;
}

async function loadHostCatalogue() {
  try {
    const res = await API.get('/api/host/catalogue');
    if (!res.ok) return;
    hostCatalogue = res;

    fillSelect(hostEls('hostDialect'), res.dialects,
      { label: d => `${d.name} — ${d.fields} fields${d.tpdu ? ', TPDU' : ''}` });
    fillSelect(hostEls('hostPlaybook'), res.playbooks,
      { label: p => `${p.name} (${p.rules})` });
    fillSelect(hostEls('hostReplayPlaybook'), res.playbooks,
      { label: p => `${p.name} (${p.rules})`, blank: '— none —' });
    fillSelect(hostEls('hostProfile'), res.profiles,
      { label: p => `${p.name} — ${p.tags} tags, ${p.session_key}` });

    ['hostCapturePick', 'hostReplayCapture', 'hostVerifyCapture'].forEach(id =>
      fillSelect(hostEls(id), res.captures,
        { label: c => `${c.name}  (${(c.size / 1024).toFixed(1)} kB)`,
          blank: res.captures.length ? null : '— no captures yet —' }));

    const warn = hostEls('hostImkWarn');
    warn.textContent = res.imk_configured
      ? ''
      : 'No issuer master key is configured on the server. Set HOST_IMK (or '
      + 'HOST_IMK_FILE) and restart ATRIUM. Keys are deliberately not accepted '
      + 'over this API — one sent from a browser ends up in logs and history.';
    warn.style.display = res.imk_configured ? 'none' : 'block';
  } catch { /* server unreachable */ }
}

// ── Proxy ─────────────────────────────────────────────────────────────────────
const hostMode = hostEls('hostMode');

function syncModeUi() {
  const mutating = hostMode.value === 'mutate';
  hostEls('hostPlaybookField').style.display = mutating ? 'flex' : 'none';
  hostEls('hostMutateWarn').style.display    = mutating ? 'block' : 'none';
}
hostMode.addEventListener('change', syncModeUi);

const splitList = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

hostEls('btnHostProxyStart').addEventListener('click', async () => {
  const mode  = hostMode.value;
  const allow = splitList(hostEls('hostAllow').value);
  const msg   = hostEls('hostProxyMsg');

  if (!hostEls('hostTarget').value.trim()) {
    return setMsg(msg, false, 'A target is required.');
  }
  if (!allow.length) {
    return setMsg(msg, false,
      'The allow-list is required and fails closed — name the target explicitly. '
      + 'It is what stops a typo from opening a link to something out of scope.');
  }
  if (mode === 'mutate' && !confirm(
      'Start a MUTATING proxy?\n\nMessages matching the playbook will be rewritten '
      + 'in flight on a live link. Everything else is forwarded byte for byte.')) {
    return;
  }

  const res = await API.post('/api/host/proxy/start', {
    mode,
    listen:  hostEls('hostListen').value.trim(),
    target:  hostEls('hostTarget').value.trim(),
    allow,
    dialect: hostEls('hostDialect').value,
    playbook: mode === 'mutate' ? hostEls('hostPlaybook').value : null,
    capture: hostEls('hostCapture').value.trim() || null,
    abort_on_live_pan: hostEls('hostAbortLivePan').checked,
    confirm: mode === 'mutate',
  });
  setMsg(msg, res.ok, res.ok ? `Listening on ${res.listen} → ${res.target}` : res.error);
  refreshHostProxy();
});

hostEls('btnHostProxyStop').addEventListener('click', async () => {
  await API.post('/api/host/proxy/stop', {});
  setMsg(hostEls('hostProxyMsg'), true, 'Stopped.');
  refreshHostProxy();
  loadHostCatalogue();
});

function setMsg(el, ok, text) {
  el.textContent = (ok ? '✓ ' : '✗ ') + (text || '');
  el.className = 'pb-msg' + (ok ? ' pb-msg-ok' : ' pb-msg-error');
}

function renderRecord(r) {
  const bits = [`seq=${r.seq}`, r.leg, `mti=${r.mti || '?'}`];
  if (r.rtt_ms != null) bits.push(`${r.rtt_ms}ms`);
  let line = '  ' + bits.join('  ');
  (r.mutations || []).forEach(m =>
    line += `\n      mutated ${m.target} ${m.mode}: ${m.before || '(absent)'} -> ${m.after || '(deleted)'}`);
  (r.discrepancies || []).forEach(d => line += `\n      ** ${d}`);
  (r.warnings || []).forEach(w => line += `\n      ** ${w}`);
  if (r.note) line += `\n      ${r.note}`;
  return line;
}

async function refreshHostProxy() {
  try {
    const res = await API.get('/api/host/proxy/status');
    const running = !!res.running;
    hostEls('btnHostProxyStart').disabled = running;
    hostEls('btnHostProxyStop').disabled  = !running;

    hostHero.classList.toggle('status-banner--active', running);
    hostHeroDot.className = running
      ? 'status-banner-dot status-banner-dot--active' : 'status-banner-dot';
    hostHeroLabel.textContent = running
      ? (res.mode === 'mutate' ? 'Mutating link' : 'Passive link') : 'No link';
    hostHeroSub.textContent = running
      ? `${res.listen} → ${res.target} · ${res.dialect}`
        + (res.playbook ? ` · ${res.playbook}` : '')
      : 'Start a proxy to observe or rewrite a host link';

    const c = res.counts || {};
    hostEls('hostCounts').textContent = running
      ? `${c.messages || 0} messages · ${c.mutations || 0} mutations · ${c.discrepancies || 0} discrepancies`
      : '';

    const live = hostEls('hostLive');
    if (!running) {
      live.textContent = 'No link running.';
    } else if (!res.records.length) {
      live.textContent = 'Waiting for traffic…';
    } else {
      live.textContent = res.records.map(renderRecord).join('\n');
      live.scrollTop = live.scrollHeight;
    }
  } catch { /* ignore */ }
}

// ── Captures ──────────────────────────────────────────────────────────────────
hostEls('hostCapturePick').addEventListener('change', async e => {
  const name = e.target.value;
  const out = hostEls('hostCaptureView');
  if (!name) { out.textContent = 'Select a capture.'; return; }
  const res = await API.get(`/api/host/capture/${encodeURIComponent(name)}?limit=60`);
  if (!res.ok) { out.textContent = '✗ ' + (res.error || 'Could not read it'); return; }
  out.textContent = res.summary + '\n\n' + res.records.map(renderRecord).join('\n');
});

hostEls('btnHostDetect').addEventListener('click', async () => {
  const name = hostEls('hostCapturePick').value;
  const out = hostEls('hostCaptureView');
  if (!name) { out.textContent = 'Pick a capture first.'; return; }
  const res = await API.post('/api/host/detect', { capture: name });
  if (!res.ok) { out.textContent = '✗ ' + res.error; return; }
  out.textContent = 'Ranked dialect candidates:\n'
    + res.candidates.map((c, i) =>
        `  ${i + 1}. ${c.label}  score=${c.score}  ${c.notes.join('; ')}`).join('\n')
    + '\n\nNothing scores 1.0 — dialects differing only in private-use fields are\n'
    + 'genuinely indistinguishable from a plain message.';
});

// ── Replay ────────────────────────────────────────────────────────────────────
let replayPoll = null;

hostEls('btnHostReplay').addEventListener('click', async () => {
  const out = hostEls('hostReplayOut');
  const allow = splitList(hostEls('hostReplayAllow').value);
  if (!hostEls('hostReplayCapture').value) { out.textContent = 'Pick a corpus first.'; return; }
  if (!allow.length) {
    out.textContent = 'The allow-list is required and fails closed — name the target explicitly.';
    return;
  }
  if (!confirm('Run replay?\n\nThis originates transactions against a live host. '
             + 'A corpus captured from a real link will resend real cardholder data.')) return;

  const res = await API.post('/api/host/replay/run', {
    capture:  hostEls('hostReplayCapture').value,
    target:   hostEls('hostReplayTarget').value.trim(),
    allow,
    freshen:  hostEls('hostFreshen').checked,
    resign:   hostEls('hostResign').checked,
    playbook: hostEls('hostReplayPlaybook').value || null,
    profile:  hostEls('hostProfile').value,
    confirm:  true,
  });
  if (!res.ok) { out.textContent = '✗ ' + res.error; return; }

  out.textContent = `Replaying ${res.total} message(s)…`;
  clearInterval(replayPoll);
  replayPoll = setInterval(pollReplay, 700);
});

async function pollReplay() {
  const res = await API.get('/api/host/replay/status');
  const out = hostEls('hostReplayOut');
  const rows = (res.results || []).map(r =>
    `  ${String(r.seq).padEnd(4)} ${(r.mti || '').padEnd(5)} `
    + `${(r.changed ? 'changed' : 'verbatim').padEnd(9)} `
    + `${(r.rc || (r.error ? 'err' : '—')).padEnd(4)} `
    + `${r.rtt_ms != null ? r.rtt_ms + 'ms' : ''}`
    + (r.approved ? '   <-- APPROVED' : '') + (r.error ? '  ' + r.error : ''));

  out.textContent = `  seq  MTI   sent      rc   rtt\n${rows.join('\n')}`
    + (res.running ? `\n\n${res.sent}/${res.total}…` : '')
    + (res.error ? `\n\n✗ ${res.error}` : '')
    + (res.done && res.summary ? `\n\n${res.summary}` : '');

  if (!res.running) clearInterval(replayPoll);
}

// ── Cryptograms ───────────────────────────────────────────────────────────────
hostEls('btnHostVerify').addEventListener('click', async () => {
  const out = hostEls('hostVerifyOut');
  const capture = hostEls('hostVerifyCapture').value;
  if (!capture) { out.textContent = 'Pick a capture first.'; return; }

  out.textContent = 'Verifying…';
  const res = await API.post('/api/host/verify', {
    capture, profile: hostEls('hostProfile').value,
    psn: hostEls('hostPsn').value.trim() || '00',
  });
  if (!res.ok) { out.textContent = '✗ ' + res.error; return; }

  const mark = { verified: '✓', mismatch: '✗', unchecked: '·', skipped: '·', error: '!' };
  out.textContent =
    res.rows.map(r => `  ${mark[r.state] || '?'} seq=${String(r.seq).padEnd(4)} ${r.detail}`).join('\n')
    + `\n\n${res.matched} of ${res.checked} verified (profile ${res.profile}).\n\n${res.advice}`;
});

// ── Activate ──────────────────────────────────────────────────────────────────
document.querySelector('[data-view="host"]').addEventListener('click', () => {
  loadHostCatalogue();
  refreshHostProxy();
  syncModeUi();
});

hostEls('btnHostRefresh').addEventListener('click', () => {
  loadHostCatalogue();
  refreshHostProxy();
});

setInterval(() => {
  if (document.getElementById('view-host')?.classList.contains('active')) {
    refreshHostProxy();
  }
}, 3000);
