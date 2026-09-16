/* ─── nfc.js — contactless view: one ACR122U reads, another presents ───

   A relay needs two readers doing opposite jobs: one holds the card, the other
   goes into target mode and answers as one. With two ACR122Us the PC/SC names
   are identical apart from a trailing index, so "which one is which" is the
   question this view exists to answer — hence two named pickers that cannot
   both land on the same device, a Detect step that proves the card side before
   the emulator is armed, and a server-side suggestion for the assignment. */

const nfcHero      = document.getElementById('nfcHero');
const nfcHeroDot   = document.getElementById('nfcHeroDot');
const nfcHeroLabel = document.getElementById('nfcHeroLabel');
const nfcHeroSub   = document.getElementById('nfcHeroSub');

const btnNfcRescan = document.getElementById('btnNfcRescan');
const btnNfcProbe  = document.getElementById('btnNfcProbe');
const nfcChip      = document.getElementById('nfcChip');

const nfcCardSource      = document.getElementById('nfcCardSource');
const nfcCardReaderField = document.getElementById('nfcCardReaderField');
const nfcCardReader      = document.getElementById('nfcCardReader');
const nfcCaptureField    = document.getElementById('nfcCaptureField');
const nfcCapture         = document.getElementById('nfcCapture');
const nfcStrictField     = document.getElementById('nfcStrictField');
const nfcStrict          = document.getElementById('nfcStrict');
const nfcPairingField    = document.getElementById('nfcPairingField');
const nfcPairing         = document.getElementById('nfcPairing');
const nfcGateHostField   = document.getElementById('nfcGateHostField');
const nfcGateHost        = document.getElementById('nfcGateHost');
const nfcGateSessionField = document.getElementById('nfcGateSessionField');
const nfcGateSession     = document.getElementById('nfcGateSession');

const btnNfcDetect     = document.getElementById('btnNfcDetect');
const nfcUid           = document.getElementById('nfcUid');
const nfcAts           = document.getElementById('nfcAts');
const nfcAnswerLabel   = document.getElementById('nfcAnswerLabel');
const nfcCardReadout   = document.getElementById('nfcCardReadout');
const nfcScanMsg       = document.getElementById('nfcScanMsg');

const nfcReader = document.getElementById('nfcReader');

const btnNfcIdentifyCard = document.getElementById('btnNfcIdentifyCard');
const btnNfcIdentifyEmu  = document.getElementById('btnNfcIdentifyEmu');
const nfcCardWhere       = document.getElementById('nfcCardWhere');
const nfcEmuWhere        = document.getElementById('nfcEmuWhere');

const nfcOwnIsoDep      = document.getElementById('nfcOwnIsoDep');
const nfcPrefetch       = document.getElementById('nfcPrefetch');
const nfcIsoDepFields   = document.getElementById('nfcIsoDepFields');
const nfcFwi            = document.getElementById('nfcFwi');
const nfcWtxm           = document.getElementById('nfcWtxm');

const btnNfcEmulate     = document.getElementById('btnNfcEmulate');
const btnNfcEmulateStop = document.getElementById('btnNfcEmulateStop');
const nfcMutate         = document.getElementById('nfcMutate');
const nfcMutateHint     = document.getElementById('nfcMutateHint');
const nfcEmuMsg         = document.getElementById('nfcEmuMsg');

const nfcStep1 = document.getElementById('nfcStep1');
const nfcStep2 = document.getElementById('nfcStep2');
const nfcStep3 = document.getElementById('nfcStep3');

// ── state ────────────────────────────────────────────────────────────────────
let _emulating   = false;
let _cardDetected = false;
let _autoAssigned = false;   // the suggestion is applied once, not every poll

// ── helpers ──────────────────────────────────────────────────────────────────
function nfcMsg(el, text, bad = false) {
  el.textContent = text || '';
  el.className   = 'pb-msg' + (text ? (bad ? ' pb-msg-error' : ' pb-msg-ok') : '');
}

/** Repopulate a <select> from readers, keeping the current pick when it survives. */
function fillReaders(select, readers, emptyLabel) {
  const previous = select.value;
  select.innerHTML = '';

  if (!readers.length) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = emptyLabel;
    select.appendChild(opt);
    return;
  }

  readers.forEach(r => {
    const opt = document.createElement('option');
    // Value is the index: it is the only unambiguous handle when two ACR122Us
    // report the same PC/SC name. The name rides along for the clash check,
    // because that is what actually collides.
    opt.value = String(r.index);
    opt.dataset.name = r.name;
    opt.dataset.where = r.where || '';
    opt.dataset.pn532 = r.pn532 ? '1' : '';
    opt.textContent = `${r.index}: ${r.name}${r.kind && r.kind !== 'unknown' ? `  (${r.kind})` : ''}`;
    select.appendChild(opt);
  });

  if (previous && [...select.options].some(o => o.value === previous)) {
    select.value = previous;
  }
}

/** The PC/SC name behind a picker's current selection. */
const selectedName = select => select.selectedOptions?.[0]?.dataset?.name || '';

/** Only an ACR122 has an LED this can blink. */
const selectedIsPn532 = select => select.selectedOptions?.[0]?.dataset?.pn532 === '1';

/** Where that reader physically is, when the driver said. */
const selectedWhere = select => select.selectedOptions?.[0]?.dataset?.where || '';

function paintLocations() {
  nfcCardWhere.textContent = selectedWhere(nfcCardReader);
  nfcEmuWhere.textContent  = selectedWhere(nfcReader);
}

const cardIsReader = () => nfcCardSource.value === 'local';

// ── status ───────────────────────────────────────────────────────────────────
function renderStatus(res) {
  const all       = res.all_readers || [];
  const emulators = res.emulators   || [];
  const cards     = all.filter(r => !r.virtual);

  fillReaders(nfcReader, emulators, '— no ACR122U found —');
  fillReaders(nfcCardReader, cards, '— no reader found —');

  // Apply the server's suggested assignment once, so a two-reader rig is set
  // up correctly on arrival and the operator only overrides it deliberately.
  const hint = res.suggested || {};
  if (!_autoAssigned && hint.emulator != null) {
    const byIndex = (select, index) => {
      const match = [...select.options].find(o => o.value === String(index));
      if (match) select.value = match.value;
    };
    byIndex(nfcReader, hint.emulator_index);
    if (hint.card_index != null) byIndex(nfcCardReader, hint.card_index);
    _autoAssigned = true;
  }

  _emulating = !!res.emulating;
  nfcHero.classList.toggle('status-banner--active', _emulating);
  nfcHeroDot.className = _emulating
    ? 'status-banner-dot status-banner-dot--active'
    : 'status-banner-dot';

  if (_emulating) {
    const n = res.exchanges || 0;
    nfcHeroLabel.textContent = res.mutating ? 'Emulating — playbook applied' : 'Emulating a card';
    // Nothing relayed yet is the state that most looks like a failure. The
    // reader holds target mode open about five seconds at a time and re-arms,
    // so saying how many windows have gone by is the difference between
    // "broken" and "listening, present the terminal".
    let sub;
    if (!n && res.arm_attempts) {
      sub = `Listening — re-armed ${res.arm_attempts}\u00d7, nobody there yet. `
          + 'Hold the reader to a terminal.';
    } else if (!n) {
      sub = 'Armed — hold the reader to a terminal.';
    } else {
      sub = `${n} APDU pair${n === 1 ? '' : 's'} relayed — hold the reader to a terminal`;
    }
    if (res.oversize) {
      sub += ` · ${res.oversize} mutated response${res.oversize === 1 ? '' : 's'} too long for one exchange, relayed unmutated`;
    }
    if (res.sessions > 1) {
      sub += ` · ${res.sessions} terminal sessions (it let go and came back)`;
    }
    if (res.split_responses) {
      sub += ` · ${res.split_responses} long answer${res.split_responses === 1 ? '' : 's'}`
           + ' offered as 61 XX for the terminal to collect';
    }
    if (res.undeliverable) {
      sub += ` · ${res.undeliverable} response${res.undeliverable === 1 ? '' : 's'}`
           + ' too big for the reader to carry — the terminal got 6F00';
    }
    if (res.silent_activations) {
      sub += ` · ${res.silent_activations} selected us and asked nothing`;
    }
    if (res.reactivations) {
      sub += ` · card re-activated ${res.reactivations}\u00d7 (the reader keeps`
           + ' dropping it — each reset it to the master file)';
    }
    if (res.prefetch_hits) {
      sub += ` · ${res.prefetch_hits} answered from the warm-up`;
    }
    if (res.wtx_requests) {
      sub += ` · asked for more time ${res.wtx_requests}\u00d7`;
    }
    if (res.chained_out) {
      sub += ` · ${res.chained_out} response${res.chained_out === 1 ? '' : 's'} chained`;
    }
    nfcHeroSub.textContent = sub;
  } else if (res.error) {
    nfcHeroLabel.textContent = 'Emulation stopped';
    nfcHeroSub.textContent   = res.error;
  } else if (!emulators.length) {
    nfcHeroLabel.textContent = 'No ACR122U';
    nfcHeroSub.textContent   = res.problem || 'Emulation needs an ACR122U on USB.';
  } else if (hint.why) {
    nfcHeroLabel.textContent = 'One reader';
    nfcHeroSub.textContent   = hint.why;
  } else {
    nfcHeroLabel.textContent = 'Ready';
    nfcHeroSub.textContent   = 'Detect the card, probe the chip, then start.';
  }

  syncSteps();
}

/**
 * Reflect what is possible right now.
 *
 * Two readers doing different jobs is the whole setup, so the one arrangement
 * that cannot work — the same device on both sides — is called out where the
 * choice is made rather than left to fail as a timeout at the terminal.
 */
function syncSteps() {
  // Compared by PC/SC name, not by index: the name is what ACR122Link resolves
  // with, so two entries sharing one really are the same device as far as this
  // can address it.
  const clash = cardIsReader()
             && nfcCardReader.value !== ''
             && selectedName(nfcCardReader) === selectedName(nfcReader);

  nfcCardReaderField.classList.toggle('nfc-same-reader', !!clash);
  nfcStep1.classList.toggle('nfc-step--done', _cardDetected && !clash);
  nfcStep2.classList.toggle('nfc-step--blocked', !nfcReader.value);
  nfcStep3.classList.toggle('nfc-step--blocked', !nfcReader.value || !!clash);

  if (clash) {
    nfcMsg(nfcScanMsg,
           'That is the reader presenting the emulated card — it cannot also hold '
           + 'the card being relayed. Pick a different one, or relay to a capture.',
           true);
  } else if (!_cardDetected) {
    nfcMsg(nfcScanMsg, '');
  }

  paintLocations();
  btnNfcIdentifyCard.disabled = _emulating || !cardIsReader()
                             || !nfcCardReader.value || !selectedIsPn532(nfcCardReader);
  btnNfcIdentifyCard.title = selectedIsPn532(nfcCardReader)
    ? "Blink this reader's LED"
    : 'Only an ACR122 has an LED to blink';
  btnNfcIdentifyEmu.disabled  = _emulating || !nfcReader.value;

  btnNfcEmulate.style.display     = _emulating ? 'none' : '';
  btnNfcEmulateStop.style.display = _emulating ? '' : 'none';
  btnNfcEmulate.disabled = !!clash || !nfcReader.value;
  btnNfcDetect.disabled  = _emulating || !cardIsReader() || !nfcCardReader.value;
  btnNfcProbe.disabled   = _emulating || !nfcReader.value;
  nfcCardReadout.style.display = cardIsReader() ? '' : 'none';
}

async function refreshNfc({ probe = false, details = false } = {}) {
  const params = new URLSearchParams();
  // Locations cost a direct connection per reader, so they ride along with the
  // deliberate actions — arriving, rescanning — and never with the poll.
  if (details) params.set('details', 'true');
  if (probe) {
    params.set('probe_chip', 'true');
    if (nfcReader.value) params.set('reader', selectedName(nfcReader));
  }
  try {
    const res = await API.get('/api/nfc/status' + (params.toString() ? `?${params}` : ''));
    if (!res.ok) return;
    renderStatus(res);
    if (probe) {
      nfcChip.textContent = res.chip
        ? `${res.chip.reader}\nchip ${res.chip.chip}   firmware ${res.chip.version}`
        : (res.chip_error || 'No answer from the chip.');
    }
  } catch { /* server unreachable */ }
}

// ── which playbook the checkbox would apply ──────────────────────────────────
async function refreshActivePlaybook() {
  try {
    const res = await API.get('/api/playbooks/active');
    const name = res?.active ? res.active.replace(/_/g, ' ') : null;
    if (!res?.engine_enabled) {
      nfcMutateHint.textContent = '— the engine is disarmed; arm it under Playbooks first';
    } else if (name) {
      nfcMutateHint.textContent = `— ${name} is active and will run on this relay`;
    } else {
      nfcMutateHint.textContent = '— mutations.yaml runs on this relay, same as the contact path';
    }
  } catch { /* leave the default wording */ }
}

// ── captures ─────────────────────────────────────────────────────────────────
let _capturesLoaded = false;

async function loadCaptures() {
  if (_capturesLoaded) return;
  try {
    const res  = await API.get('/api/nfc/captures');
    const list = res.captures || [];
    nfcCapture.innerHTML = '';
    if (!list.length) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '— nothing in logs/ to replay —';
      nfcCapture.appendChild(opt);
    } else {
      list.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.name;
        opt.textContent = `${c.name}  (${Math.max(1, Math.round(c.size / 1024))} KB)`;
        nfcCapture.appendChild(opt);
      });
    }
    _capturesLoaded = true;
  } catch { /* server unreachable */ }
}

function syncCardSource() {
  const kind = nfcCardSource.value;
  nfcCardReaderField.style.display  = kind === 'local'    ? '' : 'none';
  nfcCaptureField.style.display     = kind === 'file'     ? '' : 'none';
  nfcStrictField.style.display      = kind === 'file'     ? '' : 'none';
  nfcPairingField.style.display     = kind === 'remote'   ? '' : 'none';
  nfcGateHostField.style.display    = kind === 'nfcgate'  ? '' : 'none';
  nfcGateSessionField.style.display = kind === 'nfcgate'  ? '' : 'none';
  if (kind === 'file') loadCaptures();
  // Only a card in one of our own readers is something to detect from here.
  // The phone announces its tag when emulation starts, not before.
  _cardDetected = kind !== 'local';
  syncSteps();
}

/** "host", "host:port" or blank → what the API wants. */
function nfcGateTarget() {
  const raw = nfcGateHost.value.trim() || '127.0.0.1';
  const at = raw.lastIndexOf(':');
  if (at > 0 && !raw.slice(at + 1).includes(']')) {
    const port = parseInt(raw.slice(at + 1), 10);
    if (Number.isFinite(port)) return { host: raw.slice(0, at), port };
  }
  return { host: raw, port: 5566 };
}

// ── actions ──────────────────────────────────────────────────────────────────
document.querySelector('[data-view="nfc"]').addEventListener('click', () => {
  refreshNfc({ details: true });
  refreshActivePlaybook();
  syncCardSource();
});

btnNfcRescan.addEventListener('click', () => {
  _autoAssigned = false;
  refreshNfc({ details: true });
});
nfcCardSource.addEventListener('change', syncCardSource);
nfcOwnIsoDep.addEventListener('change', () => {
  nfcIsoDepFields.style.display = nfcOwnIsoDep.checked ? '' : 'none';
});
nfcCardReader.addEventListener('change', () => { _cardDetected = false; syncSteps(); });
nfcReader.addEventListener('change', syncSteps);

// ── identify ─────────────────────────────────────────────────────────────────
async function identify(select, button, msgEl) {
  const name = selectedName(select);
  if (!name) return;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'Blinking…';
  try {
    const res = await API.post('/api/nfc/identify', { reader: name });
    nfcMsg(msgEl,
           res.ok ? `Blinking ${res.reader}${res.where ? ` · ${res.where}` : ''} — `
                    + 'the reader that lit up is this one.'
                  : (res.error || 'Could not blink that reader'),
           !res.ok);
  } catch {
    nfcMsg(msgEl, 'Server unreachable', true);
  } finally {
    button.textContent = original;
    syncSteps();
  }
}

btnNfcIdentifyCard.addEventListener('click', () => identify(nfcCardReader, btnNfcIdentifyCard, nfcScanMsg));
btnNfcIdentifyEmu.addEventListener('click', () => identify(nfcReader, btnNfcIdentifyEmu, nfcEmuMsg));

btnNfcProbe.addEventListener('click', async () => {
  nfcChip.textContent = 'Probing…';
  await refreshNfc({ probe: true });
});

btnNfcDetect.addEventListener('click', async () => {
  nfcMsg(nfcScanMsg, '');
  btnNfcDetect.disabled = true;
  try {
    const res = await API.post('/api/nfc/detect-card',
                               { reader: parseInt(nfcCardReader.value, 10) });
    if (res.ok) {
      nfcUid.textContent = res.uid || '—';
      nfcAts.textContent = res.answer || '(none)';
      nfcAnswerLabel.textContent = res.answer_kind || 'ATS';
      _cardDetected = true;
      nfcMsg(nfcScanMsg, `${res.interface} card found on ${res.reader}.`);
    } else {
      nfcUid.textContent = nfcAts.textContent = '—';
      _cardDetected = false;
      nfcMsg(nfcScanMsg, res.error || 'No card found', true);
    }
  } catch {
    nfcMsg(nfcScanMsg, 'Server unreachable', true);
  } finally {
    syncSteps();
  }
});

btnNfcEmulate.addEventListener('click', async () => {
  const kind = nfcCardSource.value;
  const body = {
    reader: selectedName(nfcReader) || null,
    remote: kind === 'remote',
    mutate: nfcMutate.checked,
    prefetch: nfcPrefetch.checked,
  };

  if (nfcOwnIsoDep.checked) {
    const wtxm = parseInt(nfcWtxm.value, 10);
    if (!(wtxm >= 1 && wtxm <= 59)) {
      nfcMsg(nfcEmuMsg, 'Each extension has to ask for between 1 and 59 frame '
                        + 'waiting times.', true);
      return;
    }
    body.own_isodep = true;
    body.fwi        = parseInt(nfcFwi.value, 10);
    body.wtxm       = wtxm;
  }

  if (kind === 'nfcgate') {
    const session = parseInt(nfcGateSession.value, 10);
    if (!(session >= 1 && session <= 255)) {
      nfcMsg(nfcEmuMsg, 'The NFCGate session number has to be between 1 and 255.', true);
      return;
    }
    const target = nfcGateTarget();
    body.nfcgate         = true;
    body.nfcgate_host    = target.host;
    body.nfcgate_port    = target.port;
    body.nfcgate_session = session;
  } else if (kind === 'remote') {
    const pairing = nfcPairing.value.trim();
    if (!pairing) { nfcMsg(nfcEmuMsg, 'A pairing string is needed for a remote card.', true); return; }
    body.pairing = pairing;
  } else if (kind === 'file') {
    if (!nfcCapture.value) { nfcMsg(nfcEmuMsg, 'Pick a capture to replay.', true); return; }
    body.from_file     = nfcCapture.value;
    body.strict_replay = nfcStrict.value === 'strict';
  } else {
    if (!nfcCardReader.value) { nfcMsg(nfcEmuMsg, 'Pick the reader holding the card.', true); return; }
    body.card_reader = parseInt(nfcCardReader.value, 10);
  }

  nfcMsg(nfcEmuMsg, 'Arming…');
  try {
    const res = await API.post('/api/nfc/emulate/start', body);
    nfcMsg(nfcEmuMsg,
           res.ok ? `Presenting a card on ${res.reader}, relaying to ${res.relaying_to}`
                    + `${res.mutating ? ', playbook applied' : ''}. `
                    + 'Hold it to a terminal — pairs appear in the Live Trace.'
                  : (res.error || res.detail || 'Could not start'),
           !res.ok);
  } catch {
    nfcMsg(nfcEmuMsg, 'Server unreachable', true);
  }
  refreshNfc();
});

btnNfcEmulateStop.addEventListener('click', async () => {
  try {
    const res = await API.post('/api/nfc/emulate/stop', {});
    nfcMsg(nfcEmuMsg, res.ok ? 'Stopped.' : (res.error || 'Could not stop'), !res.ok);
  } catch {
    nfcMsg(nfcEmuMsg, 'Server unreachable', true);
  }
  refreshNfc();
});

// ── poll while the view is open ──────────────────────────────────────────────
const nfcViewActive = () => document.getElementById('view-nfc')?.classList.contains('active');
setInterval(() => { if (nfcViewActive()) refreshNfc(); }, 3000);
