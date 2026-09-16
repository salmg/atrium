/* ─── readers.js — name the readers, and pick the right one ───

   A reader used to be a number typed into a box. That is fine until vpcd is
   running, at which point the virtual reader usually takes index 0 — and the
   virtual reader is ATRIUM's own output side, the thing presenting a card to
   the terminal, not a slot a card goes in. Selecting it looks like a card
   fault rather than a wiring mistake, so the picker names every reader, says
   what kind it is, and defaults to the one a card is actually likely to be in. */

const readerSelect = document.getElementById('readerIndex');
const readerHint   = document.getElementById('readerHint');
const btnRescan    = document.getElementById('btnReaderRescan');

/* The selected reader index, or null for "let the server pick". Callers used
   to parseInt() a number box; an empty <select> would give them NaN. */
function currentReader() {
  const raw = readerSelect?.value;
  if (raw === undefined || raw === null || raw === '') return null;
  const n = parseInt(raw, 10);
  return Number.isNaN(n) ? null : n;
}
window.currentReader = currentReader;

const READER_BADGE = {
  virtual:     'virtual',
  contact:     'contact',
  contactless: 'contactless',
  unknown:     '',
};

function setReaderHint(text, tone = '') {
  if (!readerHint) return;
  readerHint.textContent = text || '';
  // The bar clips this to one line, so the whole sentence has to be reachable.
  readerHint.title = text || '';
  readerHint.className = 'reader-hint' + (tone ? ` reader-hint--${tone}` : '');
}

async function refreshReaders({ keepSelection = true } = {}) {
  if (!readerSelect) return;
  const previous = keepSelection ? readerSelect.value : '';

  let res;
  try {
    res = await API.get('/api/readers');
  } catch {
    return;                       // server not up; leave whatever is shown
  }

  readerSelect.innerHTML = '';

  if (!res.readers || !res.readers.length) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = '— no reader —';
    readerSelect.appendChild(opt);
    setReaderHint(res.problem || 'No PC/SC readers found.', 'warn');
    return;
  }

  res.readers.forEach(r => {
    const opt = document.createElement('option');
    opt.value = String(r.index);
    const badge = READER_BADGE[r.kind] || r.kind;
    opt.textContent = badge ? `${r.name}  ·  ${badge}` : r.name;
    readerSelect.appendChild(opt);
  });

  // Keep an explicit choice; otherwise take the server's recommendation.
  const stillThere = previous !== '' &&
    [...readerSelect.options].some(o => o.value === previous);
  readerSelect.value = stillThere ? previous
                     : (res.default != null ? String(res.default) : '');

  describeSelection(res);
}

function describeSelection(res) {
  const chosen = res.readers.find(r => String(r.index) === readerSelect.value);
  if (!chosen) { setReaderHint(''); return; }

  if (res.only_virtual) {
    setReaderHint('Only the virtual reader is present — that is ATRIUM’s own '
                + 'output side, so there is nowhere for a card to be. Plug one in.', 'warn');
  } else if (chosen.virtual) {
    setReaderHint('This is ATRIUM’s own output side, not a card slot.', 'warn');
  } else if (chosen.pn532) {
    setReaderHint('PN532-based — the Contactless view can read cards with it, or emulate one.', '');
  } else {
    setReaderHint('');
  }
}

readerSelect?.addEventListener('change', async () => {
  try {
    describeSelection(await API.get('/api/readers'));
  } catch { /* ignore */ }
});

btnRescan?.addEventListener('click', () => refreshReaders({ keepSelection: false }));

refreshReaders();
