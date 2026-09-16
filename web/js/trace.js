/* ─── trace.js — live APDU trace with TLV expansion ───

   Two things this view has to make obvious at a glance:

   * **Which way each APDU went.** A command comes from the terminal; a
     response comes from the card. The pairing was always there, but nothing
     said so, and "cmd"/"resp" is only obvious once you already know.

   * **What a mutation changed.** When a rule rewrites a response, the terminal
     is given bytes the card never sent. Showing only the final value hides the
     single most important fact on the screen, so a touched row is flagged and
     its detail shows the card's own bytes beside what was substituted. */

const traceTable = document.getElementById('traceTable');
const btnClear   = document.getElementById('btnClearTrace');

btnClear.addEventListener('click', () => { traceTable.innerHTML = ''; });

// ── WebSocket connection ──────────────────────────────────────────────────────
(function connectAPDUStream() {
  const ws = new WebSocket(`ws://${location.host}/ws/apdu`);

  ws.onmessage = (evt) => {
    let entry;
    try { entry = JSON.parse(evt.data); } catch { return; }
    appendTraceRow(entry);
  };

  ws.onclose = () => setTimeout(connectAPDUStream, 2000);
})();

// ── Row rendering ─────────────────────────────────────────────────────────────
let rowCount = 0;

function appendTraceRow(entry) {
  const ts   = new Date(entry.ts * 1000).toISOString().slice(11, 23);
  const cmd  = entry.cmd  || '';
  const resp = entry.resp || '';
  const sw   = entry.sw   || resp.slice(-4).toUpperCase();
  const swClass = sw === '9000' ? 'ok' : sw.startsWith('61') ? 'warn' : 'err';

  const mutations = Array.isArray(entry.mutations) ? entry.mutations : [];
  const touched = mutations.filter(m => m.direction === 'command').length;
  const changed = mutations.filter(m => m.direction !== 'command').length;

  rowCount++;
  const row = document.createElement('div');
  row.className = 'trace-row' + (mutations.length ? ' trace-row--mutated' : '');
  row.id = `tr-${rowCount}`;

  row.innerHTML = `
    <div class="trace-cell ts">${ts}</div>
    <div class="trace-cell cmd">${escHtml(cmd)}${badge(touched, 'cmd')}</div>
    <div class="trace-cell resp">${escHtml(resp.slice(0, -4))}${badge(changed, 'resp')}</div>
    <div class="trace-cell sw ${swClass}">${escHtml(sw)}</div>
  `;

  row.addEventListener('click', () => toggleDetail(row, entry));

  // ★ mark button — flag as manually interesting
  const markBtn = document.createElement('button');
  markBtn.className = 'trace-mark-btn';
  markBtn.title = 'Mark as interesting';
  markBtn.textContent = '★';
  markBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    markOutcome(entry, markBtn);
  });
  row.appendChild(markBtn);

  traceTable.appendChild(row);
  traceTable.scrollTop = traceTable.scrollHeight;
}

function badge(count, kind) {
  if (!count) return '';
  const word = count === 1 ? 'mutation' : 'mutations';
  return `<span class="trace-badge trace-badge--${kind}" title="${count} ${word} applied — click the row">`
       + `▲ ${count}</span>`;
}

async function markOutcome(entry, btn) {
  btn.disabled = true;
  btn.style.opacity = '0.4';

  // Try to get the current card fingerprint_hash
  let fpHash = '';
  try {
    const fp = await fetch('/api/fingerprint').then(r => r.json());
    if (fp.ok && fp.data) fpHash = fp.data.fingerprint_hash || '';
  } catch {}

  try {
    const res = await fetch('/api/outcomes/mark', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fingerprint_hash: fpHash,
        session_id:  entry.session_id || '',
        cmd_hex:     entry.cmd  || '',
        cmd_ins:     entry.desc || '',
        resp_hex:    entry.resp || '',
        sw:          entry.sw   || '',
        label:       'manual_interesting',
        notes:       '',
      }),
    });
    const data = await res.json();
    if (data.ok) {
      btn.textContent = '★';
      btn.style.color = 'var(--accent)';
      btn.style.opacity = '1';
      btn.title = 'Marked as interesting';
    } else {
      btn.style.opacity = '1';
      btn.disabled = false;
    }
  } catch {
    btn.style.opacity = '1';
    btn.disabled = false;
  }
}

function toggleDetail(row, entry) {
  const existingDetail = row.nextElementSibling;
  if (existingDetail && existingDetail.classList.contains('trace-detail')) {
    existingDetail.remove();
    return;
  }
  const detail = document.createElement('div');
  detail.className = 'trace-detail';
  detail.textContent = formatAPDUDetail(entry);
  row.after(detail);
}

function formatAPDUDetail(entry) {
  const lines = [];
  lines.push('terminal → card   ' + (entry.cmd || ''));
  if (entry.desc) lines.push('                  ' + entry.desc);
  if (entry.resp) lines.push('card → terminal   ' + entry.resp);
  if (entry.duration_us) lines.push('                  ' + (entry.duration_us / 1000).toFixed(1) + ' ms');

  const mutations = Array.isArray(entry.mutations) ? entry.mutations : [];
  if (mutations.length) lines.push('\n' + formatMutations(mutations));

  if (entry.tlv) lines.push('\nTLV\n' + formatTLV(entry.tlv, 2));
  return lines.join('\n');
}

// ── Mutations ─────────────────────────────────────────────────────────────────
function formatMutations(mutations) {
  const out = ['MUTATIONS APPLIED — the bytes above are not what the card sent'];
  mutations.forEach(m => {
    const where = m.direction === 'command' ? 'terminal → card' : 'card → terminal';
    const what  = m.tag ? `tag ${m.tag}` : (m.mutation_type || 'value');
    out.push(`  ${where}  ${what}  (${m.mode})`);
    // The whole point of this block: the card's own bytes, then the swap.
    out.push(`      card sent : ${m.original_hex || '(absent)'}`);
    out.push(`      terminal got: ${m.mutated_hex || '(deleted)'}`);
    const diff = describeDiff(m.original_hex, m.mutated_hex);
    if (diff) out.push(`      changed   : ${diff}`);
    if (m.comment) out.push(`      ${m.comment}`);
  });
  return out.join('\n');
}

/* Which byte positions actually differ, so a one-byte change inside a long
   value does not have to be spotted by eye. */
function describeDiff(before, after) {
  if (!before || !after || before.length !== after.length) return '';
  const spans = [];
  for (let i = 0; i < before.length; i += 2) {
    if (before.slice(i, i + 2) !== after.slice(i, i + 2)) {
      const byte = i / 2;
      const last = spans[spans.length - 1];
      if (last && last[1] === byte - 1) last[1] = byte;
      else spans.push([byte, byte]);
    }
  }
  if (!spans.length) return 'nothing (identical)';
  return spans.map(([a, b]) => {
    const range = a === b ? `byte ${a}` : `bytes ${a}-${b}`;
    return `${range}: ${before.slice(a * 2, (b + 1) * 2)} → ${after.slice(a * 2, (b + 1) * 2)}`;
  }).join(', ');
}

// ── TLV ───────────────────────────────────────────────────────────────────────
/* The server sends a list of TLVNode.to_dict() objects:
     {tag, name, length, value, children?: [...]}
   The previous version treated that as a {tag: value} map and excluded arrays
   from recursion, so a constructed tag printed its children as the string
   "[object Object]". This walks the real shape. */
function formatTLV(nodes, indent) {
  if (!Array.isArray(nodes)) {
    // Tolerate the flat {tag: value} shape too, rather than showing nothing.
    if (nodes && typeof nodes === 'object') {
      return Object.entries(nodes)
        .map(([tag, val]) => `${' '.repeat(indent)}${tag}  ${stringify(val)}`)
        .join('\n');
    }
    return '';
  }

  const pad = ' '.repeat(indent);
  return nodes.map(node => {
    if (!node || typeof node !== 'object') return `${pad}${stringify(node)}`;

    const tag  = node.tag ?? '??';
    const name = node.name ? `  ${node.name}` : '';
    const len  = node.length != null ? ` (${node.length})` : '';
    const kids = Array.isArray(node.children) ? node.children : null;

    if (kids && kids.length) {
      // A constructed tag: show the template, then its contents indented.
      return `${pad}${tag}${len}${name}\n${formatTLV(kids, indent + 2)}`;
    }
    return `${pad}${tag}${len}${name}\n${pad}  ${node.value ?? ''}`;
  }).join('\n');
}

function stringify(val) {
  if (val === null || val === undefined) return '';
  if (typeof val === 'object') {
    try { return JSON.stringify(val); } catch { return '[unprintable]'; }
  }
  return String(val);
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
