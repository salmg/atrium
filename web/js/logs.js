/* ─── logs.js — session log file browser ─── */

const logFileList   = document.getElementById('logFileList');
const logViewer     = document.getElementById('logViewer');
const btnRefreshLogs = document.getElementById('btnRefreshLogs');

let _currentFile    = null;
let _currentOffset  = 0;
const PAGE          = 500;

// ── activation ────────────────────────────────────────────────────────────────
document.querySelector('[data-view="logs"]').addEventListener('click', loadLogList);
btnRefreshLogs.addEventListener('click', loadLogList);

// ── file list ─────────────────────────────────────────────────────────────────
async function loadLogList() {
  logFileList.innerHTML = '<p class="text-dim" style="padding:4px 0">Loading…</p>';
  try {
    const res = await API.get('/api/logs');
    if (!res.ok || !res.data.length) {
      logFileList.innerHTML = '<p class="text-dim">No log files found.</p>';
      return;
    }
    renderFileList(res.data);
  } catch {
    logFileList.innerHTML = '<p class="text-dim">Server unreachable</p>';
  }
}

function renderFileList(files) {
  logFileList.innerHTML = files.map(f => {
    const kb   = (f.size / 1024).toFixed(1);
    const date = new Date(f.modified).toLocaleDateString(undefined,
      { month: 'short', day: 'numeric', year: '2-digit', hour: '2-digit', minute: '2-digit' });
    return `
      <div class="log-file-item" data-name="${escHtml(f.name)}">
        <span class="log-file-name">${escHtml(f.name)}</span>
        <div class="log-file-meta">
          <span>${kb} KB</span>
          <span>${date}</span>
          <button class="btn btn-ghost btn-sm log-delete-btn" data-name="${escHtml(f.name)}" title="Delete">
            <svg viewBox="0 0 16 16" fill="currentColor" width="12" height="12"><path fill-rule="evenodd" d="M5.5 5.5A.5.5 0 016 6v6a.5.5 0 01-1 0V6a.5.5 0 01.5-.5zm2.5 0a.5.5 0 01.5.5v6a.5.5 0 01-1 0V6a.5.5 0 01.5-.5zm3 .5a.5.5 0 00-1 0v6a.5.5 0 001 0V6z"/><path fill-rule="evenodd" d="M14.5 3a1 1 0 01-1 1H13v9a2 2 0 01-2 2H5a2 2 0 01-2-2V4h-.5a1 1 0 01-1-1V2a1 1 0 011-1H6a1 1 0 011-1h2a1 1 0 011 1h3.5a1 1 0 011 1v1zM4.118 4L4 4.059V13a1 1 0 001 1h6a1 1 0 001-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z" clip-rule="evenodd"/></svg>
          </button>
        </div>
      </div>
    `;
  }).join('');

  logFileList.querySelectorAll('.log-file-item').forEach(item => {
    item.addEventListener('click', e => {
      if (e.target.closest('.log-delete-btn')) return;
      openFile(item.dataset.name);
      logFileList.querySelectorAll('.log-file-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
    });
  });

  logFileList.querySelectorAll('.log-delete-btn').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      if (!confirm(`Delete ${btn.dataset.name}?`)) return;
      const res = await API.post(`/api/logs/${encodeURIComponent(btn.dataset.name)}`, {}, 'DELETE');
      if (res.ok) loadLogList();
    });
  });
}

// ── file viewer ───────────────────────────────────────────────────────────────
async function openFile(name) {
  _currentFile  = name;
  _currentOffset = 0;
  logViewer.innerHTML = `<p class="text-dim">Loading ${escHtml(name)}…</p>`;
  await loadPage(0);
}

async function loadPage(offset) {
  try {
    const res = await API.get(
      `/api/logs/${encodeURIComponent(_currentFile)}?offset=${offset}&limit=${PAGE}`
    );
    if (!res.ok) { logViewer.textContent = res.detail || 'Error'; return; }
    renderViewer(res);
  } catch {
    logViewer.textContent = 'Server unreachable';
  }
}

function renderViewer(res) {
  const hasPrev = res.offset > 0;
  const hasNext = res.offset + PAGE < res.total_lines;
  const content = res.lines.join('\n');

  logViewer.innerHTML = `
    <div class="log-viewer-header">
      <span class="log-viewer-name">${escHtml(res.name)}</span>
      <span class="text-dim" style="font-size:11px">
        Lines ${res.offset + 1}–${Math.min(res.offset + PAGE, res.total_lines)} of ${res.total_lines}
      </span>
    </div>
    <pre class="log-content">${escHtml(content)}</pre>
    <div class="log-pager">
      <button class="btn btn-ghost btn-sm" id="btnLogPrev" ${hasPrev ? '' : 'disabled'}>← Prev</button>
      <span class="text-dim" style="font-size:12px">Page ${Math.floor(res.offset / PAGE) + 1} / ${Math.ceil(res.total_lines / PAGE) || 1}</span>
      <button class="btn btn-ghost btn-sm" id="btnLogNext" ${hasNext ? '' : 'disabled'}>Next →</button>
    </div>
  `;

  if (hasPrev) {
    document.getElementById('btnLogPrev').addEventListener('click', () => {
      const off = Math.max(0, res.offset - PAGE);
      _currentOffset = off;
      loadPage(off);
    });
  }
  if (hasNext) {
    document.getElementById('btnLogNext').addEventListener('click', () => {
      const off = res.offset + PAGE;
      _currentOffset = off;
      loadPage(off);
    });
  }
}

function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
