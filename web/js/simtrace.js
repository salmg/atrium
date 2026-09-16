/* ─── simtrace.js — SimTrace2 device + daemon discovery ───

   ATRIUM does not launch simtrace2-remsim: the daemon needs root, and this
   view exists to find the board, hand over the exact command, and then watch
   /proc until the operator's own terminal has it running. */

// ── SimTrace2 view elements ──────────────────────────────────────────────────
const simtraceHero      = document.getElementById('simtraceHero');
const simtraceHeroDot   = document.getElementById('simtraceHeroDot');
const simtraceHeroLabel = document.getElementById('simtraceHeroLabel');
const simtraceHeroSub   = document.getElementById('simtraceHeroSub');
const simtraceDevice    = document.getElementById('simtraceDevice');
const btnSimtraceScan   = document.getElementById('btnSimtraceScan');

const simtraceCommand     = document.getElementById('simtraceCommand');
const simtraceCommandHint = document.getElementById('simtraceCommandHint');
const simtraceUdev        = document.getElementById('simtraceUdev');
const btnSimtraceCopy     = document.getElementById('btnSimtraceCopy');

const simtraceProcPid  = document.getElementById('simtraceProcPid');
const simtraceProcUser = document.getElementById('simtraceProcUser');
const simtraceProcUsb  = document.getElementById('simtraceProcUsb');
const simtraceProcCmd  = document.getElementById('simtraceProcCmd');

// ── Settings view config elements ────────────────────────────────────────────
const simtraceBinaryPath     = document.getElementById('simtraceBinaryPath');
const simtraceSudo           = document.getElementById('simtraceSudo');
const btnSaveSimtraceConfig  = document.getElementById('btnSaveSimtraceConfig');
const simtraceConfigMsg      = document.getElementById('simtraceConfigMsg');

// ── Activate handlers ─────────────────────────────────────────────────────────
document.querySelector('[data-view="simtrace"]').addEventListener('click', () => {
  refreshSimtrace();
});

document.querySelector('[data-view="settings"]').addEventListener('click', () => {
  loadSimtraceConfig();
});

// ── Config (Settings view) ────────────────────────────────────────────────────
async function loadSimtraceConfig() {
  try {
    const res = await API.get('/api/simtrace/config');
    if (res.ok) {
      simtraceBinaryPath.value = res.binary_path || '';
      simtraceSudo.checked     = res.use_sudo !== false;
      if (!res.binary_path && res.resolved_binary) {
        simtraceBinaryPath.placeholder = `auto-detected: ${res.resolved_binary}`;
      }
    }
  } catch { /* server unreachable */ }
}

btnSaveSimtraceConfig.addEventListener('click', async () => {
  const res = await API.post('/api/simtrace/config', {
    binary_path: simtraceBinaryPath.value.trim(),
    use_sudo:    simtraceSudo.checked,
  }, 'PUT');
  simtraceConfigMsg.textContent = res.ok ? '✓ Saved.' : '✗ ' + (res.error || 'Save failed');
  simtraceConfigMsg.className   = 'pb-msg' + (res.ok ? ' pb-msg-ok' : ' pb-msg-error');
  if (res.ok) refreshCommand();
});

// ── Device list ───────────────────────────────────────────────────────────────
function renderDeviceList(devices) {
  const prev = simtraceDevice.value;
  simtraceDevice.innerHTML = '';

  if (devices.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = '— no SimTrace2 device found —';
    simtraceDevice.appendChild(opt);
    return;
  }

  devices.forEach(d => {
    const opt = document.createElement('option');
    opt.value = d.usb_path;
    opt.textContent = d.product
      ? `${d.usb_path}  (${d.product})`
      : `${d.usb_path}  [${d.vendor_id}:${d.product_id}]`;
    simtraceDevice.appendChild(opt);
  });

  if (prev && [...simtraceDevice.options].some(o => o.value === prev)) {
    simtraceDevice.value = prev;
  }
}

// ── Suggested command ─────────────────────────────────────────────────────────
async function refreshCommand() {
  const usb = simtraceDevice.value;
  try {
    const res = await API.get('/api/simtrace/command' + (usb ? `?usb_path=${encodeURIComponent(usb)}` : ''));
    if (!res.ok) return;

    simtraceCommand.textContent = res.command;
    simtraceUdev.textContent    = `echo '${res.udev_rule}' | sudo tee ${res.udev_path}\n`
                                + 'sudo udevadm control --reload';

    const notes = [];
    if (!res.resolved) notes.push('Plug in the board and rescan to fill in the USB path.');
    if (res.binary_source === 'fallback') {
      notes.push('simtrace2-remsim was not found — set its path in Settings if this line does not resolve.');
    }
    simtraceCommandHint.textContent = notes.join(' ');
    simtraceCommandHint.className   = 'pb-msg' + (notes.length ? ' pb-msg-error' : '');
  } catch { /* server unreachable */ }
}

btnSimtraceCopy.addEventListener('click', async () => {
  const text = simtraceCommand.textContent || '';
  try {
    await navigator.clipboard.writeText(text);
    btnSimtraceCopy.textContent = 'Copied';
  } catch {
    // Clipboard needs a secure context; select the text so Ctrl-C still works.
    const range = document.createRange();
    range.selectNodeContents(simtraceCommand);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    btnSimtraceCopy.textContent = 'Press Ctrl-C';
  }
  setTimeout(() => { btnSimtraceCopy.textContent = 'Copy'; }, 2000);
});

simtraceDevice.addEventListener('change', refreshCommand);

// ── Status ────────────────────────────────────────────────────────────────────
const SIMTRACE_STATES = {
  no_device: {
    label: 'No device',
    sub:   'Plug in the SimTrace2 board and rescan',
    live:  false,
  },
  device_ready: {
    label: 'Device ready',
    sub:   'Board detected — run the command below in a second terminal',
    live:  false,
  },
  running: {
    label: 'Daemon running',
    sub:   '',
    live:  true,
  },
  running_other: {
    label: 'Daemon running',
    sub:   'Bound to a USB path this host no longer reports — check the board is still plugged in',
    live:  true,
  },
};

function renderSimtraceStatus(res) {
  const state = SIMTRACE_STATES[res.state] || SIMTRACE_STATES.no_device;

  simtraceHero.classList.toggle('status-banner--active', state.live);
  simtraceHeroDot.className = state.live
    ? 'status-banner-dot status-banner-dot--active'
    : 'status-banner-dot';
  simtraceHeroLabel.textContent = state.label;
  simtraceHeroSub.textContent   = res.state === 'running'
    ? `PID ${res.pid} as ${res.user || 'unknown'} on ${res.usb_path || 'unknown path'}`
    : state.sub;

  simtraceProcPid.textContent  = res.pid ? `PID ${res.pid}` : 'Not running';
  simtraceProcUser.textContent = res.user     || '—';
  simtraceProcUsb.textContent  = res.usb_path || '—';
  simtraceProcCmd.textContent  = res.cmdline  || '—';
}

async function refreshSimtrace() {
  btnSimtraceScan.disabled = true;
  try {
    const res = await API.get('/api/simtrace/status');
    if (res.ok) {
      renderDeviceList(res.devices || []);
      renderSimtraceStatus(res);
      await refreshCommand();
    }
  } catch {
    renderDeviceList([]);
  } finally {
    btnSimtraceScan.disabled = false;
  }
}

btnSimtraceScan.addEventListener('click', refreshSimtrace);

function _simtraceViewActive() {
  return document.getElementById('view-simtrace')?.classList.contains('active');
}

// Poll while the view is open so the banner flips over on its own the moment
// the operator's terminal brings the daemon up.
let _lastCommandKey = null;

setInterval(async () => {
  if (!_simtraceViewActive()) return;
  try {
    const res = await API.get('/api/simtrace/status');
    if (!res.ok) return;
    renderDeviceList(res.devices || []);
    renderSimtraceStatus(res);

    // Re-render the command only when the device situation actually moved,
    // so a board plugged in mid-poll fills in its USB path by itself.
    const key = `${simtraceDevice.value}|${(res.devices || []).length}`;
    if (key !== _lastCommandKey) {
      _lastCommandKey = key;
      await refreshCommand();
    }
  } catch { /* ignore */ }
}, 3000);
