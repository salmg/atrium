/* ─── theme.js — dark/light switching ───────────────────────────────────────
 * Loaded synchronously in <head> so the theme is applied before first paint;
 * a deferred script would show one frame of the wrong theme on every load.
 *
 * Stored preference is 'light' | 'dark' | null. null means "follow the OS",
 * which is also the default for a first-time visitor.
 */
(function () {
  const KEY   = 'atrium-theme';
  const root  = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: light)');

  const read  = () => { try { return localStorage.getItem(KEY); } catch { return null; } };
  const write = v => {
    try { v ? localStorage.setItem(KEY, v) : localStorage.removeItem(KEY); } catch {}
  };

  const systemTheme = () => (media.matches ? 'light' : 'dark');
  const effective   = () => read() || systemTheme();

  function apply(theme) {
    root.setAttribute('data-theme', theme);
    root.style.colorScheme = theme;
  }

  apply(effective());

  // Follow the OS only while the user hasn't made an explicit choice
  media.addEventListener?.('change', () => {
    if (!read()) { apply(systemTheme()); syncUI(); }
  });

  function syncUI() {
    const current = root.getAttribute('data-theme');
    const pref    = read();               // null => system

    const btn = document.getElementById('btnTheme');
    if (btn) {
      const dark = current === 'dark';
      btn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
      btn.title = dark ? 'Light mode' : 'Dark mode';
    }

    document.querySelectorAll('[data-theme-choice]').forEach(opt => {
      const selected = (opt.dataset.themeChoice === 'system') ? !pref : opt.dataset.themeChoice === pref;
      opt.setAttribute('aria-pressed', String(selected));
    });
  }

  function setPreference(pref) {          // 'light' | 'dark' | null (system)
    write(pref);
    apply(pref || systemTheme());
    syncUI();
  }

  document.addEventListener('DOMContentLoaded', () => {
    // Topbar quick toggle — always flips to the opposite of what's showing
    document.getElementById('btnTheme')?.addEventListener('click', () => {
      setPreference(root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });

    // Settings picker — light / dark / system
    document.querySelectorAll('[data-theme-choice]').forEach(opt => {
      opt.addEventListener('click', () => {
        const choice = opt.dataset.themeChoice;
        setPreference(choice === 'system' ? null : choice);
      });
    });

    syncUI();
  });
})();
