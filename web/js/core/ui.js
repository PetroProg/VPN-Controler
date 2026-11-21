/* Shared UI helpers: XSS escaping, toasts, bottom-sheet modal, clipboard, PWA */

let toastTimer = null;
let pendingSheetConfirm = null;
let deferredPrompt = null;

export function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function showToast(msg, tone = 'info') {
  const el = document.getElementById('app-toast');
  const dot = document.getElementById('app-toast-dot');
  const txt = document.getElementById('app-toast-msg');
  if (!el || !dot || !txt) return;

  const toneColors = {
    ok: 'var(--p-ok)',
    warn: 'var(--p-warn)',
    err: 'var(--p-err)',
    info: 'var(--p-accent)',
  };
  dot.style.background = toneColors[tone] || toneColors.info;
  txt.textContent = msg;
  el.classList.remove('hidden');

  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 2800);
}

export async function copyToClipboard(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    showToast(`Скопировано: ${text}`, 'ok');
  } catch (err) {
    showToast(text, 'info');
  }
}

export function initConfirmSheet() {
  const backdrop = document.getElementById('app-sheet-backdrop');
  const cancelBtn = document.getElementById('sheet-cancel-btn');
  const confirmBtn = document.getElementById('sheet-confirm-btn');
  if (!backdrop || !cancelBtn || !confirmBtn) return;

  cancelBtn.addEventListener('click', closeConfirmSheet);
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) closeConfirmSheet();
  });
  confirmBtn.addEventListener('click', async () => {
    const fn = pendingSheetConfirm;
    closeConfirmSheet();
    if (typeof fn === 'function') {
      await fn();
    }
  });
}

export function openConfirmSheet({ title, desc, preview, confirmLabel, confirmTone, onConfirm }) {
  const backdrop = document.getElementById('app-sheet-backdrop');
  const titleEl = document.getElementById('sheet-title');
  const descEl = document.getElementById('sheet-desc');
  const previewEl = document.getElementById('sheet-rule-preview');
  const confirmBtn = document.getElementById('sheet-confirm-btn');
  if (!backdrop || !titleEl || !descEl || !previewEl || !confirmBtn) return;

  titleEl.textContent = title;
  descEl.textContent = desc;
  previewEl.textContent = preview;
  confirmBtn.textContent = confirmLabel;
  confirmBtn.className = confirmTone === 'err' ? 'btn-danger flex-1' : 'btn-ok flex-1';
  pendingSheetConfirm = onConfirm;
  backdrop.classList.remove('hidden');
}

export function closeConfirmSheet() {
  const backdrop = document.getElementById('app-sheet-backdrop');
  if (backdrop) backdrop.classList.add('hidden');
  pendingSheetConfirm = null;
}

export function formatClock(tz = 'CET') {
  const now = new Date();
  if (tz === 'UTC') {
    return `${now.toUTCString().slice(17, 25)} UTC`;
  }
  return `${now.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' })} CET`;
}

export function isStandalonePwa() {
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    window.matchMedia('(display-mode: window-controls-overlay)').matches ||
    window.navigator.standalone === true
  );
}

export function registerServiceWorker() {
  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
  }
}

export function setupPwaInstall(btnEl, hintEl, httpsUrl = 'https://petroprog.tail703e6c.ts.net:8446') {
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    if (btnEl) btnEl.classList.remove('hidden');
  });

  window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    if (btnEl) btnEl.classList.add('hidden');
    if (hintEl) hintEl.classList.add('hidden');
    showToast('VPN Controler установлен!', 'ok');
  });

  if (!btnEl) return;
  if (isStandalonePwa()) {
    btnEl.classList.add('hidden');
    return;
  }

  btnEl.addEventListener('click', async () => {
    if (deferredPrompt) {
      try {
        deferredPrompt.prompt();
        const { outcome } = await deferredPrompt.userChoice;
        if (outcome === 'accepted') deferredPrompt = null;
        return;
      } catch (err) {
        // Fallback to manual instructions below
      }
    }
    if (!hintEl) return;

    const isHttpInsecure =
      window.location.protocol === 'http:' &&
      window.location.hostname !== 'localhost' &&
      window.location.hostname !== '127.0.0.1';
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;

    if (isHttpInsecure) {
      hintEl.innerHTML = `
        <div>Для установки PWA браузер требует HTTPS. Откройте защищённый адрес в Tailscale:</div>
        <div style="margin-top:0.4rem;"><a href="${escapeHtml(httpsUrl)}" class="btn-primary" style="min-height:2.1rem;font-size:0.75rem;">Открыть по HTTPS ↗</a></div>
      `;
    } else if (isIOS) {
      hintEl.textContent = 'На iPhone/iPad (Safari): нажмите «Поделиться» → «На экран Домой».';
    } else {
      hintEl.textContent = 'В Chrome/Edge: откройте меню браузера ⋮ → «Установить приложение VPN Controler».';
    }
    hintEl.classList.remove('hidden');
  });
}
