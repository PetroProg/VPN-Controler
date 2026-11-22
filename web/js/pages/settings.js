/* Settings page (Page 2: Настройки — Themes, Behavior, AdGuard Admin, Node & PWA) */

import { apiDelete, apiGet, apiPost } from '../core/api.js';
import { clearPageCache, isCacheFresh, readPageCache, writePageCache } from '../core/cache.js';
import {
  THEMES,
  applyI18n,
  applyThemeAndDensity,
  getSettings,
  saveSettings,
} from '../core/settings.js';
import {
  copyToClipboard,
  escapeHtml,
  formatClock,
  registerServiceWorker,
  setupPwaInstall,
  showToast,
} from '../core/ui.js';

let cfg = getSettings();
applyThemeAndDensity(cfg);
registerServiceWorker();

const state = {
  rules: [],
  filters: [],
  rewrites: [],
  meta: null,
  vpn: null,
  overview: null,
};

function renderPreferences() {
  const lang = cfg.lang;
  document.getElementById('theme-cards-grid').innerHTML = THEMES.map((th) => {
    const active = th.id === cfg.theme;
    const sub = lang === 'en' ? th.subEn : th.subRu;
    return `
      <button type="button" data-theme-opt="${escapeHtml(th.id)}" class="theme-card ${active ? 'active' : ''}">
        <div class="swatch-pair">
          <div class="swatch-dots">
            <span class="swatch-dot" style="background:${th.bg};"></span>
            <span class="swatch-dot" style="background:${th.accent};"></span>
          </div>
          ${active ? '<span style="font-size:0.75rem;font-weight:700;color:var(--p-accent);">✓</span>' : ''}
        </div>
        <div style="font-size:0.8125rem;font-weight:700;">${escapeHtml(th.name)}</div>
        <div style="font-size:0.75rem;color:var(--p-muted);">${escapeHtml(sub)}</div>
      </button>
    `;
  }).join('');

  document.querySelectorAll('[data-density-opt]').forEach((b) => {
    b.classList.toggle('active', b.dataset.densityOpt === cfg.density);
  });

  const intervals = [3000, 5000, 15000, 30000, 0];
  document.getElementById('refresh-interval-seg').innerHTML = intervals.map((ms) => {
    const lbl = ms === 0 ? (lang === 'en' ? 'Off' : 'Выкл') : `${ms / 1000}${lang === 'en' ? 's' : 'с'}`;
    return `<button type="button" data-refresh-opt="${ms}" class="seg-opt mono ${cfg.refreshMs === ms ? 'active' : ''}">${lbl}</button>`;
  }).join('');

  const pauses = [5, 15, 30, 60];
  document.getElementById('default-pause-seg').innerHTML = pauses.map((m) => (
    `<button type="button" data-defpause-opt="${m}" class="seg-opt mono ${cfg.defaultPauseMin === m ? 'active' : ''}">${m}${lang === 'en' ? 'm' : 'м'}</button>`
  )).join('');

  document.querySelectorAll('[data-defchart-opt]').forEach((b) => {
    b.classList.toggle('active', b.dataset.defchartOpt === cfg.defaultChartMode);
  });
  document.querySelectorAll('[data-lang-opt]').forEach((b) => {
    b.classList.toggle('active', b.dataset.langOpt === cfg.lang);
  });
  document.querySelectorAll('[data-tz-opt]').forEach((b) => {
    b.classList.toggle('active', b.dataset.tzOpt === cfg.tz);
  });
}

function renderAdguardAdmin() {
  document.getElementById('user-rules-count').textContent = `${state.rules.length}`;
  const rulesBox = document.getElementById('user-rules-list');
  if (!state.rules.length) {
    rulesBox.innerHTML = `<div class="hint-box" style="text-align:center;">Нет пользовательских правил</div>`;
  } else {
    rulesBox.innerHTML = state.rules.map((rule, idx) => {
      const isAllow = rule.startsWith('@@');
      return `
        <div class="list-row">
          <div style="display:flex;align-items:center;gap:0.45rem;min-width:0;">
            <span class="tag-pill mono ${isAllow ? 'ok' : 'err'}" style="flex-shrink:0;">${isAllow ? 'ALLOW' : 'BLOCK'}</span>
            <span class="mono row-truncate">${escapeHtml(rule)}</span>
          </div>
          <button type="button" data-rule-del-idx="${idx}" style="color:var(--p-muted);font-weight:700;padding:0.2rem 0.45rem;" aria-label="Удалить">✕</button>
        </div>
      `;
    }).join('');
  }

  const blBox = document.getElementById('blocklists-list');
  if (!state.filters.length) {
    blBox.innerHTML = `<div class="hint-box">Нет активных подписок</div>`;
  } else {
    blBox.innerHTML = state.filters.map((f) => {
      const upd = f.last_updated ? String(f.last_updated).slice(0, 16).replace('T', ' ') : '—';
      return `
        <div class="list-row">
          <div style="min-width:0;">
            <div style="font-weight:700;" class="row-truncate">${escapeHtml(f.name)}</div>
            <div style="color:var(--p-muted);">${Number(f.rules_count).toLocaleString('en-US')} правил · ${escapeHtml(upd)}</div>
          </div>
          <span style="font-weight:700;color:${f.enabled ? 'var(--p-ok)' : 'var(--p-dim)'};flex-shrink:0;">${f.enabled ? 'ON' : 'OFF'}</span>
        </div>
      `;
    }).join('');
  }

  document.getElementById('rewrites-count').textContent = `${state.rewrites.length}`;
  const rwBox = document.getElementById('dns-rewrites-list');
  if (!state.rewrites.length) {
    rwBox.innerHTML = `<div class="hint-box" style="text-align:center;">Нет локальных DNS-перезаписей</div>`;
  } else {
    rwBox.innerHTML = state.rewrites.map((rw, idx) => `
      <div class="list-row">
        <div class="mono row-truncate">
          <strong>${escapeHtml(rw.domain)}</strong> → <span style="color:var(--p-muted);">${escapeHtml(rw.answer)}</span>
        </div>
        <button type="button" data-rw-del-idx="${idx}" style="color:var(--p-muted);font-weight:700;padding:0.2rem 0.45rem;" aria-label="Удалить">✕</button>
      </div>
    `).join('');
  }
}

function renderNodeInfo() {
  const m = state.meta || {};
  const vpn = state.vpn || {};
  const ov = state.overview || {};

  const dnsName = (vpn.self && vpn.self.dns_name) || m.tailscale_dns_name || 'petroprog.tail703e6c.ts.net';
  const tsIp = (vpn.self && vpn.self.ip) || m.host_tailscale_ip || '100.107.4.120';
  const lanIp = vpn.lan_ip || m.host_lan_ip || '192.168.178.65';
  const tsVer = vpn.version ? `Tailscale ${vpn.version}` : 'Tailscale';
  const adgVer = ov.version ? `AdGuard ${ov.version}` : 'AdGuard';
  const health = Array.isArray(vpn.health) ? vpn.health : [];

  document.getElementById('node-dns-name').textContent = dnsName;
  document.getElementById('node-ts-ip').textContent = tsIp;
  document.getElementById('node-ts-copy').dataset.copy = tsIp;
  document.getElementById('node-lan-ip').textContent = lanIp;
  document.getElementById('node-lan-copy').dataset.copy = lanIp;

  const stackEl = document.getElementById('node-stack-status');
  stackEl.textContent = `${tsVer} · ${adgVer} · ${health.length ? 'Warn' : 'Health OK'}`;
  stackEl.style.color = health.length ? 'var(--p-warn)' : 'var(--p-ok)';

  const healthBox = document.getElementById('node-health-box');
  if (health.length) {
    healthBox.textContent = health.join('; ');
    healthBox.classList.remove('hidden');
  } else {
    healthBox.classList.add('hidden');
  }

  const adgPort = m.adguard_public_port || 3053;
  const host = window.location.hostname || lanIp;
  document.getElementById('open-adguard-link').href = `http://${host}:${adgPort}`;
}

function hydrateSettingsFromCache() {
  const cached = readPageCache();
  if (!cached) return { hasCache: false, isFresh: false };

  let hasAny = false;
  if (cached.meta) {
    state.meta = cached.meta;
    hasAny = true;
  }
  if (cached.vpn) {
    state.vpn = cached.vpn;
    hasAny = true;
  }
  if (cached.overview) {
    state.overview = cached.overview;
    state.filters = cached.overview.filters || state.filters;
    if (Array.isArray(cached.overview.user_rules) && !Array.isArray(cached.rules)) {
      state.rules = cached.overview.user_rules;
    }
    hasAny = true;
  }
  if (Array.isArray(cached.rules)) {
    state.rules = cached.rules;
    hasAny = true;
  }
  if (Array.isArray(cached.rewrites)) {
    state.rewrites = cached.rewrites;
    hasAny = true;
  }

  if (hasAny) {
    renderNodeInfo();
    renderAdguardAdmin();
  }

  const isFresh = isCacheFresh(cached, ['meta', 'vpn', 'overview', 'rules', 'rewrites'], 20000);
  return { hasCache: hasAny, isFresh };
}

async function loadSettingsData(force = false) {
  const cached = readPageCache() || {};
  const needMeta = force || !isCacheFresh(cached, ['meta'], 60000);
  const needVpn = force || !isCacheFresh(cached, ['vpn'], 15000);
  const needOverview = force || !isCacheFresh(cached, ['overview'], 15000);
  const needRules = force || (!isCacheFresh(cached, ['rules'], 15000) && !(state.overview && Array.isArray(state.overview.user_rules)));
  const needRewrites = force || !isCacheFresh(cached, ['rewrites'], 30000);

  const [metaRes, vpnRes, ovRes, rulesRes, rwRes] = await Promise.allSettled([
    needMeta ? apiGet('/api/meta') : Promise.resolve(state.meta),
    needVpn ? apiGet('/api/vpn/status') : Promise.resolve(state.vpn),
    needOverview ? apiGet('/api/dns/overview') : Promise.resolve(state.overview),
    needRules ? apiGet('/api/dns/rules') : Promise.resolve({ rules: state.rules }),
    needRewrites ? apiGet('/api/dns/rewrites') : Promise.resolve({ rewrites: state.rewrites }),
  ]);

  const patch = {};
  if (metaRes.status === 'fulfilled' && metaRes.value) {
    state.meta = metaRes.value;
    if (needMeta) patch.meta = metaRes.value;
  }
  if (vpnRes.status === 'fulfilled' && vpnRes.value) {
    state.vpn = vpnRes.value;
    if (needVpn) patch.vpn = vpnRes.value;
  }
  if (ovRes.status === 'fulfilled' && ovRes.value) {
    state.overview = ovRes.value;
    state.filters = ovRes.value.filters || [];
    if (Array.isArray(ovRes.value.user_rules) && !needRules && !state.rules.length) {
      state.rules = ovRes.value.user_rules;
      patch.rules = state.rules;
    }
    if (needOverview) patch.overview = ovRes.value;
  }
  if (rulesRes.status === 'fulfilled' && rulesRes.value && Array.isArray(rulesRes.value.rules)) {
    state.rules = rulesRes.value.rules;
    if (needRules) patch.rules = state.rules;
  }
  if (rwRes.status === 'fulfilled' && rwRes.value && Array.isArray(rwRes.value.rewrites)) {
    state.rewrites = rwRes.value.rewrites;
    if (needRewrites) patch.rewrites = state.rewrites;
  }
  if (Object.keys(patch).length) writePageCache(patch);

  renderNodeInfo();
  renderAdguardAdmin();
  setupPwaInstall(
    document.getElementById('pwa-install-btn'),
    document.getElementById('pwa-hint-box'),
    (state.meta && state.meta.https_pwa_url) || 'https://petroprog.tail703e6c.ts.net:8446',
  );
}

async function submitUserRule(mode) {
  const inp = document.getElementById('settings-rule-input');
  const domain = inp.value.trim();
  if (!domain) {
    showToast('Введите домен', 'warn');
    return;
  }
  try {
    const res = await apiPost('/api/dns/rules', { domain, mode });
    inp.value = '';
    state.rules = res.rules || state.rules;
    if (state.overview) state.overview.user_rules = state.rules;
    writePageCache({ rules: state.rules, ...(state.overview ? { overview: state.overview } : {}) });
    renderAdguardAdmin();
    showToast(`Добавлено: ${res.rule}`, mode === 'allow' ? 'ok' : 'warn');
  } catch (err) {
    showToast(err.message, 'err');
  }
}

document.getElementById('settings-rule-block-btn').addEventListener('click', () => submitUserRule('block'));
document.getElementById('settings-rule-allow-btn').addEventListener('click', () => submitUserRule('allow'));

document.getElementById('refresh-filters-btn').addEventListener('click', async () => {
  const ico = document.getElementById('refresh-filters-icon');
  ico.classList.remove('spin-once');
  void ico.offsetWidth;
  ico.classList.add('spin-once');
  try {
    await apiPost('/api/dns/filters/refresh', {});
    const ov = await apiGet('/api/dns/overview');
    state.overview = ov;
    state.filters = ov.filters || [];
    writePageCache({ overview: ov });
    renderAdguardAdmin();
    showToast('Подписки фильтров обновлены', 'ok');
  } catch (err) {
    showToast(err.message, 'err');
  }
});

document.getElementById('clear-dns-cache-btn').addEventListener('click', async () => {
  try {
    await apiPost('/api/dns/cache/clear', {});
    showToast('Кэш DNS AdGuard очищен', 'ok');
  } catch (err) {
    showToast(err.message, 'err');
  }
});

document.getElementById('rewrite-add-btn').addEventListener('click', async () => {
  const domInp = document.getElementById('rewrite-domain-input');
  const ipInp = document.getElementById('rewrite-ip-input');
  const domain = domInp.value.trim();
  const answer = ipInp.value.trim();
  if (!domain || !answer) {
    showToast('Укажите домен и IP/адрес', 'warn');
    return;
  }
  try {
    await apiPost('/api/dns/rewrites', { domain, answer });
    domInp.value = '';
    const rw = await apiGet('/api/dns/rewrites');
    state.rewrites = rw.rewrites || [];
    writePageCache({ rewrites: state.rewrites });
    renderAdguardAdmin();
    showToast(`Добавлено: ${domain} → ${answer}`, 'ok');
  } catch (err) {
    showToast(err.message, 'err');
  }
});

document.getElementById('sw-reset-btn').addEventListener('click', async () => {
  try {
    clearPageCache();
    if ('caches' in window) {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
    }
    if ('serviceWorker' in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map((r) => r.unregister()));
    }
    showToast('Кэш сброшен, перезагрузка...', 'ok');
    setTimeout(() => window.location.reload(), 600);
  } catch (err) {
    showToast(err.message, 'err');
  }
});

document.querySelector('main').addEventListener('click', async (e) => {
  const tEl = e.target;

  const copyBtn = tEl.closest('[data-copy]');
  if (copyBtn) {
    await copyToClipboard(copyBtn.dataset.copy);
    return;
  }

  const themeOpt = tEl.closest('[data-theme-opt]');
  if (themeOpt) {
    cfg = saveSettings({ theme: themeOpt.dataset.themeOpt });
    renderPreferences();
    return;
  }

  const densityOpt = tEl.closest('[data-density-opt]');
  if (densityOpt) {
    cfg = saveSettings({ density: densityOpt.dataset.densityOpt });
    renderPreferences();
    return;
  }

  const refreshOpt = tEl.closest('[data-refresh-opt]');
  if (refreshOpt) {
    cfg = saveSettings({ refreshMs: Number(refreshOpt.dataset.refreshOpt) });
    renderPreferences();
    showToast(cfg.refreshMs === 0 ? 'Автообновление отключено' : `Интервал: ${cfg.refreshMs / 1000}с`, 'info');
    return;
  }

  const pauseOpt = tEl.closest('[data-defpause-opt]');
  if (pauseOpt) {
    cfg = saveSettings({ defaultPauseMin: Number(pauseOpt.dataset.defpauseOpt) });
    renderPreferences();
    return;
  }

  const chartOpt = tEl.closest('[data-defchart-opt]');
  if (chartOpt) {
    cfg = saveSettings({ defaultChartMode: chartOpt.dataset.defchartOpt });
    renderPreferences();
    return;
  }

  const langOpt = tEl.closest('[data-lang-opt]');
  if (langOpt) {
    cfg = saveSettings({ lang: langOpt.dataset.langOpt });
    applyI18n(cfg.lang);
    renderPreferences();
    return;
  }

  const tzOpt = tEl.closest('[data-tz-opt]');
  if (tzOpt) {
    cfg = saveSettings({ tz: tzOpt.dataset.tzOpt });
    renderPreferences();
    document.getElementById('settings-live-clock').textContent = formatClock(cfg.tz);
    return;
  }

  const ruleDelBtn = tEl.closest('[data-rule-del-idx]');
  if (ruleDelBtn) {
    const rule = state.rules[Number(ruleDelBtn.dataset.ruleDelIdx)];
    if (!rule) return;
    try {
      const res = await apiDelete('/api/dns/rules', { rule });
      state.rules = res.rules || state.rules.filter((r) => r !== rule);
      if (state.overview) state.overview.user_rules = state.rules;
      writePageCache({ rules: state.rules, ...(state.overview ? { overview: state.overview } : {}) });
      renderAdguardAdmin();
      showToast(`Удалено: ${rule}`, 'info');
    } catch (err) {
      showToast(err.message, 'err');
    }
    return;
  }

  const rwDelBtn = tEl.closest('[data-rw-del-idx]');
  if (rwDelBtn) {
    const rw = state.rewrites[Number(rwDelBtn.dataset.rwDelIdx)];
    if (!rw) return;
    try {
      await apiDelete('/api/dns/rewrites', { domain: rw.domain, answer: rw.answer });
      state.rewrites = state.rewrites.filter((x) => !(x.domain === rw.domain && x.answer === rw.answer));
      writePageCache({ rewrites: state.rewrites });
      renderAdguardAdmin();
      showToast(`Удалено: ${rw.domain}`, 'info');
    } catch (err) {
      showToast(err.message, 'err');
    }
  }
});

function updateClock() {
  const el = document.getElementById('settings-live-clock');
  if (el) el.textContent = formatClock(cfg.tz);
}

applyI18n(cfg.lang);
renderPreferences();
updateClock();
setInterval(updateClock, 1000);
hydrateSettingsFromCache();
loadSettingsData();
