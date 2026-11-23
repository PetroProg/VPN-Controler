/* Main page (Page 1: Главная — Shield-First + 3 Segments) */

import { apiGet, apiPost, apiPut } from '../core/api.js';
import { inspectAndGuardStorage, isCacheFresh, readPageCache, writePageCache } from '../core/cache.js';
import { applyI18n, applyThemeAndDensity, getSettings, t } from '../core/settings.js';
import {
  copyToClipboard,
  escapeHtml,
  initConfirmSheet,
  openConfirmSheet,
  registerServiceWorker,
  showToast,
} from '../core/ui.js';

const DOH_META = [
  { id: 'quad9', name: 'Quad9 🇨🇭', descRu: 'Швейцария + защита', descEn: 'Swiss privacy + threat block' },
  { id: 'cloudflare', name: 'Cloudflare ⚡', descRu: '1.1.1.1 быстрый', descEn: '1.1.1.1 fast edge' },
  { id: 'adguard', name: 'AdGuard 🛡️', descRu: 'Двойной фильтр', descEn: 'Double ad filtering' },
  { id: 'google', name: 'Google 🌐', descRu: '8.8.8.8 глобальный', descEn: '8.8.8.8 global DNS' },
];

const TOGGLE_META = [
  { id: 'adblock', labelRu: 'AdBlocker (Фильтрация рекламы)', labelEn: 'AdBlocker (Ad Filtering)', descRu: 'Блокирует трекеры и рекламные сети', descEn: 'Blocks ads and telemetry trackers' },
  { id: 'malware', labelRu: 'Антивирус и фишинг', labelEn: 'Malware & Phishing Shield', descRu: 'AdGuard SafeBrowsing защита от угроз', descEn: 'AdGuard SafeBrowsing threat protection' },
  { id: 'doh', labelRu: 'Шифрование DoH', labelEn: 'DoH Encryption', descRu: 'DNS-over-HTTPS до внешнего шлюза', descEn: 'Encrypted DNS-over-HTTPS upstream' },
  { id: 'safesearch', labelRu: 'SafeSearch', labelEn: 'SafeSearch', descRu: 'Безопасный поиск в Google / YouTube / Bing', descEn: 'Enforce SafeSearch on search engines' },
  { id: 'parental', labelRu: 'Родительский контроль', labelEn: 'Parental Control', descRu: 'Блокировка 18+ доменов по всей сети', descEn: 'Block adult domains network-wide' },
];

let cfg = getSettings();
applyThemeAndDensity(cfg);
registerServiceWorker();
initConfirmSheet();

const state = {
  segment: 'network',
  chartMode: cfg.defaultChartMode === 'dns24' ? 'dns24' : 'mesh',
  topMode: 'domains',
  selectedPauseMin: cfg.defaultPauseMin || 15,
  expandedPeerId: null,
  logSearch: '',
  logStatus: 'all',
  logClient: 'all',
  showQuickRule: false,
  vpn: null,
  traffic: null,
  overview: null,
  logs: [],
  services: [],
  activeServiceIds: [],
  dohLatencies: {},
  pauseRemainingSec: 0,
  isPolling: false,
};

let countdownTimer = null;
let refreshTimer = null;
let searchDebounce = null;
let servicesMutationSeq = 0;
let servicesSyncRunning = false;
let pendingServiceIds = null;
let lastServiceMutationAt = 0;

function formatCountdown(sec) {
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${String(m).padStart(2, '0')}:${String(rem).padStart(2, '0')}`;
}

function niceCeil(val, minTop = 50) {
  const target = Math.max(minTop, val * 1.2);
  const mag = Math.pow(10, Math.floor(Math.log10(target)));
  const norm = target / mag;
  if (norm <= 1.5) return 1.5 * mag;
  if (norm <= 2) return 2 * mag;
  if (norm <= 3) return 3 * mag;
  if (norm <= 5) return 5 * mag;
  return 10 * mag;
}

function updatePauseCountdownTick() {
  const ov = state.overview;
  if (!ov || !ov.online || ov.protection) {
    state.pauseRemainingSec = 0;
    return;
  }
  if (state.pauseRemainingSec > 0) {
    state.pauseRemainingSec -= 1;
    renderHeaderAndHero();
    if (state.pauseRemainingSec === 0) {
      loadOverviewAndLogs();
    }
  }
}

function renderHeaderAndHero() {
  const lang = cfg.lang;
  const ov = state.overview;
  const vpn = state.vpn;
  const adgOnline = Boolean(ov && ov.online);
  const isProtected = adgOnline ? Boolean(ov.protection) : false;

  const pill = document.getElementById('header-status-pill');
  const pillTxt = document.getElementById('header-status-text');
  const hero = document.getElementById('hero-card');
  const heroTitle = document.getElementById('hero-title');
  const heroSub = document.getElementById('hero-subtitle');
  const activeCtrls = document.getElementById('hero-active-controls');
  const pausedCtrls = document.getElementById('hero-paused-controls');
  const countdownEl = document.getElementById('hero-countdown-text');

  hero.classList.remove('is-paused', 'is-offline');
  pill.classList.remove('is-paused', 'is-offline');

  if (!ov || !adgOnline) {
    pill.classList.add('is-offline');
    pillTxt.textContent = t('statusOffline', lang);
    hero.classList.add('is-offline');
    heroTitle.textContent = t('heroOffline', lang);
    activeCtrls.classList.remove('hidden');
    pausedCtrls.classList.add('hidden');
  } else if (isProtected) {
    pillTxt.textContent = t('statusProtected', lang);
    heroTitle.textContent = t('heroActive', lang);
    activeCtrls.classList.remove('hidden');
    pausedCtrls.classList.add('hidden');
  } else {
    pill.classList.add('is-paused');
    const remStr = state.pauseRemainingSec > 0 ? ` ${formatCountdown(state.pauseRemainingSec)}` : '';
    pillTxt.textContent = `${t('statusPaused', lang)}${remStr}`;
    hero.classList.add('is-paused');
    heroTitle.textContent = t('heroPaused', lang);
    activeCtrls.classList.add('hidden');
    pausedCtrls.classList.remove('hidden');
    countdownEl.textContent = state.pauseRemainingSec > 0
      ? (lang === 'en' ? `Left ${formatCountdown(state.pauseRemainingSec)}` : `Осталось ${formatCountdown(state.pauseRemainingSec)}`)
      : (lang === 'en' ? 'Manual pause' : 'Ручная пауза');
  }

  const pOnline = vpn ? vpn.peers_online : 0;
  const pTotal = vpn ? vpn.peers_count : 0;
  const onlineWord = lang === 'en' ? 'online' : 'онлайн';
  heroSub.textContent = `AdGuard Home + Tailscale Mesh · ${pOnline}/${pTotal} ${onlineWord}`;

  const nodeIp = (vpn && vpn.self && vpn.self.ip) || (ov && ov.tailscale_ip) || '100.107.4.120';
  const nodeDns = (vpn && vpn.self && vpn.self.dns_name) || '';
  document.getElementById('hero-node-ip').textContent = nodeIp;
  document.getElementById('hero-node-dns').textContent = nodeDns ? `· ${nodeDns}` : '';
  document.getElementById('hero-copy-ip-btn').dataset.copy = nodeIp;

  document.querySelectorAll('.pause-dur-chip').forEach((chip) => {
    const mins = Number(chip.dataset.pauseMin);
    chip.classList.toggle('active', mins === state.selectedPauseMin);
  });
  const pauseBtnLabel = document.getElementById('hero-pause-btn-text');
  pauseBtnLabel.textContent = lang === 'en' ? `Pause ${state.selectedPauseMin}m` : `Пауза ${state.selectedPauseMin} мин`;
}

function renderKpis() {
  const ov = state.overview;
  const vpn = state.vpn;
  const stats = (ov && ov.stats) || {};
  const total = Number(stats.total_queries || 0);
  const blocked = Number(stats.blocked_queries || 0);
  const pct = Number(stats.blocked_percent || 0).toFixed(1);
  const threats = Number(stats.threats_count || 0);
  const avgMs = Number(stats.avg_latency_ms || 0).toFixed(1);

  document.getElementById('kpi-total-val').textContent = total.toLocaleString('en-US');
  document.getElementById('kpi-blocked-count').textContent = blocked.toLocaleString('en-US');
  document.getElementById('kpi-blocked-pct').textContent = `${pct}%`;
  document.getElementById('kpi-blocked-bar').style.width = `${Math.min(100, Number(pct))}%`;

  // Dynamic SVG sparkline from 24h query history
  const hist = Array.isArray(stats.dns_queries_history) ? stats.dns_queries_history : [];
  const poly = document.getElementById('kpi-sparkline-poly');
  if (poly && hist.length >= 2) {
    const maxV = Math.max(...hist, 1);
    const pts = hist.map((val, idx) => {
      const x = Math.round((idx / (hist.length - 1)) * 54) + 1;
      const y = Math.round(18 - (val / maxV) * 14);
      return `${x},${y}`;
    }).join(' ');
    poly.setAttribute('points', pts);
  }

  const pOnline = vpn ? vpn.peers_online : 0;
  const pCount = vpn ? vpn.peers_count : 0;
  const relay = (vpn && vpn.self && vpn.self.relay) || 'mesh';
  document.getElementById('kpi-peers-online').textContent = `${pOnline} / ${pCount}`;
  document.getElementById('kpi-peers-relay').textContent = relay;

  const provName = (DOH_META.find((p) => p.id === (ov && ov.provider)) || DOH_META[0]).name.split(' ')[0];
  document.getElementById('kpi-dns-ms').textContent = `${avgMs} ms`;
  document.getElementById('kpi-dns-provider').textContent = provName;
  document.getElementById('kpi-threats-badge').textContent =
    cfg.lang === 'en' ? `${threats} threats` : `${threats} угроз`;
}

function renderSegmentsNav() {
  document.querySelectorAll('.seg-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.segment === state.segment);
  });
  document.getElementById('seg-panel-network').classList.toggle('hidden', state.segment !== 'network');
  document.getElementById('seg-panel-dnslog').classList.toggle('hidden', state.segment !== 'dnslog');
  document.getElementById('seg-panel-shield').classList.toggle('hidden', state.segment !== 'shield');
  if (state.segment === 'network') {
    requestAnimationFrame(drawTelemetryCanvas);
  }
}

function drawTelemetryCanvas() {
  const canvas = document.getElementById('main-telemetry-canvas');
  if (!canvas || state.segment !== 'network') return;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return;

  const styles = getComputedStyle(document.documentElement);
  const cGrid = styles.getPropertyValue('--p-grid').trim() || 'rgba(128,128,128,0.12)';
  const cMuted = styles.getPropertyValue('--p-dim').trim() || '#71717a';
  const cRx = styles.getPropertyValue('--p-chart-rx').trim() || '#059669';
  const cRxFill = styles.getPropertyValue('--p-chart-rx-fill').trim() || 'rgba(5,150,105,0.18)';
  const cTx = styles.getPropertyValue('--p-chart-tx').trim() || '#d97706';
  const cTxFill = styles.getPropertyValue('--p-chart-tx-fill').trim() || 'rgba(217,119,6,0.13)';
  const cBlocked = styles.getPropertyValue('--p-chart-blocked').trim() || '#dc2626';

  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(rect.width * dpr);
  canvas.height = Math.round(rect.height * dpr);
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const leftPad = 38 * dpr;
  const topPad = 12 * dpr;
  const botPad = 20 * dpr;
  const cw = w - leftPad - 6 * dpr;
  const ch = h - topPad - botPad;

  ctx.strokeStyle = cGrid;
  ctx.lineWidth = 1 * dpr;
  ctx.font = `${Math.round(10 * dpr)}px monospace`;
  ctx.fillStyle = cMuted;

  if (state.chartMode === 'mesh') {
    const rxPts = (state.traffic && state.traffic.history_rx) || new Array(24).fill(0);
    const txPts = (state.traffic && state.traffic.history_tx) || new Array(24).fill(0);
    const peak = Math.max(...rxPts, ...txPts, 10);
    const maxVal = niceCeil(peak, 50);

    [0, 0.33, 0.66, 1].forEach((ratio) => {
      const val = Math.round(maxVal * ratio);
      const y = topPad + ch - ratio * ch;
      ctx.beginPath();
      ctx.moveTo(leftPad, y);
      ctx.lineTo(w - 4 * dpr, y);
      ctx.stroke();
      const lbl = val >= 1000 ? `${(val / 1000).toFixed(1)}M` : String(val);
      ctx.fillText(lbl, 2 * dpr, y + 3 * dpr);
    });

    function drawSeries(pts, stroke, fill) {
      if (pts.length < 2) return;
      const step = cw / (pts.length - 1);
      const yAt = (v) => topPad + ch - (Math.min(maxVal, Math.max(0, v)) / maxVal) * ch;

      ctx.beginPath();
      ctx.moveTo(leftPad, yAt(pts[0]));
      for (let i = 1; i < pts.length; i += 1) ctx.lineTo(leftPad + i * step, yAt(pts[i]));
      ctx.lineTo(leftPad + (pts.length - 1) * step, topPad + ch);
      ctx.lineTo(leftPad, topPad + ch);
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();

      ctx.beginPath();
      ctx.moveTo(leftPad, yAt(pts[0]));
      for (let i = 1; i < pts.length; i += 1) ctx.lineTo(leftPad + i * step, yAt(pts[i]));
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 2.2 * dpr;
      ctx.lineJoin = 'round';
      ctx.stroke();
    }

    drawSeries(rxPts, cRx, cRxFill);
    drawSeries(txPts, cTx, cTxFill);

    ctx.fillStyle = cMuted;
    ctx.fillText('-2m', leftPad, h - 4 * dpr);
    ctx.fillText(cfg.lang === 'en' ? 'now' : 'сейчас', w - 42 * dpr, h - 4 * dpr);
  } else {
    const stats = (state.overview && state.overview.stats) || {};
    const totPts = Array.isArray(stats.dns_queries_history) && stats.dns_queries_history.length
      ? stats.dns_queries_history
      : new Array(24).fill(0);
    const blkPts = Array.isArray(stats.blocked_history) && stats.blocked_history.length
      ? stats.blocked_history
      : new Array(24).fill(0);

    const peak = Math.max(...totPts, 20);
    const maxVal = niceCeil(peak, 100);

    [0, 0.33, 0.66, 1].forEach((ratio) => {
      const val = Math.round(maxVal * ratio);
      const y = topPad + ch - ratio * ch;
      ctx.beginPath();
      ctx.moveTo(leftPad, y);
      ctx.lineTo(w - 4 * dpr, y);
      ctx.stroke();
      const lbl = val >= 1000 ? `${(val / 1000).toFixed(1)}k` : String(val);
      ctx.fillText(lbl, 2 * dpr, y + 3 * dpr);
    });

    const n = totPts.length;
    const slot = cw / n;
    const bw = Math.max(3 * dpr, slot * 0.62);
    for (let i = 0; i < n; i += 1) {
      const x = leftPad + i * slot + (slot - bw) / 2;
      const totH = (Math.min(maxVal, totPts[i]) / maxVal) * ch;
      const blkH = (Math.min(maxVal, blkPts[i] || 0) / maxVal) * ch;

      ctx.fillStyle = cRxFill;
      ctx.fillRect(x, topPad + ch - totH, bw, totH);
      ctx.fillStyle = cRx;
      ctx.fillRect(x, topPad + ch - totH, bw, Math.min(2 * dpr, totH));

      ctx.fillStyle = cBlocked;
      ctx.fillRect(x, topPad + ch - blkH, bw, blkH);
    }

    ctx.fillStyle = cMuted;
    ctx.fillText('-24h', leftPad, h - 4 * dpr);
    ctx.fillText('-12h', leftPad + cw * 0.45, h - 4 * dpr);
    ctx.fillText(cfg.lang === 'en' ? 'now' : 'сейчас', w - 42 * dpr, h - 4 * dpr);
  }
}

function renderNetworkSegment() {
  document.querySelectorAll('.chart-mode-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.chartMode === state.chartMode);
  });

  const legend = document.getElementById('chart-legend');
  if (state.chartMode === 'mesh') {
    const tr = state.traffic || {};
    const rxText = tr.rx_mbps >= 1 ? `${tr.rx_mbps} Mb/s` : `${tr.rx_kbps ?? 0} Kb/s`;
    const txText = tr.tx_mbps >= 1 ? `${tr.tx_mbps} Mb/s` : `${tr.tx_kbps ?? 0} Kb/s`;
    legend.innerHTML = `<span class="mono" style="color:var(--p-ok);">↓ ${escapeHtml(rxText)}</span><span class="mono" style="color:var(--p-warn);">↑ ${escapeHtml(txText)}</span>`;
  } else {
    const qLbl = cfg.lang === 'en' ? 'Queries' : 'Запросы';
    const bLbl = cfg.lang === 'en' ? 'Blocked' : 'Блоки';
    legend.innerHTML = `<span style="color:var(--p-ok);">■ ${qLbl}</span><span style="color:var(--p-err);">■ ${bLbl}</span>`;
  }

  // Tailscale Mesh Peer Cards
  const peers = (state.vpn && state.vpn.peers) || [];
  document.getElementById('peers-count-badge').textContent =
    cfg.lang === 'en' ? `${peers.length} nodes` : `${peers.length} узлов`;

  const peersBox = document.getElementById('peers-accordion-list');
  if (!peers.length) {
    peersBox.innerHTML = `<div class="hint-box">Нет данных от Tailscale LocalAPI</div>`;
  } else {
    peersBox.innerHTML = peers.map((p) => {
      const isOpen = state.expandedPeerId === p.id;
      const osIcon = p.os === 'android' || p.os === 'ios' ? '📱' : (p.os === 'linux' ? '🐧' : '💻');
      const modeClass = !p.online ? '' : (p.direct ? 'ok' : 'warn');
      const pingText = p.online && p.ping_ms !== null && p.ping_ms !== undefined ? `${p.ping_ms} ms` : '';

      return `
        <div class="peer-item ${isOpen ? 'is-open' : ''}">
          <button type="button" data-peer-toggle="${escapeHtml(p.id)}" class="peer-summary">
            <div class="peer-left">
              <span>${osIcon}</span>
              <div style="min-width:0;">
                <div class="peer-name-row">
                  <span class="peer-dot ${p.online ? 'online' : ''}"></span>
                  <span class="peer-name">${escapeHtml(p.display_name || p.hostname)}</span>
                </div>
                <div class="peer-ip mono">${escapeHtml(p.ip || '—')}</div>
              </div>
            </div>
            <div class="peer-right">
              <span class="tag-pill mono ${modeClass}">${escapeHtml(p.mode)}</span>
              ${pingText ? `<span class="mono" style="font-size:0.75rem;font-weight:700;">${escapeHtml(pingText)}</span>` : ''}
            </div>
          </button>
          ${isOpen ? `
            <div class="peer-details">
              <div class="peer-detail-grid">
                <div><span style="color:var(--p-dim);">Трафик:</span> <span class="mono" style="font-weight:600;">${escapeHtml(p.rx_mb)}↓ / ${escapeHtml(p.tx_mb)}↑ MB</span></div>
                <div><span style="color:var(--p-dim);">Активность:</span> <span style="font-weight:600;">${escapeHtml(p.last_seen_label)}</span></div>
              </div>
              ${p.dns_name ? `<div class="mono row-truncate" style="color:var(--p-muted);">${escapeHtml(p.dns_name)}</div>` : ''}
              <div class="peer-actions">
                <button type="button" data-peer-ping="${escapeHtml(p.ip)}" data-peer-online="${p.online ? '1' : '0'}" class="btn-mini accent-soft flex-1">
                  ⚡ Пинг
                </button>
                <button type="button" data-copy="${escapeHtml(p.ip)}" class="btn-mini flex-1">
                  📋 Копировать IP
                </button>
              </div>
            </div>
          ` : ''}
        </div>
      `;
    }).join('');
  }

  // Top 24h
  document.querySelectorAll('.top-mode-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.topMode === state.topMode);
  });

  const stats = (state.overview && state.overview.stats) || {};
  const listData = state.topMode === 'domains' ? (stats.top_blocked || []) : (stats.top_clients || []);
  const topBox = document.getElementById('top-24h-list');
  if (!listData.length) {
    topBox.innerHTML = `<div class="hint-box">За 24 часа статистика пока пуста</div>`;
  } else {
    const maxVal = Math.max(...listData.map((x) => x.count), 1);
    topBox.innerHTML = listData.map((item) => {
      const label = state.topMode === 'domains' ? item.domain : (item.name || item.ip);
      const pctW = Math.round((item.count / maxVal) * 100);
      return `
        <div>
          <div class="top-row-head">
            <span class="mono row-truncate" style="font-weight:600;">${escapeHtml(label)}</span>
            <span class="mono" style="color:var(--p-muted);flex-shrink:0;">${Number(item.count).toLocaleString('en-US')}</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill ${state.topMode === 'domains' ? 'err' : ''}" style="width:${pctW}%;"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  requestAnimationFrame(drawTelemetryCanvas);
}

function updateClientDropdown() {
  const select = document.getElementById('dns-client-filter');
  if (!select) return;
  const current = state.logClient;
  const names = new Set();
  ((state.vpn && state.vpn.peers) || []).forEach((p) => {
    if (p.display_name) names.add(p.display_name);
  });
  state.logs.forEach((l) => {
    if (l.client_name) names.add(l.client_name);
  });
  const sorted = Array.from(names).sort((a, b) => a.localeCompare(b));
  select.innerHTML = `<option value="all">${escapeHtml(t('allDevices', cfg.lang))}</option>` +
    sorted.map((n) => `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`).join('');
  select.value = sorted.includes(current) || current === 'all' ? current : 'all';
}

function renderDnsLogSegment() {
  document.getElementById('quick-rule-drawer').classList.toggle('hidden', !state.showQuickRule);
  document.getElementById('dns-search-clear').classList.toggle('hidden', !state.logSearch);

  document.querySelectorAll('.log-status-chip').forEach((ch) => {
    ch.classList.toggle('active', ch.dataset.logStatus === state.logStatus);
  });

  const box = document.getElementById('dns-query-cards');
  if (!state.logs.length) {
    box.innerHTML = `<div class="card hint-box" style="text-align:center;">Запросы не найдены</div>`;
    return;
  }

  box.innerHTML = state.logs.map((item, idx) => {
    const isBlocked = item.status === 'blocked';
    return `
      <div class="card dns-card">
        <div class="dns-card-top">
          <span class="dns-domain mono">${escapeHtml(item.domain)}</span>
          <span class="tag-pill mono ${isBlocked ? 'err' : 'ok'}" style="flex-shrink:0;">
            ${isBlocked ? 'BLOCKED' : 'ALLOWED'}
          </span>
        </div>
        <div class="dns-card-bot">
          <span>
            <strong style="color:var(--p-text);">${escapeHtml(item.client_name || item.client_ip)}</strong>
            · ${escapeHtml(item.reason)}
            · <span class="mono">${escapeHtml(item.elapsed_ms)} ms</span>
            · <span class="mono">${escapeHtml(item.time)}</span>
          </span>
          <button type="button" data-log-idx="${idx}" class="btn-mini ${isBlocked ? '' : 'danger-soft'}">
            ${isBlocked ? 'Разблок.' : 'Заблок.'}
          </button>
        </div>
      </div>
    `;
  }).join('');
}

function renderShieldSegment() {
  const ov = state.overview;
  const toggles = (ov && ov.toggles) || {};
  const lang = cfg.lang;

  document.getElementById('shield-toggles-list').innerHTML = TOGGLE_META.map((item) => {
    const enabled = Boolean(toggles[item.id]);
    const label = lang === 'en' ? item.labelEn : item.labelRu;
    const desc = lang === 'en' ? item.descEn : item.descRu;
    return `
      <div class="toggle-row">
        <div style="min-width:0;">
          <div style="font-size:0.8125rem;font-weight:700;">${escapeHtml(label)}</div>
          <div style="font-size:0.75rem;color:var(--p-muted);">${escapeHtml(desc)}</div>
        </div>
        <button type="button" role="switch" aria-checked="${enabled}" data-toggle-id="${escapeHtml(item.id)}" class="switch-btn">
          <span class="switch-knob"></span>
        </button>
      </div>
    `;
  }).join('');

  const activeProvider = (ov && ov.provider) || 'quad9';
  document.getElementById('doh-providers-grid').innerHTML = DOH_META.map((p) => {
    const active = p.id === activeProvider;
    const lat = state.dohLatencies[p.id];
    const latText = lat !== undefined && lat !== null ? `${lat} ms` : '—';
    const latColor = lat !== undefined && lat !== null && lat <= 35 ? 'var(--p-ok)' : 'var(--p-warn)';
    return `
      <button type="button" data-doh-id="${escapeHtml(p.id)}" class="doh-card ${active ? 'active' : ''}">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:0.3rem;">
          <span style="font-size:0.8125rem;font-weight:700;">${escapeHtml(p.name)}</span>
          <span class="mono" style="font-size:0.75rem;font-weight:700;color:${latColor};">${escapeHtml(latText)}</span>
        </div>
        <span style="font-size:0.75rem;color:var(--p-muted);">${escapeHtml(lang === 'en' ? p.descEn : p.descRu)}</span>
      </button>
    `;
  }).join('');

  const blockedCnt = state.services.filter((s) => s.blocked).length;
  const badge = document.getElementById('blocked-services-badge');
  badge.textContent = lang === 'en' ? `${blockedCnt} blocked` : `${blockedCnt} заблок.`;
  badge.className = `tag-pill mono ${blockedCnt > 0 ? 'err' : ''}`;

  document.getElementById('blocked-services-grid').innerHTML = state.services.map((s) => `
    <button type="button" data-service-id="${escapeHtml(s.id)}" class="service-tile ${s.blocked ? 'blocked' : ''}">
      <span class="row-truncate">${escapeHtml(s.name)}</span>
      <span class="mono" style="font-size:0.75rem;color:${s.blocked ? 'var(--p-err)' : 'var(--p-ok)'};flex-shrink:0;">
        ${s.blocked ? 'БЛОК' : 'ON'}
      </span>
    </button>
  `).join('');
}

async function loadVpnStatusAndTraffic() {
  const [vpnRes, trafRes] = await Promise.allSettled([
    apiGet('/api/vpn/status'),
    apiGet('/api/vpn/traffic'),
  ]);
  const patch = {};
  if (vpnRes.status === 'fulfilled') {
    state.vpn = vpnRes.value;
    patch.vpn = vpnRes.value;
  }
  if (trafRes.status === 'fulfilled') {
    state.traffic = trafRes.value;
    patch.traffic = trafRes.value;
  }
  if (Object.keys(patch).length) writePageCache(patch);
}

async function loadOverviewAndLogs() {
  const reqSeq = servicesMutationSeq;
  const q = new URLSearchParams({
    limit: '60',
    filter: state.logStatus,
    search: state.logSearch.trim(),
    client: state.logClient === 'all' ? '' : state.logClient,
  });
  const [ovRes, logRes] = await Promise.allSettled([
    apiGet('/api/dns/overview'),
    apiGet(`/api/dns/querylog?${q.toString()}`),
  ]);
  const patch = {};
  if (ovRes.status === 'fulfilled') {
    const canSyncServices = !servicesSyncRunning
      && reqSeq === servicesMutationSeq
      && (Date.now() - lastServiceMutationAt) > 2500;
    const prevBlockedIds = state.overview && Array.isArray(state.overview.blocked_service_ids)
      ? state.overview.blocked_service_ids
      : state.activeServiceIds;
    state.overview = ovRes.value;
    if (!canSyncServices && Array.isArray(prevBlockedIds)) {
      state.overview.blocked_service_ids = prevBlockedIds;
    }
    patch.overview = state.overview;
    const durMs = Number(ovRes.value.protection_disabled_duration_ms || 0);
    state.pauseRemainingSec = !ovRes.value.protection && durMs > 0 ? Math.ceil(durMs / 1000) : 0;
    if (canSyncServices && Array.isArray(ovRes.value.blocked_service_ids)) {
      const activeIds = ovRes.value.blocked_service_ids.map((x) => String(x).toLowerCase());
      const activeSet = new Set(activeIds);
      state.activeServiceIds = activeIds;
      patch.activeServiceIds = activeIds;
      if (state.services.length) {
        state.services = state.services.map((s) => ({ ...s, blocked: activeSet.has(s.id) }));
        patch.services = state.services;
      }
    }
  }
  if (logRes.status === 'fulfilled' && Array.isArray(logRes.value.logs)) {
    state.logs = logRes.value.logs;
    if (state.logStatus === 'all' && !state.logSearch.trim() && state.logClient === 'all') {
      patch.logs = logRes.value.logs;
    }
    updateClientDropdown();
  }
  if (Object.keys(patch).length) writePageCache(patch);
}

async function loadServicesAndLatencies(forceProbe = false) {
  const reqSeq = servicesMutationSeq;
  const [svcRes, latRes] = await Promise.allSettled([
    apiGet('/api/dns/services'),
    apiGet(`/api/dns/doh-latency?force=${forceProbe ? 'true' : 'false'}`),
  ]);
  const patch = {};
  if (
    svcRes.status === 'fulfilled'
    && Array.isArray(svcRes.value.services)
    && !servicesSyncRunning
    && reqSeq === servicesMutationSeq
  ) {
    state.services = svcRes.value.services;
    state.activeServiceIds = svcRes.value.active_ids || [];
    patch.services = state.services;
    patch.activeServiceIds = state.activeServiceIds;
  }
  if (latRes.status === 'fulfilled' && latRes.value.latencies) {
    state.dohLatencies = latRes.value.latencies;
    patch.dohLatencies = state.dohLatencies;
  }
  if (Object.keys(patch).length) writePageCache(patch);
}

async function flushBlockedServicesSync() {
  if (servicesSyncRunning) return;
  servicesSyncRunning = true;
  try {
    while (pendingServiceIds !== null) {
      const targetIds = pendingServiceIds;
      pendingServiceIds = null;
      await apiPut('/api/dns/services', { ids: targetIds });
    }
  } catch (err) {
    showToast(err.message || 'Ошибка синхронизации сервисов', 'err');
    if (pendingServiceIds === null) {
      servicesSyncRunning = false;
      await loadServicesAndLatencies(false);
      renderShieldSegment();
      return;
    }
  } finally {
    servicesSyncRunning = false;
  }
}

function renderAllViews() {
  renderHeaderAndHero();
  renderKpis();
  renderNetworkSegment();
  renderDnsLogSegment();
  renderShieldSegment();
}

function hydrateFromCache() {
  const cached = readPageCache();
  if (!cached) return { hasCache: false, isFresh: false, servicesFresh: false };

  let hasAny = false;
  if (cached.segment && ['network', 'dnslog', 'shield'].includes(cached.segment)) {
    state.segment = cached.segment;
  }
  if (cached.chartMode && ['mesh', 'dns24'].includes(cached.chartMode)) {
    state.chartMode = cached.chartMode;
  }
  if (cached.topMode && ['domains', 'clients'].includes(cached.topMode)) {
    state.topMode = cached.topMode;
  }
  if (cached.vpn) {
    state.vpn = cached.vpn;
    hasAny = true;
  }
  if (cached.traffic) {
    state.traffic = cached.traffic;
    hasAny = true;
  }
  if (cached.overview) {
    state.overview = cached.overview;
    const durMs = Number(cached.overview.protection_disabled_duration_ms || 0);
    const elapsedSec = cached.timestamps && cached.timestamps.overview
      ? Math.max(0, Math.floor((Date.now() - cached.timestamps.overview) / 1000))
      : 0;
    state.pauseRemainingSec = !cached.overview.protection && durMs > 0
      ? Math.max(0, Math.ceil(durMs / 1000) - elapsedSec)
      : 0;
    hasAny = true;
  }
  if (Array.isArray(cached.logs)) {
    state.logs = cached.logs;
    updateClientDropdown();
    hasAny = true;
  }
  if (Array.isArray(cached.services)) {
    state.services = cached.services;
    state.activeServiceIds = cached.activeServiceIds || cached.services.filter((s) => s.blocked).map((s) => s.id);
    hasAny = true;
  }
  if (cached.dohLatencies && typeof cached.dohLatencies === 'object') {
    state.dohLatencies = cached.dohLatencies;
  }

  if (hasAny) {
    renderSegmentsNav();
    renderAllViews();
  }

  const freshTtl = cfg.refreshMs > 0 ? Math.max(cfg.refreshMs, 10000) : 30000;
  const isFresh = isCacheFresh(cached, ['vpn', 'traffic', 'overview', 'logs'], freshTtl);
  const servicesFresh = isCacheFresh(cached, ['services', 'dohLatencies'], 60000);
  return { hasCache: hasAny, isFresh, servicesFresh };
}

async function refreshAll(includeLatencies = false) {
  if (state.isPolling) return;
  state.isPolling = true;
  try {
    await Promise.all([
      loadVpnStatusAndTraffic(),
      loadOverviewAndLogs(),
      includeLatencies ? loadServicesAndLatencies(false) : Promise.resolve(),
    ]);
    renderAllViews();
  } finally {
    state.isPolling = false;
  }
}

function setupRefreshLoop() {
  if (refreshTimer) clearInterval(refreshTimer);
  if (cfg.refreshMs > 0) {
    refreshTimer = setInterval(() => {
      if (!document.hidden) {
        refreshAll(false);
      }
    }, cfg.refreshMs);
  }
}

// Direct Listeners
document.getElementById('refresh-btn').addEventListener('click', async () => {
  const ico = document.getElementById('refresh-icon');
  ico.classList.remove('spin-once');
  void ico.offsetWidth;
  ico.classList.add('spin-once');
  await refreshAll(true);
  showToast('Телеметрия обновлена', 'ok');
});

document.getElementById('hero-pause-btn').addEventListener('click', async () => {
  try {
    const res = await apiPost('/api/dns/pause', { minutes: state.selectedPauseMin });
    state.pauseRemainingSec = Math.round((res.duration_ms || state.selectedPauseMin * 60000) / 1000);
    await loadOverviewAndLogs();
    renderHeaderAndHero();
    showToast(`Защита приостановлена на ${state.selectedPauseMin} мин`, 'warn');
  } catch (err) {
    showToast(err.message, 'err');
  }
});

document.getElementById('hero-resume-btn').addEventListener('click', async () => {
  try {
    await apiPost('/api/dns/toggle', { feature: 'protection', enabled: true });
    state.pauseRemainingSec = 0;
    await loadOverviewAndLogs();
    renderHeaderAndHero();
    showToast('Защита AdGuard возобновлена', 'ok');
  } catch (err) {
    showToast(err.message, 'err');
  }
});

document.getElementById('dns-search-input').addEventListener('input', (e) => {
  state.logSearch = e.target.value;
  document.getElementById('dns-search-clear').classList.toggle('hidden', !state.logSearch);
  if (searchDebounce) clearTimeout(searchDebounce);
  searchDebounce = setTimeout(async () => {
    await loadOverviewAndLogs();
    renderDnsLogSegment();
  }, 260);
});

document.getElementById('dns-search-clear').addEventListener('click', async () => {
  state.logSearch = '';
  document.getElementById('dns-search-input').value = '';
  await loadOverviewAndLogs();
  renderDnsLogSegment();
});

document.getElementById('dns-client-filter').addEventListener('change', async (e) => {
  state.logClient = e.target.value;
  await loadOverviewAndLogs();
  renderDnsLogSegment();
});

document.getElementById('toggle-quick-rule-btn').addEventListener('click', () => {
  state.showQuickRule = !state.showQuickRule;
  renderDnsLogSegment();
});

async function submitQuickRule(mode) {
  const inp = document.getElementById('quick-rule-domain');
  const domain = inp.value.trim();
  if (!domain) {
    showToast('Введите домен', 'warn');
    return;
  }
  try {
    const res = await apiPost('/api/dns/rules', { domain, mode });
    inp.value = '';
    showToast(`${mode === 'allow' ? 'Исключение' : 'Блок'}: ${res.rule}`, mode === 'allow' ? 'ok' : 'warn');
    await loadOverviewAndLogs();
    renderDnsLogSegment();
  } catch (err) {
    showToast(err.message, 'err');
  }
}

document.getElementById('quick-rule-block-btn').addEventListener('click', () => submitQuickRule('block'));
document.getElementById('quick-rule-allow-btn').addEventListener('click', () => submitQuickRule('allow'));

document.getElementById('probe-doh-btn').addEventListener('click', async () => {
  const ico = document.getElementById('probe-doh-icon');
  ico.classList.remove('spin-once');
  void ico.offsetWidth;
  ico.classList.add('spin-once');
  try {
    const res = await apiGet('/api/dns/doh-latency?force=true');
    state.dohLatencies = res.latencies || {};
    writePageCache({ dohLatencies: state.dohLatencies });
    renderShieldSegment();
    showToast('Пинг DoH шлюзов замерен', 'ok');
  } catch (err) {
    showToast(err.message, 'err');
  }
});

// Delegated Clicks inside Main Shell
document.querySelector('main').addEventListener('click', async (e) => {
  const tEl = e.target;

  const copyBtn = tEl.closest('[data-copy]');
  if (copyBtn) {
    await copyToClipboard(copyBtn.dataset.copy);
    return;
  }

  const pauseChip = tEl.closest('[data-pause-min]');
  if (pauseChip) {
    state.selectedPauseMin = Number(pauseChip.dataset.pauseMin);
    renderHeaderAndHero();
    return;
  }

  const segBtn = tEl.closest('[data-segment]');
  if (segBtn) {
    state.segment = segBtn.dataset.segment;
    writePageCache({ segment: state.segment });
    renderSegmentsNav();
    return;
  }

  const chartModeBtn = tEl.closest('[data-chart-mode]');
  if (chartModeBtn) {
    state.chartMode = chartModeBtn.dataset.chartMode;
    writePageCache({ chartMode: state.chartMode });
    renderNetworkSegment();
    return;
  }

  const topModeBtn = tEl.closest('[data-top-mode]');
  if (topModeBtn) {
    state.topMode = topModeBtn.dataset.topMode;
    writePageCache({ topMode: state.topMode });
    renderNetworkSegment();
    return;
  }

  const pingBtn = tEl.closest('[data-peer-ping]');
  if (pingBtn) {
    const ip = pingBtn.dataset.peerPing;
    const isOn = pingBtn.dataset.peerOnline === '1';
    if (!isOn) {
      showToast('Устройство не в сети', 'warn');
      return;
    }
    try {
      const res = await apiPost('/api/vpn/ping?force=true', { ip });
      if (res.success) {
        const peer = (state.vpn && state.vpn.peers || []).find((p) => p.ip === ip);
        if (peer) {
          peer.ping_ms = res.latency_ms;
          peer.mode = res.mode;
          peer.direct = res.direct;
          writePageCache({ vpn: state.vpn });
        }
        renderNetworkSegment();
        showToast(`Пинг ${ip}: ${res.latency_ms} ms (${res.mode})`, 'ok');
      } else {
        showToast(res.error || 'Узел недоступен', 'warn');
      }
    } catch (err) {
      showToast(err.message, 'err');
    }
    return;
  }

  const peerToggle = tEl.closest('[data-peer-toggle]');
  if (peerToggle) {
    const pid = peerToggle.dataset.peerToggle;
    state.expandedPeerId = state.expandedPeerId === pid ? null : pid;
    renderNetworkSegment();
    return;
  }

  const statusChip = tEl.closest('[data-log-status]');
  if (statusChip) {
    state.logStatus = statusChip.dataset.logStatus;
    await loadOverviewAndLogs();
    renderDnsLogSegment();
    return;
  }

  const logBtn = tEl.closest('[data-log-idx]');
  if (logBtn) {
    const item = state.logs[Number(logBtn.dataset.logIdx)];
    if (!item) return;
    const isBlocked = item.status === 'blocked';
    if (!isBlocked) {
      openConfirmSheet({
        title: 'Заблокировать домен?',
        desc: `Все DNS-запросы к домену «${item.domain}» будут блокироваться для всех устройств.`,
        preview: `Добавить правило: ||${item.domain}^`,
        confirmLabel: 'Заблокировать',
        confirmTone: 'err',
        onConfirm: async () => {
          try {
            await apiPost('/api/dns/block', { domain: item.domain });
            showToast(`Заблокирован ${item.domain}`, 'warn');
            await loadOverviewAndLogs();
            renderKpis();
            renderDnsLogSegment();
          } catch (err) {
            showToast(err.message, 'err');
          }
        },
      });
    } else {
      const fromList = item.source !== 'user_rule';
      openConfirmSheet({
        title: 'Разблокировать домен?',
        desc: fromList
          ? `Домен «${item.domain}» заблокирован подпиской (${item.reason}). Умная разблокировка добавит белое правило @@.`
          : `Удалить ручное правило блокировки для «${item.domain}»?`,
        preview: fromList ? `Добавить исключение: @@||${item.domain}^` : `Удалить правило: ||${item.domain}^`,
        confirmLabel: 'Разблокировать',
        confirmTone: 'ok',
        onConfirm: async () => {
          try {
            const res = await apiPost('/api/dns/unblock', { domain: item.domain });
            showToast(`Разблокирован: ${res.rule}`, 'ok');
            await loadOverviewAndLogs();
            renderKpis();
            renderDnsLogSegment();
          } catch (err) {
            showToast(err.message, 'err');
          }
        },
      });
    }
    return;
  }

  const toggleBtn = tEl.closest('[data-toggle-id]');
  if (toggleBtn) {
    const feature = toggleBtn.dataset.toggleId;
    const current = toggleBtn.getAttribute('aria-checked') === 'true';
    const nextVal = !current;
    if (state.overview && state.overview.toggles) {
      state.overview.toggles[feature] = nextVal;
      writePageCache({ overview: state.overview });
    }
    renderShieldSegment();
    showToast(`Модуль обновлён: ${nextVal ? 'Вкл' : 'Выкл'}`, nextVal ? 'ok' : 'info');
    try {
      await apiPost('/api/dns/toggle', { feature, enabled: nextVal });
    } catch (err) {
      if (state.overview && state.overview.toggles) {
        state.overview.toggles[feature] = current;
        writePageCache({ overview: state.overview });
      }
      renderShieldSegment();
      showToast(err.message, 'err');
    }
    return;
  }

  const dohBtn = tEl.closest('[data-doh-id]');
  if (dohBtn) {
    const provider = dohBtn.dataset.dohId;
    const prevProvider = state.overview ? state.overview.provider : null;
    if (state.overview) {
      state.overview.provider = provider;
      writePageCache({ overview: state.overview });
    }
    renderKpis();
    renderShieldSegment();
    showToast(`Активный шлюз: ${provider}`, 'ok');
    try {
      await apiPost('/api/dns/upstream', { provider });
    } catch (err) {
      if (state.overview && prevProvider) {
        state.overview.provider = prevProvider;
        writePageCache({ overview: state.overview });
      }
      renderKpis();
      renderShieldSegment();
      showToast(err.message, 'err');
    }
    return;
  }

  const svcBtn = tEl.closest('[data-service-id]');
  if (svcBtn) {
    const sid = svcBtn.dataset.serviceId;
    const currentSet = new Set(
      state.activeServiceIds && state.activeServiceIds.length
        ? state.activeServiceIds
        : state.services.filter((s) => s.blocked).map((s) => s.id),
    );
    const willBlock = !currentSet.has(sid);
    if (willBlock) currentSet.add(sid);
    else currentSet.delete(sid);
    const nextIds = Array.from(currentSet);

    servicesMutationSeq += 1;
    lastServiceMutationAt = Date.now();
    state.activeServiceIds = nextIds;
    state.services = state.services.map((s) => ({ ...s, blocked: currentSet.has(s.id) }));
    if (state.overview) {
      state.overview.blocked_service_ids = nextIds;
    }
    writePageCache({
      services: state.services,
      activeServiceIds: state.activeServiceIds,
      ...(state.overview ? { overview: state.overview } : {}),
    });
    renderShieldSegment();
    showToast(`${sid}: ${willBlock ? 'заблокирован' : 'разблокирован'}`, willBlock ? 'warn' : 'ok');

    pendingServiceIds = nextIds;
    flushBlockedServicesSync();
  }
});

window.addEventListener('resize', () => requestAnimationFrame(drawTelemetryCanvas));
window.addEventListener('themechange', () => requestAnimationFrame(drawTelemetryCanvas));

applyI18n(cfg.lang);
renderSegmentsNav();
inspectAndGuardStorage().catch(() => {});
const cacheStatus = hydrateFromCache();
countdownTimer = setInterval(updatePauseCountdownTick, 1000);
if (!cacheStatus.isFresh) {
  refreshAll(!cacheStatus.servicesFresh);
} else if (!cacheStatus.servicesFresh) {
  loadServicesAndLatencies(false).then(() => renderShieldSegment());
}
setupRefreshLoop();
