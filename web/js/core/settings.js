/* Theme, preferences, and RU/EN i18n store for VPN Controler */

export const SETTINGS_STORAGE_KEY = 'vc_settings_v1';

export const THEMES = [
  { id: 'warm-paper', name: 'Warm Paper', subRu: 'Светлая · По умолчанию', subEn: 'Light · Default', bg: '#f5f3ee', accent: '#059669' },
  { id: 'emerald-tactical', name: 'Emerald Tactical', subRu: 'Тёмная · Изумруд', subEn: 'Dark · Emerald', bg: '#090d0b', accent: '#10b981' },
  { id: 'obsidian-amber', name: 'Obsidian Amber', subRu: 'Как Server-Monitor', subEn: 'Matches Server-Monitor', bg: '#0d0d0f', accent: '#f59e0b' },
  { id: 'matte-copper', name: 'Matte Copper', subRu: 'Тёплая медь', subEn: 'Warm Copper', bg: '#0f0c0b', accent: '#f97316' },
];

export const THEME_COLORS = {
  'warm-paper': '#f5f3ee',
  'emerald-tactical': '#090d0b',
  'obsidian-amber': '#0d0d0f',
  'matte-copper': '#0f0c0b',
};

export const DEFAULT_SETTINGS = {
  theme: 'warm-paper',
  density: 'standard',
  refreshMs: 5000,
  defaultPauseMin: 15,
  defaultChartMode: 'mesh',
  lang: 'ru',
  tz: 'CET',
};

export const I18N = {
  ru: {
    navHome: 'Главная',
    navSettings: 'Настройки',
    statusProtected: 'Защищено',
    statusPaused: 'Пауза',
    statusOffline: 'Оффлайн',
    heroActive: 'Щит активен',
    heroPaused: 'Щит на паузе',
    heroOffline: 'AdGuard недоступен',
    resumeNow: 'Возобновить сейчас',
    copy: 'Копировать',
    kpiQueries: 'Запросы 24ч',
    kpiBlocked: 'Заблокировано',
    kpiPeers: 'Mesh Пиры',
    kpiLatency: 'Отклик DNS',
    segNet: 'Сеть',
    segLog: 'Лог DNS',
    segShield: 'Щит',
    activityTitle: 'Активность',
    chartMesh: 'Трафик Mesh',
    chartDns24: 'DNS 24ч',
    top24Title: 'Топ за 24 часа',
    topDomains: 'Домены',
    topClients: 'Клиенты',
    peersTitle: 'Устройства Tailscale Mesh',
    peersSub: 'Нажмите на устройство для пинга и деталей',
    searchPlaceholder: 'Поиск домена или клиента...',
    addRuleBtn: '+ Правило',
    quickRuleTitle: 'Быстрое правило AdGuard',
    btnBlock: 'Заблокировать',
    btnAllow: 'Разрешить',
    filterAll: 'Все',
    filterBlocked: 'Заблок.',
    filterAllowed: 'Разреш.',
    allDevices: 'Все устройства',
    modulesTitle: 'Модули защиты AdGuard',
    dohTitle: 'Upstream DoH шлюз',
    probeBtn: 'Замерить пинг',
    servicesTitle: 'Блокировка сервисов в 1 тап',
    servicesSub: 'Мгновенное ограничение для всей сети',
    settingsAppearance: 'Оформление',
    densityLabel: 'Плотность карточек',
    densityStd: 'Стандарт',
    densityCompact: 'Компакт',
    settingsBehavior: 'Обновление и поведение',
    refreshLabel: 'Интервал автообновления',
    defaultPauseLabel: 'Пауза щита по умолчанию',
    defaultChartLabel: 'График по умолчанию',
    langLabel: 'Язык',
    tzLabel: 'Часовой пояс',
    nodeTitle: 'Узел и подключение',
    pwaInstallBtn: 'Установить PWA',
    swResetBtn: 'Сбросить кэш Service Worker',
    userRulesTitle: 'Пользовательские правила',
    blocklistsTitle: 'Подписки фильтров',
    refreshFiltersBtn: 'Обновить',
    clearCacheBtn: 'Очистить кэш DNS',
    rewritesTitle: 'Локальные DNS-перезаписи',
    rewritesSub: 'Короткие домашние адреса *.home внутри сети',
  },
  en: {
    navHome: 'Home',
    navSettings: 'Settings',
    statusProtected: 'Protected',
    statusPaused: 'Paused',
    statusOffline: 'Offline',
    heroActive: 'Shield Active',
    heroPaused: 'Shield Paused',
    heroOffline: 'AdGuard Offline',
    resumeNow: 'Resume Now',
    copy: 'Copy',
    kpiQueries: 'Queries 24h',
    kpiBlocked: 'Blocked',
    kpiPeers: 'Mesh Peers',
    kpiLatency: 'DNS Latency',
    segNet: 'Network',
    segLog: 'DNS Log',
    segShield: 'Shield',
    activityTitle: 'Activity',
    chartMesh: 'Mesh Traffic',
    chartDns24: 'DNS 24h',
    top24Title: 'Top 24 Hours',
    topDomains: 'Domains',
    topClients: 'Clients',
    peersTitle: 'Tailscale Mesh Peers',
    peersSub: 'Tap a device for live ping and details',
    searchPlaceholder: 'Search domain or client...',
    addRuleBtn: '+ Rule',
    quickRuleTitle: 'Quick AdGuard Rule',
    btnBlock: 'Block',
    btnAllow: 'Allow',
    filterAll: 'All',
    filterBlocked: 'Blocked',
    filterAllowed: 'Allowed',
    allDevices: 'All devices',
    modulesTitle: 'AdGuard Protection Modules',
    dohTitle: 'Upstream DoH Gateway',
    probeBtn: 'Probe Ping',
    servicesTitle: '1-Tap Service Blocker',
    servicesSub: 'Instant restriction across your network',
    settingsAppearance: 'Appearance',
    densityLabel: 'Card density',
    densityStd: 'Standard',
    densityCompact: 'Compact',
    settingsBehavior: 'Refresh & Behavior',
    refreshLabel: 'Auto-refresh interval',
    defaultPauseLabel: 'Default shield pause',
    defaultChartLabel: 'Default chart mode',
    langLabel: 'Language',
    tzLabel: 'Timezone',
    nodeTitle: 'Node & Connection',
    pwaInstallBtn: 'Install PWA',
    swResetBtn: 'Reset Service Worker Cache',
    userRulesTitle: 'Custom Filtering Rules',
    blocklistsTitle: 'Filter Subscriptions',
    refreshFiltersBtn: 'Refresh',
    clearCacheBtn: 'Clear DNS Cache',
    rewritesTitle: 'Local DNS Rewrites',
    rewritesSub: 'Short *.home hostnames inside your network',
  },
};

export function getSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw);
    return {
      ...DEFAULT_SETTINGS,
      ...parsed,
      theme: THEME_COLORS[parsed.theme] ? parsed.theme : DEFAULT_SETTINGS.theme,
      density: parsed.density === 'compact' ? 'compact' : 'standard',
      lang: parsed.lang === 'en' ? 'en' : 'ru',
      tz: parsed.tz === 'UTC' ? 'UTC' : 'CET',
    };
  } catch (err) {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(partial) {
  const next = { ...getSettings(), ...partial };
  try {
    localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(next));
  } catch (err) {
    // Ignore storage errors
  }
  applyThemeAndDensity(next);
  return next;
}

export function applyThemeAndDensity(cfg = getSettings()) {
  const th = THEME_COLORS[cfg.theme] ? cfg.theme : DEFAULT_SETTINGS.theme;
  const bg = THEME_COLORS[th];
  const isDark = th !== 'warm-paper';
  const scheme = isDark ? 'dark' : 'light';

  const root = document.documentElement;
  root.dataset.theme = th;
  root.dataset.density = cfg.density === 'compact' ? 'compact' : 'standard';
  root.lang = cfg.lang === 'en' ? 'en' : 'ru';
  root.style.colorScheme = scheme;
  root.style.backgroundColor = bg;
  if (document.body) {
    document.body.style.backgroundColor = bg;
  }

  let metaTheme = document.querySelector('meta[name="theme-color"]');
  if (!metaTheme) {
    metaTheme = document.createElement('meta');
    metaTheme.name = 'theme-color';
    document.head.appendChild(metaTheme);
  }
  metaTheme.setAttribute('content', bg);

  let metaScheme = document.querySelector('meta[name="color-scheme"]');
  if (!metaScheme) {
    metaScheme = document.createElement('meta');
    metaScheme.name = 'color-scheme';
    document.head.appendChild(metaScheme);
  }
  metaScheme.setAttribute('content', scheme);

  const metaStatusBar = document.querySelector('meta[name="apple-mobile-web-app-status-bar-style"]');
  if (metaStatusBar) {
    metaStatusBar.setAttribute('content', isDark ? 'black-translucent' : 'default');
  }

  window.dispatchEvent(new CustomEvent('themechange', { detail: { theme: th } }));
}

export function t(key, lang = getSettings().lang) {
  const dict = I18N[lang] || I18N.ru;
  return dict[key] || I18N.ru[key] || key;
}

export function applyI18n(lang = getSettings().lang) {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.dataset.i18n;
    el.textContent = t(key, lang);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    const key = el.dataset.i18nPlaceholder;
    el.setAttribute('placeholder', t(key, lang));
  });
}
