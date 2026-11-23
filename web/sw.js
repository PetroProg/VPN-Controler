/* VPN Controler Service Worker (Lightweight App Shell Only — Zero API Disk Cache) */

const CACHE_VERSION = 'vc-v1.2.1';
const SHELL_CACHE = `vc-shell-${CACHE_VERSION}`;

const PRECACHE_URLS = [
  '/',
  '/settings',
  '/manifest.webmanifest',
  '/css/themes.css',
  '/css/app.css',
  '/js/core/settings.js',
  '/js/core/cache.js',
  '/js/core/api.js',
  '/js/core/ui.js',
  '/js/pages/vpn.js',
  '/js/pages/settings.js',
  '/icons/favicon.svg',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/apple-touch-icon.png',
];

const PRECACHE_SET = new Set(PRECACHE_URLS);

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(SHELL_CACHE).then(async (cache) => {
      for (const url of PRECACHE_URLS) {
        try {
          const req = new Request(url, { cache: 'reload' });
          const resp = await fetch(req);
          if (resp && resp.ok) {
            await cache.put(url, resp);
          }
        } catch (err) {
          // Ignore individual precache failure
        }
      }
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) =>
        Promise.all(
          keys.map((k) => (k.startsWith('vc-') && k !== SHELL_CACHE ? caches.delete(k) : null))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // 1. API requests: NEVER write to CacheStorage (prevents SimpleCache/LevelDB bloat)
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // 2. HTML navigation: serve cached shell immediately, only write on miss
  if (request.mode === 'navigate' || url.pathname === '/' || url.pathname === '/vpn' || url.pathname === '/settings') {
    event.respondWith(
      (async () => {
        const cache = await caches.open(SHELL_CACHE);
        const cacheKey = url.pathname === '/vpn' ? '/' : url.pathname;
        const cached = await cache.match(cacheKey);
        if (cached) {
          return cached;
        }
        try {
          const netResp = await fetch(request);
          if (netResp && netResp.ok) {
            await cache.put(cacheKey, netResp.clone());
          }
          return netResp;
        } catch (err) {
          return (await cache.match('/')) || new Response('Offline', { status: 503 });
        }
      })()
    );
    return;
  }

  // 3. Static CSS / JS / Icons: strict Cache-First (no disk writes on hit)
  event.respondWith(
    (async () => {
      const cache = await caches.open(SHELL_CACHE);
      const canonicalKey = PRECACHE_SET.has(url.pathname) ? url.pathname : request;
      const cached = await cache.match(canonicalKey, { ignoreSearch: true });
      if (cached) {
        return cached;
      }
      try {
        const netResp = await fetch(request);
        if (netResp && netResp.ok && PRECACHE_SET.has(url.pathname)) {
          await cache.put(url.pathname, netResp.clone());
        }
        return netResp;
      } catch (err) {
        return new Response('', { status: 504 });
      }
    })()
  );
});

self.addEventListener('message', (event) => {
  if (!event.data) return;
  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  } else if (event.data.type === 'CLEAR_VC_CACHES') {
    event.waitUntil(
      caches.keys().then((keys) =>
        Promise.all(keys.map((k) => (k.startsWith('vc-') ? caches.delete(k) : null)))
      )
    );
  }
});
