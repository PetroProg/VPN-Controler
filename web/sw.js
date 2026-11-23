/* VPN Controler Service Worker (Offline-ready App Shell + Network-First API) */

const CACHE_VERSION = 'vc-v1.1.1';
const SHELL_CACHE = `vc-shell-${CACHE_VERSION}`;
const API_CACHE = `vc-api-${CACHE_VERSION}`;

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

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(SHELL_CACHE).then(async (cache) => {
      for (const url of PRECACHE_URLS) {
        try {
          await cache.add(url);
        } catch (err) {
          // Ignore individual precache failure
        }
      }
    })
  );
});

self.addEventListener('activate', (event) => {
  const allowed = new Set([SHELL_CACHE, API_CACHE]);
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.map((k) => (!allowed.has(k) ? caches.delete(k) : null))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // 1. API GET requests: Network-First with cached offline fallback
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(API_CACHE);
        try {
          const netResp = await fetch(request);
          if (netResp && netResp.ok) {
            cache.put(request, netResp.clone());
          }
          return netResp;
        } catch (err) {
          const cached = await cache.match(request);
          if (cached) return cached;
          return new Response(
            JSON.stringify({ offline: true, online: false, error: 'Offline mode' }),
            { status: 503, headers: { 'Content-Type': 'application/json', 'X-PWA-Offline': 'true' } }
          );
        }
      })()
    );
    return;
  }

  // 2. HTML navigation: Stale-While-Revalidate (instant page switch)
  if (request.mode === 'navigate' || url.pathname === '/' || url.pathname === '/vpn' || url.pathname === '/settings') {
    event.respondWith(
      (async () => {
        const cache = await caches.open(SHELL_CACHE);
        const cacheKey = url.pathname === '/vpn' ? '/' : url.pathname;
        const cached = await cache.match(cacheKey);
        const netPromise = fetch(request)
          .then((netResp) => {
            if (netResp && netResp.ok) {
              cache.put(cacheKey, netResp.clone());
            }
            return netResp;
          })
          .catch(() => null);

        if (cached) return cached;
        const netResp = await netPromise;
        if (netResp) return netResp;
        return (await cache.match('/')) || new Response('Offline', { status: 503 });
      })()
    );
    return;
  }

  // 3. Static CSS / JS / Icons: Stale-While-Revalidate
  event.respondWith(
    (async () => {
      const cache = await caches.open(SHELL_CACHE);
      const cached = await cache.match(request, { ignoreSearch: true });
      const netPromise = fetch(request)
        .then((netResp) => {
          if (netResp && netResp.ok) {
            cache.put(request, netResp.clone());
          }
          return netResp;
        })
        .catch(() => null);
      if (cached) return cached;
      const netResp = await netPromise;
      return netResp || new Response('', { status: 504 });
    })()
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
