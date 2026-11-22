/* Client-side state & telemetry cache (Stale-While-Revalidate across page switches) */

export const CACHE_STORAGE_KEY = 'vc_telemetry_cache_v1';
export const DEFAULT_TTL_MS = 15000;

export function readPageCache() {
  try {
    const raw = sessionStorage.getItem(CACHE_STORAGE_KEY) || localStorage.getItem(CACHE_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (err) {
    return null;
  }
}

export function writePageCache(partial) {
  try {
    const prev = readPageCache() || {};
    const now = Date.now();
    const prevTs = (prev.timestamps && typeof prev.timestamps === 'object') ? prev.timestamps : {};
    const nextTs = { ...prevTs };

    Object.keys(partial).forEach((key) => {
      if (key !== 'timestamps' && key !== 'updatedAt') {
        nextTs[key] = now;
      }
    });

    const next = {
      ...prev,
      ...partial,
      updatedAt: now,
      timestamps: nextTs,
    };
    const serialized = JSON.stringify(next);
    sessionStorage.setItem(CACHE_STORAGE_KEY, serialized);
    localStorage.setItem(CACHE_STORAGE_KEY, serialized);
    return next;
  } catch (err) {
    return null;
  }
}

export function isCacheFresh(cache, keys, maxAgeMs = DEFAULT_TTL_MS) {
  if (!cache || typeof cache !== 'object') return false;
  const tsMap = cache.timestamps || {};
  const now = Date.now();
  return keys.every((k) => {
    if (cache[k] === undefined || cache[k] === null) return false;
    const ts = tsMap[k] || cache.updatedAt || 0;
    return ts > 0 && (now - ts) < maxAgeMs;
  });
}

export function clearPageCache() {
  try {
    sessionStorage.removeItem(CACHE_STORAGE_KEY);
    localStorage.removeItem(CACHE_STORAGE_KEY);
  } catch (err) {
    // Ignore storage errors
  }
}
