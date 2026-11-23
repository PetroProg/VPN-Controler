/* Client-side state & telemetry cache (in-memory sessionStorage only — zero LevelDB disk churn) */

export const CACHE_STORAGE_KEY = 'vc_telemetry_cache_v1';
export const DEFAULT_TTL_MS = 15000;
const MAX_SESSION_BYTES = 65536;
const MAX_CACHED_LOGS = 30;
const MAX_VC_STORAGE_BYTES = 15 * 1024 * 1024; // 15 MB safety ceiling for VPN Controler origin

// Purge legacy localStorage telemetry key once on startup to stop LevelDB bloat
try {
  localStorage.removeItem(CACHE_STORAGE_KEY);
} catch (err) {
  // Ignore storage access errors
}

export function readPageCache() {
  try {
    const raw = sessionStorage.getItem(CACHE_STORAGE_KEY);
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

    if (Array.isArray(next.logs) && next.logs.length > MAX_CACHED_LOGS) {
      next.logs = next.logs.slice(0, MAX_CACHED_LOGS);
    }

    const serialized = JSON.stringify(next);
    if (serialized.length <= MAX_SESSION_BYTES) {
      sessionStorage.setItem(CACHE_STORAGE_KEY, serialized);
    }
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

export function formatStorageBytes(bytes) {
  const b = Number(bytes || 0);
  if (!Number.isFinite(b) || b <= 0) return '0 КБ';
  if (b < 1024) return `${b} Б`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} КБ`;
  return `${(b / (1024 * 1024)).toFixed(2)} МБ`;
}

/**
 * Inspects only VPN Controler's own origin storage and vc-* caches,
 * auto-purging legacy vc-api-* caches or oversized vc-* caches without touching other apps.
 */
export async function inspectAndGuardStorage(maxBytes = MAX_VC_STORAGE_BYTES) {
  try {
    localStorage.removeItem(CACHE_STORAGE_KEY);
  } catch (err) {
    // Ignore
  }

  let purgedLegacy = false;
  if ('caches' in window) {
    try {
      const keys = await caches.keys();
      for (const key of keys) {
        if (key.startsWith('vc-api-')) {
          await caches.delete(key);
          purgedLegacy = true;
        }
      }
    } catch (err) {
      // Ignore CacheStorage errors
    }
  }

  let usageBytes = 0;
  let quotaBytes = 0;
  if (navigator.storage && typeof navigator.storage.estimate === 'function') {
    try {
      const est = await navigator.storage.estimate();
      usageBytes = Number(est.usage || 0);
      quotaBytes = Number(est.quota || 0);
    } catch (err) {
      // Ignore estimate errors
    }
  }

  if (usageBytes > maxBytes && 'caches' in window) {
    try {
      const keys = await caches.keys();
      await Promise.all(
        keys.map((k) => (k.startsWith('vc-') ? caches.delete(k) : null))
      );
      purgedLegacy = true;
      if (navigator.storage && typeof navigator.storage.estimate === 'function') {
        const estAfter = await navigator.storage.estimate();
        usageBytes = Number(estAfter.usage || 0);
      }
    } catch (err) {
      // Ignore cleanup errors
    }
  }

  return {
    usageBytes,
    quotaBytes,
    formattedUsage: formatStorageBytes(usageBytes),
    purgedLegacy,
  };
}
