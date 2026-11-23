/* Fetch wrapper with explicit timeouts and uniform error extraction */

export async function apiRequest(url, options = {}) {
  const timeoutMs = options.timeoutMs || 10000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const headers = { ...(options.headers || {}) };
  let body = options.body;
  if (body !== undefined && typeof body !== 'string') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  try {
    const resp = await fetch(url, {
      method: options.method || 'GET',
      headers,
      body,
      cache: 'no-store',
      signal: controller.signal,
    });
    const text = await resp.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch (e) {
      data = { detail: text };
    }
    if (!resp.ok) {
      const msg = typeof data.detail === 'string' ? data.detail : `HTTP ${resp.status}`;
      throw new Error(msg);
    }
    return data;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Таймаут запроса к серверу');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export function apiGet(url, timeoutMs) {
  return apiRequest(url, { method: 'GET', timeoutMs });
}

export function apiPost(url, body, timeoutMs) {
  return apiRequest(url, { method: 'POST', body, timeoutMs });
}

export function apiPut(url, body, timeoutMs) {
  return apiRequest(url, { method: 'PUT', body, timeoutMs });
}

export function apiDelete(url, body, timeoutMs) {
  return apiRequest(url, { method: 'DELETE', body, timeoutMs });
}
