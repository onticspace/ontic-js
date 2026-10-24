export class APIError extends Error {
  constructor(status, detail = {}) {
    super(detail.message || `The request failed (${status}).`);
    this.name = 'APIError'; this.status = status; this.code = detail.code;
    this.fields = detail.fields; this.statementID = detail.statement_id;
  }
}

// Credentials stay in this client instance; browser refresh cookies remain HttpOnly.
export function createBackendClient({ fetcher = (...args) => fetch(...args), changed = () => {}, apiBaseURL = '/api/v1', authPath = '/auth', cookieCredentials = 'omit' } = {}) {
  if (typeof apiBaseURL !== 'string' || typeof authPath !== 'string' || !/^\/[a-zA-Z0-9/-]+$/.test(authPath) || authPath.includes('..')) throw new Error('Invalid backend configuration.');
  const base = new URL(apiBaseURL, 'https://ontic.invalid');
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash || apiBaseURL.startsWith('//')) throw new Error('Invalid backend URL.');
  apiBaseURL = apiBaseURL.replace(/\/$/, '');
  let accessToken = '', refreshToken = '', expiresAt = 0, refreshing, username = '';
  function setCredentials(value) {
    if (!value || typeof value.access_token !== 'string' || !value.access_token || (typeof value.user?.username !== 'string' || !value.user.username)
      || (value.expires_in !== undefined && (!Number.isFinite(value.expires_in) || value.expires_in <= 0))
      || (value.refresh_token !== undefined && typeof value.refresh_token !== 'string')) throw new Error('Invalid backend credentials.');
    accessToken = value.access_token; refreshToken = value.refresh_token || '';
    expiresAt = value.expires_in === undefined ? Infinity : Date.now() + value.expires_in * 1000;
    username = value.user.username; changed(value.user);
  }
  function clear() { accessToken = ''; refreshToken = ''; expiresAt = 0; username = ''; changed(null); }
  async function read(response) {
    const text = await response.text();
    let data;
    try { data = text ? JSON.parse(text) : null; }
    catch { throw new APIError(response.status, { message: 'The API returned an invalid response.' }); }
    if (!response.ok) throw new APIError(response.status, data?.error);
    return data;
  }
  async function performAuth(action, body = {}) {
    if (typeof action !== 'string' || !/^[a-z-]+(?:\/[a-z-]+)?$/.test(action)) throw new Error('Invalid authentication action.');
    const tokenAction = action === 'refresh' || action === 'logout';
    const authToken = tokenAction ? refreshToken : '';
    if (authToken) refreshToken = ''; // A token that may be consumed must never be replayed.
    let result;
    try {
      result = await read(await fetcher(`${apiBaseURL}${authPath}/${action}`, {
        method: 'POST', credentials: cookieCredentials,
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(authToken ? { ...body, refresh_token: authToken } : body)
      }));
    } catch (error) {
      if (authToken) clear();
      // An absent/expired refresh cookie already has no reusable browser session.
      if (action === 'logout' && error.status === 401) { clear(); return null; }
      throw error;
    }
    if (result?.access_token) {
      setCredentials(result);
    } else clear();
    return result;
  }
  function auth(action, body = {}) {
    if (globalThis.navigator?.locks) return navigator.locks.request('ontic-browser-refresh', () => performAuth(action, body));
    return performAuth(action, body);
  }
  function refresh() {
    // Serialize within and across tabs to avoid replaying a rotated refresh token.
    refreshing ||= (async () => {
      try {
        return await auth('refresh');
      } catch (error) {
        if (error.status === 401) clear();
        throw error;
      } finally { refreshing = undefined; }
    })();
    return refreshing;
  }
  async function request(path, { method = 'GET', body, private: owned = false, signal, idempotencyKey, raw = false } = {}) {
    // Never send a bearer to a record-supplied URL or another origin.
    if (typeof path !== 'string' || /[\u0000-\u0020\u007f#]/.test(path) || /(?:^|\/)(?:\.|%2e){1,2}(?:\/|\?|$)/i.test(path) || !path.startsWith('/') || path.startsWith('//') || path.includes('\\') || !/^\/(pay2read(?:[/?]|$)|me(?:[/?]|$)|users(?:[/?]|$)|external-verifications(?:[/?]|$)|organization-membership-verifications(?:[/?]|$)|statements(?:[/?]|$)|agent-keys(?:[/?]|$)|auth\/password-reset\/(?:request|confirm)$|meta(?:[?]|$)|browser\/admin(?:[/?]|$))/.test(path)) throw new Error('Invalid API resource path.');
    if (owned && (!accessToken || Date.now() >= expiresAt - 15000)) await refresh();
    const requestUsername = username;
    const headers = {};
    if (owned) headers.Authorization = `Bearer ${accessToken}`;
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    const multipart = typeof FormData !== 'undefined' && body instanceof FormData;
    if (body !== undefined && !multipart) headers['Content-Type'] = 'application/json';
    const send = () => fetcher(`${apiBaseURL}${path}`, {
      method, headers, credentials: cookieCredentials, signal,
      body: body === undefined ? undefined : multipart ? body : JSON.stringify(body)
    });
    let response = await send();
    if (response.status === 401 && owned) {
      await refresh();
      // A rejected image PUT has not reached the upload handler; replay its exact
      // FormData once, only for the same owner after authentication is renewed.
      const retryUpload = method === 'PUT' && path === '/me/image' && multipart && username === requestUsername;
      if (method === 'GET' || method === 'HEAD' || retryUpload) {
        headers.Authorization = `Bearer ${accessToken}`;
        response = await send();
        if (response.status === 401) clear();
      } else {
        throw new APIError(401, { code: 'session_renewed', message: 'Your session was renewed. Retry this action.' });
      }
    }
    // Other mutations and uncertain failures always require an explicit retry.
    if (raw && response.ok) return response;
    return read(response);
  }
  return { request, auth, refresh, clear, setCredentials, authenticated: () => Boolean(accessToken), username: () => username };
}

