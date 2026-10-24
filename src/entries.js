import { startGitHub, githubCallback } from './github-auth.js';
import { startLinkedIn, completeLinkedIn } from './linkedin-linking.js';
import { parseStatementBundle } from './verification.js';

function identifier(value) {
  if (typeof value !== 'string' || !value || value.length > 128) throw new Error('An entry identifier is required.');
  return encodeURIComponent(value);
}
function entryPath(id) { return `/me/entries/${identifier(id)}`; }
function pageQuery({ limit = 20, cursor } = {}) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('Use a page size from 1 to 100.');
  if (cursor !== undefined && cursor !== null && typeof cursor !== 'string') throw new Error('Invalid entry cursor.');
  return `?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
}

/** Entry-domain operations share the parent client's authentication and transport. */
export function createEntries(client) {
  const write = (path, method, body, { signal } = {}) => client.request(path, { method, body, private: true, signal });
  const entries = {
    create({ service, value = '' }, options) {
      if (typeof service !== 'string' || !service || service.length > 128) throw new Error('Choose an external service.');
      if (['GitHub', 'Bluesky', 'LinkedIn'].includes(service)) value = '';
      if (typeof value !== 'string' || value.length > 2048) throw new Error('Enter an account or address up to 2048 characters.');
      return write('/me/entries', 'POST', { service, value }, options);
    },
    get(id, { signal } = {}) { return client.request(entryPath(id), { private: true, signal }); },
    list(options = {}) { return client.request('/me/entries' + pageQuery(options), { private: true, signal: options.signal }); },
    listPublic(username, options = {}) {
      if (typeof username !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,38}$/.test(username)) throw new Error('Invalid username.');
      return client.request(`/users/${encodeURIComponent(username)}/entries` + pageQuery(options), { signal: options.signal });
    },
    async *iterate({ username, limit = 100, signal } = {}) {
      let cursor;
      const seen = new Set();
      do {
        signal?.throwIfAborted();
        const page = username === undefined ? await entries.list({ limit, cursor, signal }) : await entries.listPublic(username, { limit, cursor, signal });
        signal?.throwIfAborted();
        if (!Array.isArray(page?.items)) throw new Error('Invalid entries page.');
        cursor = page.next_cursor;
        if (cursor !== undefined && cursor !== null && typeof cursor !== 'string') throw new Error('Invalid entry cursor.');
        if (cursor) {
          if (seen.has(cursor)) throw new Error('Invalid or repeated entry cursor.');
          seen.add(cursor);
        }
        yield* page.items;
      } while (cursor);
    },
    async all(options) {
      const result = [];
      for await (const entry of entries.iterate(options)) result.push(entry);
      return result;
    },
    setVisibility(id, visible, options) {
      if (typeof visible !== 'boolean') throw new Error('Entry visibility must be a boolean.');
      return write(entryPath(id), 'PATCH', { visible }, options);
    },
    remove(id, options) { return write(entryPath(id), 'DELETE', { confirm: true }, options); },
    renewWebsiteProof(id, options) { return write(entryPath(id) + '/website-proof/renew', 'POST', {}, options); },
    verifyWebsiteProof(id, options) { return write(entryPath(id) + '/website-proof/verify', 'POST', {}, options); },
    renewProof(id, { chainID, signal } = {}) {
      if (chainID !== undefined && (!Number.isSafeInteger(chainID) || chainID <= 0)) throw new Error('A positive Ethereum chain ID is required.');
      return write(entryPath(id) + '/proof/renew', 'POST', chainID === undefined ? {} : { chain_id: chainID }, { signal });
    },
    submitProof(id, { url, signature }, options) {
      if ((url !== undefined) === (signature !== undefined)) throw new Error('Supply a proof URL or wallet signature.');
      if (url !== undefined && (typeof url !== 'string' || !url || url.length > 2048)) throw new Error('A proof URL up to 2048 characters is required.');
      if (signature !== undefined && (typeof signature !== 'string' || !signature || signature.length > 16386)) throw new Error('A wallet signature is required.');
      return write(entryPath(id) + '/proof/verify', 'POST', url === undefined ? { signature } : { url }, options);
    },
    async startLinkedIn(id, { signal } = {}) {
      identifier(id);
      let destination;
      await startLinkedIn(id, (path, method, body) => write(path, method, body ?? {}, { signal }), url => { destination = url; });
      return destination;
    },
    completeLinkedIn(url, { signal } = {}) {
      return completeLinkedIn(url, (path, method, body, options) => write(path, method, body, options), signal);
    },
    async startGitHub({ signal } = {}) {
      let destination;
      await startGitHub(() => write('/me/github/start', 'POST', {}, { signal }), url => { destination = url; });
      return destination;
    },
    async completeGitHub(url, options) { return write('/me/github/complete', 'POST', githubCallback(url), options); },
    disconnectGitHub({ current_password }, options) { return write('/me/github', 'DELETE', { current_password }, options); },
    getVerification(id, { signal, private: owned = client.authenticated() } = {}) {
      return client.request(`/external-verifications/${identifier(id)}`, { private: owned, signal });
    },
    verifyAttestation(text, options) {
      if (!parseStatementBundle(text).external_account) throw new Error('An external-account verification bundle is required.');
      return client.verifyStatementJSON(text, options);
    },
  };
  return Object.freeze(entries);
}
