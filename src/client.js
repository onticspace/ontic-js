import { createEntries } from './entries.js';
import { createBackendClient } from './backend-client.js';
import { createVerificationRPC, ethereumRPCURL, parseStatementBundle, verifyStatementJSON } from './verification.js';

/** Stateful Ontic backend and verification client. RPC policy is always caller-owned. */
export class OnticClient {
  #backend;
  #rpcFetcher;
  ethereumVerificationRPC;
  entries;

  constructor({ ethereumVerificationRPC, credentials, backend, fetcher = (...args) => fetch(...args),
    rpcFetcher = fetcher, changed, apiBaseURL = '/api/v1', authPath = '/auth', cookieCredentials = 'omit' } = {}) {
    Object.defineProperty(this, 'ethereumVerificationRPC', {
      value: ethereumRPCURL(ethereumVerificationRPC), enumerable: true, writable: false, configurable: false,
    });
    this.#rpcFetcher = rpcFetcher;
    this.#backend = backend || createBackendClient({ fetcher, changed, apiBaseURL, authPath, cookieCredentials });
    Object.defineProperty(this, 'entries', { value: createEntries(this), enumerable: true, writable: false, configurable: false });
    if (credentials) this.setCredentials(credentials);
  }

  // Bound methods can be passed directly to application code without losing state.
  request = (path, options) => this.#backend.request(path, options);
  auth = (action, body) => this.#backend.auth(action, body);
  refresh = () => this.#backend.refresh();
  clear = () => this.#backend.clear();
  authenticated = () => this.#backend.authenticated();
  username = () => this.#backend.username();
  setCredentials = credentials => {
    if (!this.#backend.setCredentials) throw new Error('Credentials are managed by the platform backend adapter.');
    this.#backend.setCredentials(credentials);
  };

  /** Request the backend's exact ERC-191 ownership challenge. */
  createEthereumAccountChallenge(entryID, chainID, { signal } = {}) {
    if (typeof entryID !== 'string' || !entryID) throw new Error('An external account entry ID is required.');
    if (!Number.isSafeInteger(chainID) || chainID <= 0) throw new Error('A positive Ethereum chain ID is required.');
    return this.entries.renewProof(entryID, { chainID, signal });
  }

  /** Submit the wallet signature for backend verification; manual signatures work too. */
  verifyEthereumAccount(entryID, signature, { signal } = {}) {
    if (typeof entryID !== 'string' || !entryID) throw new Error('An external account entry ID is required.');
    if (typeof signature !== 'string' || !signature || signature.length > 16386) throw new Error('A wallet signature is required.');
    return this.entries.submitProof(entryID, { signature }, { signal });
  }

  getOrganizationMembershipVerification(snapshotID, { signal } = {}) {
    if (typeof snapshotID !== 'string' || !/^[a-f0-9]{32}$/.test(snapshotID)) throw new Error('A membership verification ID is required.');
    return this.request(`/organization-membership-verifications/${snapshotID}`, { signal });
  }

  verifyOrganizationMembership(text, options) {
    if (!parseStatementBundle(text).organization_membership) throw new Error('An organization membership bundle is required.');
    return this.verifyStatementJSON(text, options);
  }

  async verifyStatementJSON(text, { publishing, signal, progress } = {}) {
    parseStatementBundle(text);
    const rpc = createVerificationRPC(this.ethereumVerificationRPC, signal, this.#rpcFetcher);
    publishing ??= (await this.request('/meta', { signal })).ethereum_root_publishing;
    return verifyStatementJSON(text, {
      publishing, rpc, signal, progress,
      api: (path, options) => this.request(path, { ...options,
        private: path.startsWith('/external-verifications/') && this.authenticated() }),
    });
  }
}

export function createOnticClient(options) { return new OnticClient(options); }
