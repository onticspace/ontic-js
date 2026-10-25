import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { OnticClient, createOnticClient } from 'ontic-js';

const endpoint = 'https://rpc.example/custom';
const json = (data, status = 200) => new Response(data === null ? null : JSON.stringify(data), { status });
const credentials = (token = 'alice-token', refresh = 'refresh-token') => ({ access_token: token, refresh_token: refresh, expires_in: 900, user: { username: 'alice' } });

test('client requires one immutable RPC URL, without a network map', () => {
  for (const value of [undefined, '', {}, { '1': endpoint }, [endpoint], 'file:///etc/passwd']) {
    assert.throws(() => new OnticClient({ ethereumVerificationRPC: value }));
  }
  const client = createOnticClient({ ethereumVerificationRPC: endpoint });
  assert.equal(client.ethereumVerificationRPC, endpoint);
  assert.throws(() => { client.ethereumVerificationRPC = 'https://other.example'; });
});

test('credentials belong to each instance and only accompany private backend requests', async () => {
  const calls = [];
  const fetcher = async (url, options) => { calls.push({ url, options }); return json({}); };
  const client = new OnticClient({ ethereumVerificationRPC: endpoint, credentials: credentials(), apiBaseURL: 'https://registry.example/api/v1/', fetcher });
  const request = client.request;
  await request('/me', { private: true });
  await request('/users/alice');
  assert.equal(calls[0].url, 'https://registry.example/api/v1/me');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer alice-token');
  assert.equal(calls[0].options.credentials, 'omit');
  assert.equal(calls[1].options.headers.Authorization, undefined);
  assert.equal(client.username(), 'alice');
  assert.equal(new OnticClient({ ethereumVerificationRPC: endpoint }).authenticated(), false);
  for (const path of ['https://other.example/me', '//other.example/me', '/me/../users/alice', '/me/%2e%2e/users/alice']) {
    await assert.rejects(request(path, { private: true }), /Invalid API resource/);
  }
  assert.equal(calls.length, 2);
  assert.ok(!JSON.stringify(client).includes('alice-token'));
  client.clear();
  assert.equal(client.authenticated(), false);
  assert.equal(client.username(), '');
});

test('login, concurrent refresh, and logout share and rotate instance credentials', async () => {
  const calls = [];
  const client = new OnticClient({ ethereumVerificationRPC: endpoint, fetcher: async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/logout')) return json(null, 204);
    return json(credentials(url.endsWith('/refresh') ? 'new-token' : 'login-token', url.endsWith('/refresh') ? 'new-refresh' : 'login-refresh'));
  }});
  await client.auth('login', { username: 'alice', password: 'test-password' });
  await Promise.all([client.refresh(), client.refresh()]);
  assert.equal(calls.filter(c => c.url.endsWith('/refresh')).length, 1);
  assert.equal(JSON.parse(calls[1].options.body).refresh_token, 'login-refresh');
  await client.auth('logout');
  assert.equal(JSON.parse(calls[2].options.body).refresh_token, 'new-refresh');
  assert.equal(client.authenticated(), false);
});

test('a refresh token with an uncertain outcome is cleared instead of replayed', async () => {
  const client = new OnticClient({ ethereumVerificationRPC: endpoint, credentials: credentials(), fetcher: async () => { throw new Error('connection lost'); } });
  await assert.rejects(client.refresh(), /connection lost/);
  assert.equal(client.authenticated(), false);
});

function bundleFor(entry) {
  const hash = entry.external_account
    ? blake3(concatBytes(new Uint8Array([255]), new TextEncoder().encode('ontic.space/external-account-verification/v1\n' + entry.external_account.content)))
    : blake3(new TextEncoder().encode(entry.statement.text));
  const root = bytesToHex(blake3(concatBytes(hash, new Uint8Array([1]))));
  const publishing = { chain_id: '31337', contract_address: '0x' + '12'.repeat(20) };
  return { version: 1, ...entry,
    merkle_proof: { version: 1, tree_hash: 'blake3', statement_hash: 'blake3', max_levels: 256, key: bytesToHex(hash), root, value: '', siblings: '04000000', siblings_encoding: 'arbo-packed-hex', exists: true },
    ethereum_anchor: { ...publishing, status: 'confirmed', root: '0x' + root, block_number: '42', block_hash: '0x' + '34'.repeat(32), block_timestamp: '1970-01-01T00:01:00Z', transaction_hash: 'tx' },
  };
}

test('client verification uses its backend credentials and caller RPC for both bundle types', async () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/openssh-signature.json', import.meta.url)));
  const content = JSON.stringify({ type: 'external-account-verification', version: 1, username: 'alice', entry_id: 'entry', service: 'GitHub', account: 'octocat', identity_key: 'github:42', verified_at: '2026-10-05 00:00:00' });
  const externalHash = bytesToHex(blake3(concatBytes(new Uint8Array([255]), new TextEncoder().encode('ontic.space/external-account-verification/v1\n' + content))));
  for (const entry of [
    { statement: { id: 'statement', author: 'alice', kind: 'plain', text: fixture.text, hash: bytesToHex(blake3(new TextEncoder().encode(fixture.text))), hash_algorithm: 'blake3' }, signature: fixture.signature },
    { external_account: { id: 'ab'.repeat(16), content, hash: externalHash, hash_algorithm: 'blake3' } },
  ]) {
    const bundle = bundleFor(entry);
    const calls = [];
    const client = new OnticClient({ ethereumVerificationRPC: endpoint, credentials: credentials(), fetcher: async (url, options) => {
      calls.push({ url, options });
      if (url === endpoint) {
        assert.equal(options.credentials, 'omit');
        assert.equal(options.headers.Authorization, undefined);
        const request = JSON.parse(options.body);
        return json({ jsonrpc: '2.0', id: request.id, result: {
          eth_chainId: '0x7a69', eth_call: bundle.ethereum_anchor.root,
          eth_getBlockByNumber: { hash: bundle.ethereum_anchor.block_hash, number: '0x2a', timestamp: '0x3c' },
        }[request.method] });
      }
      if (url === '/api/v1/meta') return json({ ethereum_root_publishing: bundle.ethereum_anchor });
      return json(entry.statement ? { ...entry.statement, signature: entry.signature } : entry);
    }});
    const result = await client.verifyStatementJSON(JSON.stringify(bundle));
    assert.equal(result.author, 'alice');
    assert.equal(result.timestamp, '1970-01-01T00:01:00.000Z');
    const registry = calls.find(c => /\/statements\/|\/external-verifications\//.test(c.url));
    assert.equal(registry.options.headers.Authorization, entry.external_account ? 'Bearer alice-token' : undefined);
    assert.equal(calls.filter(c => c.url === endpoint).length, 4);
    calls.length = 0;
    const localResult = await client.verifyProofData(JSON.stringify(bundle), { publishing: bundle.ethereum_anchor });
    assert.equal(localResult.author, 'alice');
    assert.equal(calls.length, 4);
    assert.ok(calls.every(call => call.url === endpoint));
    const unknown = structuredClone(bundle); unknown.ethereum_anchor.chain_id = '1';
    await assert.rejects(client.verifyStatementJSON(JSON.stringify(unknown), { publishing: unknown.ethereum_anchor }), /wrong network/);
  }
});
