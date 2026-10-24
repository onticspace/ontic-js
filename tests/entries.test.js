import assert from 'node:assert/strict';
import test from 'node:test';
import { OnticClient } from 'ontic-js';

const state = 'a'.repeat(64);
function setup(respond = () => ({ id: 'entry' })) {
  const calls = [];
  const client = new OnticClient({
    ethereumVerificationRPC: 'https://rpc.example',
    credentials: { access_token: 'entry-owner', user: { username: 'alice' } },
    fetcher: async (url, options) => {
      calls.push({ url, options });
      const result = await respond(url, options);
      return result instanceof Response ? result : Response.json(result);
    },
  });
  return { client, calls };
}

test('entry lifecycle uses authenticated backend contracts and preserves visibility scope', async () => {
  const { client, calls } = setup();
  await client.entries.create({ service: 'Ethereum address', value: '0x' + '12'.repeat(20) });
  await client.entries.create({ service: 'GitHub', value: 'ignored until proof discovers identity' });
  await client.entries.get('entry');
  await client.entries.setVisibility('entry', false);
  await client.entries.remove('entry');
  assert.deepEqual(calls.map(c => [c.url, c.options.method || 'GET']), [
    ['/api/v1/me/entries', 'POST'], ['/api/v1/me/entries', 'POST'],
    ['/api/v1/me/entries/entry', 'GET'], ['/api/v1/me/entries/entry', 'PATCH'], ['/api/v1/me/entries/entry', 'DELETE'],
  ]);
  assert.deepEqual(JSON.parse(calls[1].options.body), { service: 'GitHub', value: '' });
  assert.deepEqual(JSON.parse(calls[3].options.body), { visible: false });
  assert.deepEqual(JSON.parse(calls[4].options.body), { confirm: true });
  assert.ok(calls.every(c => c.options.headers.Authorization === 'Bearer entry-owner'));
  assert.throws(() => client.entries.setVisibility('entry', 'false'), /boolean/);
  assert.throws(() => client.entries.create({ service: 'website', value: 'a'.repeat(2049) }), /2048/);
});

test('public and private pagination retain scope, cursor encoding, and cancellation', async () => {
  const { client, calls } = setup(url => url.includes('cursor=') ? { items: [{ id: 'second' }], next_cursor: null } : { items: [{ id: 'first' }], next_cursor: 'cursor+/=' });
  const signal = new AbortController().signal;
  assert.deepEqual((await client.entries.all({ username: 'alice', signal })).map(e => e.id), ['first', 'second']);
  assert.equal(calls[1].url, '/api/v1/users/alice/entries?limit=100&cursor=cursor%2B%2F%3D');
  assert.ok(calls.every(c => c.options.headers.Authorization === undefined && c.options.signal === signal));
  calls.length = 0;
  const list = client.entries.list;
  await list({ limit: 5, signal });
  assert.equal(calls[0].url, '/api/v1/me/entries?limit=5');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer entry-owner');
  assert.throws(() => client.entries.listPublic('//attacker.example'), /username/);
  assert.throws(() => client.entries.list({ limit: 101 }), /page size/);
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(client.entries.all({ signal: aborted.signal }), { name: 'AbortError' });
  const duringRead = new AbortController();
  const ignoresCancellation = setup(() => { duringRead.abort(); return { items: [{ id: 'stale' }] }; }).client;
  await assert.rejects(ignoresCancellation.entries.all({ signal: duringRead.signal }), { name: 'AbortError' });
});

test('repeated pagination cursors fail instead of looping forever', async () => {
  const { client, calls } = setup(() => ({ items: [], next_cursor: 'same-cursor' }));
  await assert.rejects(client.entries.all(), /repeated entry cursor/);
  assert.equal(calls.length, 2);
});

test('website, social, and Ethereum proofs preserve their separate backend flows', async () => {
  const { client, calls } = setup();
  const signal = new AbortController().signal;
  await client.entries.renewWebsiteProof('website', { signal });
  await client.entries.verifyWebsiteProof('website', { signal });
  await client.entries.renewProof('github', { signal });
  await client.entries.submitProof('github', { url: 'https://gist.github.com/alice/proof' }, { signal });
  await client.entries.renewProof('wallet', { chainID: 1, signal });
  await client.entries.submitProof('wallet', { signature: '0xsignature' }, { signal });
  assert.deepEqual(calls.map(c => c.url), [
    '/api/v1/me/entries/website/website-proof/renew', '/api/v1/me/entries/website/website-proof/verify',
    '/api/v1/me/entries/github/proof/renew', '/api/v1/me/entries/github/proof/verify',
    '/api/v1/me/entries/wallet/proof/renew', '/api/v1/me/entries/wallet/proof/verify',
  ]);
  assert.deepEqual(JSON.parse(calls[4].options.body), { chain_id: 1 });
  assert.deepEqual(JSON.parse(calls[5].options.body), { signature: '0xsignature' });
  assert.ok(calls.every(c => c.options.method === 'POST' && c.options.signal === signal && c.options.headers.Authorization === 'Bearer entry-owner'));
  assert.throws(() => client.entries.submitProof('entry', { signature: 'sig', url: 'url' }), /or wallet signature/);
});

test('OAuth methods return validated URLs and exchange callbacks without owning navigation', async () => {
  const { client, calls } = setup(url => ({ authorization_url: url.includes('linkedin')
    ? 'https://www.linkedin.com/oauth/v2/authorization?state=' + state
    : 'https://github.com/login/oauth/authorize?state=' + state }));
  const signal = new AbortController().signal;
  assert.match(await client.entries.startLinkedIn('entry', { signal }), /^https:\/\/www.linkedin.com\//);
  assert.match(await client.entries.startGitHub({ signal }), /^https:\/\/github.com\//);
  const callback = new URL(`https://app.example/callback?code=exact%2Bcode&state=${state}`);
  await client.entries.completeLinkedIn(callback, { signal });
  await client.entries.completeGitHub(callback, { signal });
  await client.entries.disconnectGitHub({ current_password: 'password' }, { signal });
  assert.deepEqual(calls.slice(2).map(c => c.url), ['/api/v1/me/linkedin/complete', '/api/v1/me/github/complete', '/api/v1/me/github']);
  assert.deepEqual(JSON.parse(calls[2].options.body), { code: 'exact+code', state });
  assert.ok(calls.every(c => c.options.signal === signal && c.options.headers.Authorization === 'Bearer entry-owner'));
  const denied = setup(() => ({ authorization_url: 'https://attacker.example/steal' })).client;
  await assert.rejects(denied.entries.startLinkedIn('entry'), /Invalid LinkedIn/);
  await assert.rejects(denied.entries.startGitHub(), /Invalid GitHub/);
  await assert.rejects(client.entries.completeGitHub(new URL('https://app.example?error=denied')), /cancelled/);
});

test('failed proof submissions preserve backend errors and are never automatically retried', async () => {
  const { client, calls } = setup(() => Response.json({ error: { code: 'identity_claimed', message: 'Already claimed.' } }, { status: 409 }));
  await assert.rejects(client.entries.submitProof('entry', { url: 'https://gist.github.com/alice/proof' }), error => error.status === 409 && error.code === 'identity_claimed');
  assert.equal(calls.length, 1);
});

test('verification downloads use instance credentials with explicit public-read support', async () => {
  const { client, calls } = setup();
  await client.entries.getVerification('snapshot');
  await client.entries.getVerification('snapshot', { private: false });
  assert.equal(calls[0].url, '/api/v1/external-verifications/snapshot');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer entry-owner');
  assert.equal(calls[1].options.headers.Authorization, undefined);
  assert.throws(() => client.entries.verifyAttestation(JSON.stringify({ version: 1, statement: {} })), /external-account/);
});
