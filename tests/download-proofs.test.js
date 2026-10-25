import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const script = fileURLToPath(new URL('../example/download-proofs.py', import.meta.url));
async function withAPI(respond, callback) {
  const directory = await mkdtemp(join(tmpdir(), 'ontic-download-proofs-'));
  const calls = [];
  const server = createServer((request, response) => {
    calls.push(request.url);
    assert.equal(request.headers.authorization, undefined);
    const data = respond(new URL(request.url, 'http://local.test'));
    if (data?.redirectTo) {
      response.writeHead(302, { Location: data.redirectTo });
      response.end();
      return;
    }
    response.writeHead(data ? 200 : 404, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(data || { error: 'not found' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await callback({ directory, calls, env: { ...process.env, ONTIC_API_URL: `http://127.0.0.1:${server.address().port}/api/v1` } });
  } finally {
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}
const ids = ['ab'.repeat(16), 'cd'.repeat(16), 'ef'.repeat(16)];
const external = id => ({ version: 1, external_account: { id, content: 'exact JSON string', hash: 'hash', hash_algorithm: 'blake3' }, merkle_proof: { siblings: '04000000' }, ethereum_anchor: { status: 'pending' } });
const membership = { version: 1, organization_membership: { id: ids[2], content: 'exact membership JSON' }, merkle_proof: { root: 'root' } };

test('Python downloader collects paginated external proofs and membership proofs in one file', async () => {
  await withAPI(url => {
    if (url.pathname === '/api/v1/users/alice') return { username: 'alice', organizations: [
      { verification_url: `/statements/verify?organization_membership=${ids[2]}` },
      { verification_url: `/statements/verify?organization_membership=${ids[2]}` },
    ] };
    if (url.pathname === '/api/v1/users/alice/entries') {
      if (url.searchParams.has('cursor')) {
        assert.equal(url.searchParams.get('cursor'), 'cursor+/=');
        return { items: [{ verification_url: `/statements/verify?external_account=${ids[1]}` }], next_cursor: null };
      }
      return { items: [{ verification_url: `https://untrusted.invalid/verify?external_account=${ids[0]}` }, { service: 'unverified' }], next_cursor: 'cursor+/=' };
    }
    if (url.pathname.startsWith('/api/v1/external-verifications/')) return external(url.pathname.split('/').at(-1));
    if (url.pathname === `/api/v1/organization-membership-verifications/${ids[2]}`) return membership;
  }, async ({ directory, env, calls }) => {
    await run('python3', [script, 'Alice'], { cwd: directory, env });
    const result = JSON.parse(await readFile(join(directory, 'alice-proofs.json'), 'utf8'));
    assert.equal(result.username, 'alice');
    assert.deepEqual(result.external_account_proofs, [external(ids[0]), external(ids[1])]);
    assert.deepEqual(result.organization_membership_proofs, [membership]);
    assert.equal(calls.filter(path => path.includes('/organization-membership-verifications/')).length, 1);
  });
});

test('failed downloads leave an existing destination untouched', async () => {
  await withAPI(url => {
    if (url.pathname === '/api/v1/users/alice') return { username: 'alice', organizations: [] };
    if (url.pathname === '/api/v1/users/alice/entries') return { items: [{ verification_url: `/statements/verify?external_account=${ids[0]}` }] };
  }, async ({ directory, env }) => {
    const output = join(directory, 'my proofs.json');
    await writeFile(output, 'existing file');
    await assert.rejects(run('python3', [script, 'alice', output], { env }), error => error.code === 1 && /Could not download/.test(error.stderr));
    assert.equal(await readFile(output, 'utf8'), 'existing file');
  });
});

test('repeated cursors and invalid usernames fail without writing output', async () => {
  await withAPI(url => url.pathname === '/api/v1/users/alice'
    ? { username: 'alice', organizations: [] }
    : { items: [], next_cursor: 'same' }, async ({ directory, env }) => {
    await assert.rejects(run('python3', [script, 'alice'], { cwd: directory, env }), error => /Repeated/.test(error.stderr));
    await assert.rejects(readFile(join(directory, 'alice-proofs.json')), { code: 'ENOENT' });
    await assert.rejects(run('python3', [script, '../alice'], { cwd: directory, env }), error => /username/.test(error.stderr));
  });
});

test('Python downloader rejects HTTP redirects instead of fetching another destination', async () => {
  await withAPI(() => ({ redirectTo: '/unexpected' }), async ({ directory, env, calls }) => {
    await assert.rejects(run('python3', [script, 'alice'], { cwd: directory, env }), error => /302/.test(error.stderr));
    assert.deepEqual(calls, ['/api/v1/users/alice']);
    await assert.rejects(readFile(join(directory, 'alice-proofs.json')), { code: 'ENOENT' });
  });
});
