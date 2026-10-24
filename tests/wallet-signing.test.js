import assert from 'node:assert/strict';
import { test } from 'node:test';
import { signWalletMessage } from 'ontic-js';

test('wallet signs exact UTF-8 message after account and chain checks, without transactions', async () => {
  const calls = [];
  const address = '0xabcdef';
  const message = 'Exact α\r\n statement ';
  const provider = { request: async request => {
    calls.push(request);
    if (request.method === 'eth_requestAccounts') return [address.toUpperCase()];
    if (request.method === 'eth_chainId') return '0x1';
    if (request.method === 'personal_sign') return '0xsignature';
    throw new Error('Unexpected request');
  } };
  assert.equal(await signWalletMessage(provider, address, 1, message), '0xsignature');
  assert.deepEqual(calls.map(call => call.method), ['eth_requestAccounts','eth_chainId','personal_sign']);
  assert.deepEqual(calls[2].params, ['0x' + Buffer.from(message).toString('hex'),address]);
  await assert.rejects(signWalletMessage(provider,address,2,message), /network/);
  await assert.rejects(signWalletMessage(provider,'0xdifferent',1,message), /matching/);
  await assert.rejects(signWalletMessage(null,address,1,message), /manual/);
});

test('Ethereum challenge and signature submission use the client credentials and existing backend routes', async () => {
  const { OnticClient } = await import('ontic-js');
  const calls = [];
  const signal = new AbortController().signal;
  const client = new OnticClient({
    ethereumVerificationRPC: 'https://rpc.example',
    credentials: { access_token: 'owned-token', user: { username: 'alice' } },
    fetcher: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ id: 'entry', verified_at: null }), { status: 200 });
    },
  });
  await client.createEthereumAccountChallenge('entry', 1, { signal });
  await client.verifyEthereumAccount('entry', '0xsignature', { signal });
  assert.deepEqual(calls.map(c => c.url), ['/api/v1/me/entries/entry/proof/renew', '/api/v1/me/entries/entry/proof/verify']);
  assert.deepEqual(calls.map(c => JSON.parse(c.options.body)), [{ chain_id: 1 }, { signature: '0xsignature' }]);
  for (const { options } of calls) {
    assert.equal(options.method, 'POST');
    assert.equal(options.headers.Authorization, 'Bearer owned-token');
    assert.equal(options.signal, signal);
  }
});
