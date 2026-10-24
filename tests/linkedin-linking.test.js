import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startLinkedIn, completeLinkedIn, hasLinkedInCallback } from 'ontic-js';

const state = 'a'.repeat(64);
test('LinkedIn starts through an authenticated entry and only navigates to its authorization endpoint', async () => {
  const requests = [], destinations = [];
  await startLinkedIn('entry', async (...args) => {
    requests.push(args);
    return { authorization_url: `https://www.linkedin.com/oauth/v2/authorization?state=${state}` };
  }, url => destinations.push(url));
  assert.deepEqual(requests, [['/me/entries/entry/linkedin/start', 'POST']]);
  assert.equal(destinations.length, 1);
  for (const url of ['https://attacker.test/oauth/v2/authorization', 'http://www.linkedin.com/oauth/v2/authorization', 'https://www.linkedin.com/other', 'https://user:password@www.linkedin.com/oauth/v2/authorization', 'https://www.linkedin.com/oauth/v2/authorization#secret']) {
    await assert.rejects(startLinkedIn('entry', async () => ({ authorization_url: url }), () => assert.fail('untrusted navigation')), /Invalid LinkedIn/);
  }
});

test('LinkedIn completion forwards the exact one-time code and state with cancellation', async () => {
  const callback = new URL(`https://ontic.test/account?code=one%2Btime&state=${state}`);
  const signal = new AbortController().signal;
  const entry = { id: 'entry', service: 'LinkedIn', value: 'Jane Smith' };
  assert.equal(hasLinkedInCallback(callback), true);
  assert.equal(hasLinkedInCallback(new URL('https://ontic.test/account#entries')), false);
  const result = await completeLinkedIn(callback, async (...args) => {
    assert.deepEqual(args, ['/me/linkedin/complete', 'POST', { code: 'one+time', state }, { signal }]);
    return entry;
  }, signal);
  assert.equal(result, entry);
});

test('denied and ambiguous LinkedIn callbacks never submit a verification', async () => {
  const request = () => assert.fail('invalid callback submitted');
  for (const query of [`error=access_denied&error_description=secret&state=${state}`, `code=one&code=two&state=${state}`, `code=one&state=${state}&state=${state}`, `code=one`, `state=${state}`, `code=&state=${state}`]) {
    await assert.rejects(completeLinkedIn(new URL(`https://ontic.test/account?${query}`), request), /Connect again/);
  }
});

test('LinkedIn failure preserves actionable errors and never automatically retries code exchange', async () => {
  let calls = 0;
  const error = new Error('This identity is already verified by another account.');
  await assert.rejects(completeLinkedIn(new URL(`https://ontic.test/account?code=one&state=${state}`), async () => { calls++; throw error; }), failure => failure === error);
  assert.equal(calls, 1);
});
