import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { OnticClient } from 'ontic-js';

const data = JSON.parse(readFileSync(new URL('../example/example-proofs.json', import.meta.url)));
const proofs = [...data.external_account_proofs, ...data.organization_membership_proofs];
const endpoint = 'https://rpc.example/';
function clientFor(proof, override = {}) {
  const anchor = proof.ethereum_anchor;
  const calls = [];
  const client = new OnticClient({ ethereumVerificationRPC: endpoint, fetcher: async (url, request) => {
    calls.push(url);
    assert.equal(url, endpoint, 'verification must never contact the backend');
    const input = JSON.parse(request.body);
    const results = {
      eth_chainId: '0x' + BigInt(anchor.chain_id).toString(16),
      eth_call: anchor.root,
      eth_getBlockByNumber: { number: '0x' + BigInt(anchor.block_number).toString(16), hash: anchor.block_hash,
        timestamp: '0x' + (BigInt(Date.parse(anchor.block_timestamp)) / 1000n).toString(16) },
      ...override,
    };
    return Response.json({ jsonrpc: '2.0', id: input.id, result: results[input.method] });
  } });
  return { client, calls };
}

test('data verification checks saved external and membership proofs using RPC only', async () => {
  for (const proof of proofs) {
    const { client, calls } = clientFor(proof);
    const result = await client.verifyProofData(JSON.stringify(proof), { publishing: proof.ethereum_anchor });
    assert.equal(result.author, data.username);
    assert.equal(calls.length, 4);
  }
});

test('data verification requires trusted policy and rejects tampering and wrong Ethereum evidence', async () => {
  const proof = proofs[0];
  const { client, calls } = clientFor(proof);
  await assert.rejects(async () => client.verifyProofData(JSON.stringify(proof)), /Trusted publishing/);
  assert.equal(calls.length, 0);
  const changed = structuredClone(proof);
  changed.external_account.content += ' ';
  await assert.rejects(client.verifyProofData(JSON.stringify(changed), { publishing: proof.ethereum_anchor }), /content hash/);
  await assert.rejects(client.verifyProofData(JSON.stringify(proof), { publishing: { ...proof.ethereum_anchor, contract_address: '0x' + '00'.repeat(20) } }), /network or contract/);
  const badRPC = clientFor(proof, { eth_call: '0x' + '00'.repeat(32) }).client;
  await assert.rejects(badRPC.verifyProofData(JSON.stringify(proof), { publishing: proof.ethereum_anchor }), /rootsByBlock/);
});

test('fetchProofData fetches evidence and policy without querying Ethereum', async () => {
  for (const [type, resource] of [['external_account', 'external-verifications'], ['organization_membership', 'organization-membership-verifications'], ['statement', 'statements']]) {
    const calls = [];
    const client = new OnticClient({ ethereumVerificationRPC: endpoint, fetcher: async url => {
      calls.push(url);
      return Response.json(url.endsWith('/meta') ? { ethereum_root_publishing: { chain_id: '1' } } : proofs[0]);
    } });
    const result = await client.fetchProofData(type, 'abc');
    assert.deepEqual(calls.sort(), [`/api/v1/${resource}/abc`, '/api/v1/meta'].sort());
    assert.deepEqual(result.proof, proofs[0]);
    assert.equal(result.publishing.chain_id, '1');
    await assert.rejects(client.fetchProofData('other', 'abc'), /Unsupported proof/);
    await assert.rejects(client.fetchProofData(type, '../abc'), /proof ID/);
  }
});
