import assert from 'node:assert/strict';
import test from 'node:test';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { OnticClient, parseStatementBundle, verifyStatementJSON, statementVerificationMessage } from 'ontic-js';

const encode = text => new TextEncoder().encode(text);
const content = JSON.stringify({ type: 'organization-membership-verification', version: 1, membership_id: 'ab'.repeat(16), username: 'alice', organization: 'acme', invited_at: '2026-10-24 10:00:00', recorded_at: '2026-10-24 11:00:00' });
const hash = blake3(concatBytes(new Uint8Array([255]), encode('ontic.space/organization-membership-verification/v1\n' + content)));
const root = bytesToHex(blake3(concatBytes(hash, new Uint8Array([1]))));
const contract = '0x' + '12'.repeat(20), blockHash = '0x' + '34'.repeat(32);
const bundle = {
  version: 1,
  organization_membership: { id: 'cd'.repeat(16), content, hash: bytesToHex(hash), hash_algorithm: 'blake3' },
  merkle_proof: { version: 1, tree_hash: 'blake3', statement_hash: 'blake3', max_levels: 256, root, key: bytesToHex(hash), value: '', siblings: '04000000', siblings_encoding: 'arbo-packed-hex', exists: true },
  ethereum_anchor: { status: 'confirmed', chain_id: '1', contract_address: contract, root: '0x' + root, block_number: '42', block_hash: blockHash, block_timestamp: '2026-10-24T12:00:00Z', transaction_hash: '0x' + '56'.repeat(32) },
};
const publishing = { chain_id: '1', contract_address: contract };
const rpc = async method => ({ eth_chainId: '0x1', eth_call: '0x' + root, eth_getBlockByNumber: { number: '0x2a', hash: blockHash, timestamp: '0x' + (BigInt(Date.parse(bundle.ethereum_anchor.block_timestamp)) / 1000n).toString(16) } })[method];
const options = { publishing, rpc, api: async path => {
  assert.equal(path, `/organization-membership-verifications/${bundle.organization_membership.id}`);
  return bundle;
} };

test('membership proofs bind both identities, typed Blake3, Arbo inclusion, registry, and Ethereum time', async () => {
  const result = await verifyStatementJSON(JSON.stringify(bundle), options);
  assert.equal(result.type, 'organization-membership-verification');
  assert.equal(result.author, 'alice');
  assert.equal(result.organization, 'acme');
  assert.equal(result.timestamp, '2026-10-24T12:00:00.000Z');
  assert.match(statementVerificationMessage(result), /@alice to @acme/);
  assert.notEqual(bytesToHex(hash), bytesToHex(blake3(encode(content))));
  assert.notEqual(bytesToHex(hash), bytesToHex(blake3(concatBytes(new Uint8Array([255]), encode('ontic.space/external-account-verification/v1\n' + content)))));
});

test('membership verification rejects altered relations, roots, registry responses, and unpublished records', async () => {
  const tampered = structuredClone(bundle);
  tampered.organization_membership.content = content.replace('acme', 'attacker');
  await assert.rejects(verifyStatementJSON(JSON.stringify(tampered), options), /content hash/);
  const badRoot = structuredClone(bundle); badRoot.merkle_proof.root = '00'.repeat(32);
  await assert.rejects(verifyStatementJSON(JSON.stringify(badRoot), options), /Merkle proof verification failed/);
  await assert.rejects(verifyStatementJSON(JSON.stringify(bundle), { ...options, api: async () => ({ organization_membership: { ...bundle.organization_membership, content: content + ' ' } }) }), /registry does not attest/);
  const pending = structuredClone(bundle); pending.ethereum_anchor.status = 'pending';
  await assert.rejects(verifyStatementJSON(JSON.stringify(pending), options), /no mined Ethereum/);
  const wrongTime = structuredClone(bundle); wrongTime.ethereum_anchor.block_timestamp = '2026-10-23T12:00:00Z';
  await assert.rejects(verifyStatementJSON(JSON.stringify(wrongTime), options), /timestamp verification failed/);
});

test('membership records cannot be confused with statements/external accounts or contain duplicate fields', async () => {
  for (const extra of [{ statement: {} }, { external_account: {} }]) {
    assert.throws(() => parseStatementBundle(JSON.stringify({ ...bundle, ...extra })), /exactly one/);
  }
  const duplicate = content.replace('"username":"alice"', '"username":"alice","username":"bob"');
  const changed = structuredClone(bundle);
  changed.organization_membership.content = duplicate;
  changed.organization_membership.hash = bytesToHex(blake3(concatBytes(new Uint8Array([255]), encode('ontic.space/organization-membership-verification/v1\n' + duplicate))));
  await assert.rejects(verifyStatementJSON(JSON.stringify(changed), options), /Duplicate JSON field/);
  const lookalike = structuredClone(bundle);
  lookalike.external_account = lookalike.organization_membership;
  delete lookalike.organization_membership;
  await assert.rejects(verifyStatementJSON(JSON.stringify(lookalike), options), /content hash verification failed/);
});

test('SDK downloads and verifies public historical memberships without sending backend credentials', async () => {
  const calls = [];
  const endpoint = 'https://rpc.example/ethereum';
  const client = new OnticClient({ ethereumVerificationRPC: endpoint,
    credentials: { access_token: 'private-owner-token', user: { username: 'alice' } },
    fetcher: async (url, request) => {
      calls.push({ url, request });
      assert.equal(request.headers?.Authorization, undefined);
      if (url === endpoint) {
        assert.equal(request.credentials, 'omit');
        const input = JSON.parse(request.body);
        return Response.json({ jsonrpc: '2.0', id: input.id, result: await rpc(input.method) });
      }
      if (url === '/api/v1/meta') return Response.json({ ethereum_root_publishing: publishing });
      assert.equal(url, '/api/v1/organization-membership-verifications/' + bundle.organization_membership.id);
      return Response.json(bundle);
    },
  });
  const downloaded = await client.getOrganizationMembershipVerification(bundle.organization_membership.id);
  assert.equal((await client.verifyOrganizationMembership(JSON.stringify(downloaded))).organization, 'acme');
  assert.equal(calls.filter(c => c.url === endpoint).length, 4);
  assert.throws(() => client.verifyOrganizationMembership(JSON.stringify({ version: 1, statement: {} })), /membership bundle/);
});
