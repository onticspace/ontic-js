import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { verifyStatementJSON } from 'ontic-js';

const encode = text => new TextEncoder().encode(text);
const content = JSON.stringify({ type: 'external-account-verification', version: 1, entry_id: 'entry', username: 'alice', service: 'GitHub', account: 'octocat', identity_key: 'github:42', verified_at: '2026-10-05 00:00:00' });
const hash = blake3(concatBytes(new Uint8Array([255]), encode('ontic.space/external-account-verification/v1\n' + content)));
const root = bytesToHex(blake3(concatBytes(hash, new Uint8Array([1]))));
const contract = '0x' + '12'.repeat(20);
const blockHash = '0x' + '34'.repeat(32);
const block = { number: '0xb', hash: blockHash, timestamp: '0x68e1b880' };
const timestamp = new Date(Number(BigInt(block.timestamp)) * 1000).toISOString();
const bundle = {
  version: 1,
  external_account: { id: 'ab'.repeat(16), content, hash: bytesToHex(hash), hash_algorithm: 'blake3' },
  merkle_proof: { version: 1, tree_hash: 'blake3', statement_hash: 'blake3', max_levels: 256, root, key: bytesToHex(hash), value: '', siblings: '04000000', siblings_encoding: 'arbo-packed-hex', exists: true },
  ethereum_anchor: { status: 'confirmed', chain_id: '11155111', contract_address: contract, root: '0x' + root, block_number: '11', block_hash: blockHash, block_timestamp: timestamp, transaction_hash: '0x' + '56'.repeat(32) }
};
const publishing = { chain_id: '11155111', contract_address: contract };
const rpc = async method => method === 'eth_chainId' ? '0xaa36a7' : method === 'eth_call' ? '0x' + root : block;
const options = { publishing, rpc, api: async path => { assert.equal(path, `/external-verifications/${bundle.external_account.id}`); return bundle; } };

test('external verification binds the relation, Arbo proof, registry attestation and Ethereum evidence', async () => {
  const result = await verifyStatementJSON(JSON.stringify(bundle), options);
  assert.equal(result.type, 'external-account-verification');
  assert.equal(result.author, 'alice');
  assert.equal(result.service, 'GitHub');
  assert.equal(result.account, 'octocat');
  assert.equal(result.blockNumber, '11');
  assert.equal(result.timestamp, timestamp);
  assert.equal(result.verifiedAt, timestamp);
});

test('tampered accounts, non-attested lookalikes, unmined roots and mismatched contracts fail', async () => {
  const changed = structuredClone(bundle);
  changed.external_account.content = content.replace('octocat', 'attacker');
  await assert.rejects(verifyStatementJSON(JSON.stringify(changed), options), /content hash verification failed/);
  await assert.rejects(verifyStatementJSON(JSON.stringify(bundle), { ...options, api: async () => ({ external_account: { ...bundle.external_account, content: content + ' ' } }) }), /registry does not attest/);
  await assert.rejects(verifyStatementJSON(JSON.stringify({ ...bundle, ethereum_anchor: { ...bundle.ethereum_anchor, status: 'pending' } }), options), /no mined Ethereum publication/);
  await assert.rejects(verifyStatementJSON(JSON.stringify(bundle), { ...options, publishing: { ...publishing, contract_address: '0x' + '11'.repeat(20) } }), /network or contract/);
  const badRoot = structuredClone(bundle); badRoot.merkle_proof.root = '00'.repeat(32);
  await assert.rejects(verifyStatementJSON(JSON.stringify(badRoot), options), /Merkle proof verification failed/);
});

test('user-authored statement text cannot masquerade as a typed registry commitment', async () => {
  const lookalike = structuredClone(bundle);
  // A user can sign and commit this exact UTF-8 text as an ordinary statement.
  const statementHash = blake3(encode('ontic.space/external-account-verification/v1\n' + content));
  lookalike.external_account.hash = bytesToHex(statementHash);
  lookalike.merkle_proof.key = bytesToHex(statementHash);
  lookalike.merkle_proof.root = bytesToHex(blake3(concatBytes(statementHash, new Uint8Array([1]))));
  lookalike.ethereum_anchor.root = '0x' + lookalike.merkle_proof.root;
  await assert.rejects(verifyStatementJSON(JSON.stringify(lookalike), { ...options, api: async () => lookalike }), /content hash verification failed/);
});

test('external content rejects duplicate fields and cannot masquerade as a signed statement', async () => {
  const duplicated = content.replace('"username":"alice"', '"username":"alice","username":"bob"');
  const bad = structuredClone(bundle);
  bad.external_account.content = duplicated;
  bad.external_account.hash = bytesToHex(blake3(concatBytes(new Uint8Array([255]), encode('ontic.space/external-account-verification/v1\n' + duplicated))));
  await assert.rejects(verifyStatementJSON(JSON.stringify(bad), options), /Duplicate JSON field/);
  await assert.rejects(verifyStatementJSON(JSON.stringify({ ...bundle, statement: { kind: 'plain' } }), options), /both a statement and an external account/);
});
