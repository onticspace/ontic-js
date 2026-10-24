import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { blake3 } from '@noble/hashes/blake3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { parseStatementBundle, verifyStatementSignature, verifyStatementMerkleProof, verifyStatementEthereum, verifyStatementJSON, createVerificationRPC, statementVerificationMessage } from 'ontic-js';

// Generated and checked with the pinned Go Arbo library, including a 21-level branch.
const ethereumVerificationRPC = 'https://rpc.example/ethereum';
const fixtures = JSON.parse(readFileSync(new URL('./fixtures/statement-merkle.json', import.meta.url)));
const directory = mkdtempSync(join(tmpdir(), 'ontic-verification-test-'));
const keyFile = join(directory, 'key');
execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', keyFile]);
const publicKey = readFileSync(keyFile + '.pub', 'utf8').trim();
const fingerprint = execFileSync('ssh-keygen', ['-lf', keyFile + '.pub', '-E', 'sha256'], { encoding: 'utf8' }).split(/\s+/)[1];
after(async () => { rmSync(directory, { recursive: true, force: true }); });
const encode = value => new TextEncoder().encode(value);
const contentHash = content => bytesToHex(blake2b(encode(content), { dkLen: 32 }));
function signature(content, namespace = 'statement@ontic.space', hashAlgorithm = 'sha512') {
  return { format: 'sshsig', namespace: 'statement@ontic.space', public_key: publicKey, fingerprint,
    signature: execFileSync('ssh-keygen', ['-Y', 'sign', '-f', keyFile, '-n', namespace, '-O', `hashalg=${hashAlgorithm}`], { input: content, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }) };
}

test('library verifies legacy BLAKE2b/SHA-256 and new BLAKE3 statements with real OpenSSH signatures', async () => {
  for (const algorithm of ['blake2b-256', 'sha256', 'blake3']) {
    const hashContent = content => algorithm === 'blake3' ? bytesToHex(blake3(encode(content))) : algorithm === 'sha256' ? bytesToHex(sha256(encode(content))) : contentHash(content);
    for (const [kind, content] of [['plain', fixtures[1].content], ['encrypted', fixtures[3].content], ['scheduled', fixtures[4].content]]) {
      for (const hashAlgorithm of ['sha256', 'sha512']) {
        const statement = { kind, hash_algorithm: algorithm, hash: hashContent(content), [kind === 'plain' ? 'text' : 'ciphertext']: content };
        assert.equal((await verifyStatementSignature(statement, signature(content, undefined, hashAlgorithm))).fingerprint, fingerprint);
        await assert.rejects(verifyStatementSignature({ ...statement, [kind === 'plain' ? 'text' : 'ciphertext']: content + '\n' }, signature(content)), /Content hash verification failed/);
        await assert.rejects(verifyStatementSignature({ ...statement, hash: hashContent(content + ' changed'), [kind === 'plain' ? 'text' : 'ciphertext']: content + ' changed' }, signature(content)), /Signature verification failed/);
      }
    }
  }
});

test('signature verification rejects unsigned records, forged fingerprints, wrong namespaces, and malformed frames', async () => {
  const content = fixtures[1].content;
  const statement = { kind: 'plain', text: content, hash: contentHash(content), hash_algorithm: 'blake2b-256' };
  await assert.rejects(verifyStatementSignature(statement, null), /signature/);
  await assert.rejects(verifyStatementSignature(statement, { ...signature(content), fingerprint: 'SHA256:forged' }), /fingerprint/);
  await assert.rejects(verifyStatementSignature(statement, signature(content, 'identity-registry')), /namespace/);
  await assert.rejects(verifyStatementSignature(statement, { ...signature(content), signature: '-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----' }), /Truncated SSH/);
});

test('frontend Merkle verification interoperates with independent Arbo proofs', () => {
  for (const fixture of fixtures) {
    const hash = hexToBytes(contentHash(fixture.content));
    assert.equal(bytesToHex(verifyStatementMerkleProof(fixture.proof, hash)), fixture.proof.root);
    assert.throws(() => verifyStatementMerkleProof({ ...fixture.proof, root: '0'.repeat(64) }, hash), /Merkle proof verification failed/);
    assert.throws(() => verifyStatementMerkleProof(fixture.proof, new Uint8Array(32)), /leaf does not match/);
  }
});

test('malformed or unsupported Merkle proofs fail before unsafe unpacking', () => {
  const fixture = fixtures[1], hash = hexToBytes(fixture.proof.key);
  for (const siblings of ['', '00', '04002000', '0500010001', '04000000' + '00'.repeat(32)]) {
    assert.throws(() => verifyStatementMerkleProof({ ...fixture.proof, siblings }, hash), /Merkle|merkle/);
  }
  for (const change of [{ exists: false }, { value: '01' }, { tree_hash: 'keccak256' }, { max_levels: 512 }, { siblings_encoding: 'json' }]) {
    assert.throws(() => verifyStatementMerkleProof({ ...fixture.proof, ...change }, hash));
  }
});

const root = hexToBytes(fixtures[1].proof.root);
const contract = '0x' + '12'.repeat(20), transaction = '0x' + '34'.repeat(32), blockHash = '0x' + '56'.repeat(32);
const anchor = { status: 'confirmed', chain_id: '11155111', contract_address: contract, root: '0x' + bytesToHex(root), transaction_hash: transaction, block_number: '123456', block_hash: blockHash, block_timestamp: '2026-10-10T12:00:00Z' };
const publishing = { chain_id: anchor.chain_id, contract_address: contract };
const number = '0x' + BigInt(anchor.block_number).toString(16);
const timestamp = '0x' + (BigInt(Date.parse(anchor.block_timestamp)) / 1000n).toString(16);
const block = { hash: blockHash, number, timestamp };
function rpc(overrides = {}, calls = []) {
  return async (method, params) => {
    calls.push({ method, params });
    if (Object.hasOwn(overrides, method)) return typeof overrides[method] === 'function' ? overrides[method](params) : overrides[method];
    return { eth_chainId: '0xaa36a7', eth_getBlockByNumber: block, eth_call: anchor.root }[method];
  };
}

test('Ethereum checks read the publication block and rootsByBlock', async () => {
  const calls = [];
  const result = await verifyStatementEthereum(anchor, root, publishing, rpc({}, calls));
  assert.deepEqual(result, { blockNumber: '123456', timestamp: '2026-10-10T12:00:00.000Z' });
  const call = calls.find(call => call.method === 'eth_call');
  const selector = bytesToHex(keccak_256(encode('rootsByBlock(uint256)'))).slice(0, 8);
  assert.deepEqual(call.params, [{ to: contract, data: '0x' + selector + BigInt(anchor.block_number).toString(16).padStart(64, '0') }, 'latest']);
  assert.equal(calls.filter(call => call.method === 'eth_getBlockByNumber').length, 2);
});

test('Ethereum publication verification succeeds when the RPC has pruned historical receipts and logs', async () => {
  const calls = [];
  const prunedHistory = () => { throw new Error('pruned history unavailable'); };
  const result = await verifyStatementEthereum(anchor, root, publishing, rpc({
    eth_getTransactionReceipt: null,
    eth_getBlockReceipts: null,
    eth_getLogs: prunedHistory
  }, calls));
  assert.equal(result.blockNumber, anchor.block_number);
  assert.deepEqual(calls.map(call => call.method).sort(), ['eth_call', 'eth_chainId', 'eth_getBlockByNumber', 'eth_getBlockByNumber']);
});

test('Ethereum verification rejects forged roots, timestamps, networks, and reorganized blocks', async () => {
  for (const [change, overrides, expected] of [
    [{ status: 'pending' }, {}, /no mined/],
    [{ chain_id: '1' }, {}, /does not match this registry/],
    [{ contract_address: '0x' + '99'.repeat(20) }, {}, /does not match this registry/],
    [{ root: '0x' + '00'.repeat(32) }, {}, /root does not match/],
    [{ block_timestamp: '2026-10-09T12:00:00Z' }, {}, /timestamp verification failed/],
    [{}, { eth_chainId: '0x1' }, /wrong network/],
    [{}, { eth_getBlockByNumber: { ...block, hash: transaction } }, /not canonical/],
    [{}, { eth_getBlockByNumber: null }, /not canonical/],
    [{}, { eth_getBlockByNumber: { ...block, number: '0x1' } }, /not canonical/],
    [{}, { eth_call: '0x' + '00'.repeat(32) }, /rootsByBlock/],
    [{}, { eth_call: '0x' + '99'.repeat(32) }, /rootsByBlock/],
    [{}, { eth_call: '0x' }, /hexadecimal/]
  ]) await assert.rejects(verifyStatementEthereum({ ...anchor, ...change }, root, publishing, rpc(overrides)), expected);
  let reads = 0;
  await assert.rejects(verifyStatementEthereum(anchor, root, publishing, rpc({ eth_getBlockByNumber: () => ++reads === 1 ? block : { ...block, hash: transaction } })), /block changed/);
});

function bundle() {
  const content = fixtures[1].content;
  return { version: 1, statement: { id: 'sample', author: 'alice', kind: 'plain', text: content, hash: contentHash(content), hash_algorithm: 'blake2b-256' }, signature: signature(content), merkle_proof: fixtures[1].proof, ethereum_anchor: anchor };
}

test('full verification keeps JSON local and binds the signed key to registry attribution', async () => {
  const input = bundle(), requests = [], progress = [];
  const api = async (path, options) => { requests.push({ path, options }); return { ...input.statement, signature: input.signature }; };
  const result = await verifyStatementJSON(JSON.stringify(input), { api, publishing, rpc: rpc(), progress: message => progress.push(message) });
  assert.equal(result.author, 'alice');
  assert.equal(result.fingerprint, fingerprint);
  assert.equal(result.chainID, anchor.chain_id);
  assert.equal(result.transactionHash, anchor.transaction_hash);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].path, '/statements/sample');
  assert.equal(requests[0].options.body, undefined);
  assert.equal(progress.length, 4);
  assert.match(statementVerificationMessage(result), /Cryptographic statement verification successful: signed by SHA256:.* from @alice, included at Ethereum block number 123456 with timestamp 2026-10-10T12:00:00.000Z/);
  await assert.rejects(verifyStatementJSON(JSON.stringify({ ...input, statement: { ...input.statement, author: 'bob' } }), { api, publishing, rpc: rpc() }), /Author verification failed/);
  await assert.rejects(verifyStatementJSON(JSON.stringify(input), { api: async () => ({ ...input.statement, signature: { ...input.signature, public_key: 'ssh-ed25519 other-key' } }), publishing, rpc: rpc() }), /Author verification failed/);
});

test('JSON parsing rejects incomplete bundles, duplicate fields, invalid Unicode, and excessive nesting', () => {
  assert.throws(() => parseStatementBundle('not json'), /Invalid JSON/);
  assert.throws(() => parseStatementBundle('{"statement":{}}'), /full version 1/);
  assert.throws(() => parseStatementBundle('{"version":1,"statement":{"hash":"first","hash":"second"}}'), /Duplicate JSON field/);
  assert.throws(() => parseStatementBundle('{"version":1,"version":2,"statement":{}}'), /Duplicate JSON field/);
  assert.throws(() => parseStatementBundle('{"version":1,"statement":{"text":"\\ud800"}}'), /invalid Unicode/);
  assert.throws(() => parseStatementBundle('['.repeat(34) + '0' + ']'.repeat(34)), /too deeply nested/);
  assert.throws(() => parseStatementBundle(' '.repeat(262145)), /256 KiB/);
  assert.equal(parseStatementBundle('{"version":1,"statement":{"text":"😀"},"signature":null}').statement.text, '😀');
});

test('public RPC requests contain only reads and omit cookies, bearer tokens, and pasted content', async () => {
  const calls = [];
  const request = async (url, options) => {
    calls.push({ url, options });
    const body = JSON.parse(options.body);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: '0xaa36a7' }));
  };
  assert.equal(await createVerificationRPC(ethereumVerificationRPC, undefined, request)('eth_chainId', []), '0xaa36a7');
  assert.equal(calls[0].url, 'https://rpc.example/ethereum');
  assert.equal(calls[0].options.credentials, 'omit');
  assert.equal(calls[0].options.headers.Authorization, undefined);
  assert.equal(calls[0].options.referrerPolicy, 'no-referrer');
  assert.deepEqual(JSON.parse(calls[0].options.body).params, []);
  await assert.rejects(createVerificationRPC(ethereumVerificationRPC, undefined, async () => { throw new Error('network'); })('eth_chainId', []), /could not be reached/);
  await assert.rejects(createVerificationRPC(ethereumVerificationRPC, undefined, async () => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { message: 'upstream secret' } })))('eth_chainId', []), /could not complete/);
  assert.throws(() => createVerificationRPC({ '1': ethereumVerificationRPC }), /single Ethereum RPC URL/);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(createVerificationRPC(ethereumVerificationRPC, controller.signal, request)('eth_chainId', []), { name: 'AbortError' });
});

 test('SHA-256 statements verify against SHA-256 Merkle trees', () => {
  const hash = sha256(encode('new SHA-256 statement'));
  const root = sha256(new Uint8Array([...hash, 1]));
  const proof = { ...fixtures[0].proof, statement_hash: 'sha256', key: bytesToHex(hash), root: bytesToHex(root), siblings: fixtures[0].proof.siblings };
  assert.deepEqual(verifyStatementMerkleProof(proof, hash), root);
 });

 test('full SHA-256 verification checks algorithm agreement and registry attribution', async () => {
  const input = bundle();
  const hash = sha256(encode(input.statement.text));
  const root = sha256(new Uint8Array([...hash, 1]));
  input.statement = { ...input.statement, hash_algorithm: 'sha256', hash: bytesToHex(hash) };
  input.merkle_proof = { ...fixtures[0].proof, statement_hash: 'sha256', key: bytesToHex(hash), root: bytesToHex(root) };
  input.ethereum_anchor = { ...anchor, root: '0x' + bytesToHex(root) };
  const api = async () => ({ ...input.statement, signature: input.signature });
  const options = { api, publishing, rpc: rpc({ eth_call: '0x' + bytesToHex(root) }) };
  assert.equal((await verifyStatementJSON(JSON.stringify(input), options)).author, 'alice');
  await assert.rejects(verifyStatementJSON(JSON.stringify({ ...input, merkle_proof: { ...input.merkle_proof, statement_hash: 'blake2b-256' } }), options), /hash algorithms do not match/);
  await assert.rejects(verifyStatementJSON(JSON.stringify(input), { ...options, api: async () => ({ ...input.statement, hash_algorithm: 'blake2b-256', signature: input.signature }) }), /Author verification failed/);
 });

test('full BLAKE3 verification uses Arbo-compatible BLAKE3 content and tree hashes', async () => {
  const input = bundle();
  const hash = blake3(encode(input.statement.text));
  const root = blake3(new Uint8Array([...hash, 1]));
  input.statement = { ...input.statement, hash_algorithm: 'blake3', hash: bytesToHex(hash) };
  input.merkle_proof = { ...fixtures[0].proof, tree_hash: 'blake3', statement_hash: 'blake3', key: bytesToHex(hash), root: bytesToHex(root) };
  input.ethereum_anchor = { ...anchor, root: '0x' + bytesToHex(root) };
  const api = async () => ({ ...input.statement, signature: input.signature });
  const options = { api, publishing, rpc: rpc({ eth_call: '0x' + bytesToHex(root) }) };
  assert.equal((await verifyStatementJSON(JSON.stringify(input), options)).author, 'alice');
  assert.throws(() => verifyStatementMerkleProof({ ...input.merkle_proof, tree_hash: 'sha256' }, hash), /verification failed/);
});

// Produced and independently checked with Arbo 124e5c6dd79c HashBlake3.
test('library verifies Go Arbo BLAKE3 proofs, including multi-leaf branches', () => {
  const fixtures = JSON.parse(readFileSync(new URL('./fixtures/statement-merkle-blake3.json', import.meta.url)));
  for (const fixture of fixtures) {
    const hash = blake3(encode(fixture.content));
    assert.equal(bytesToHex(hash), fixture.proof.key);
    assert.equal(bytesToHex(verifyStatementMerkleProof(fixture.proof, hash)), fixture.proof.root);
    assert.throws(() => verifyStatementMerkleProof({ ...fixture.proof, root: '0'.repeat(64) }, hash), /Merkle proof verification failed/);
  }
});
