import { blake3 } from '@noble/hashes/blake3.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js';
import { loadSodium } from './sodium.js';

const encode = value => new TextEncoder().encode(value);
const decode = value => new TextDecoder('utf-8', { fatal: true }).decode(value);
const namespace = 'statement@ontic.space';
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function requireCheck(condition, message) { if (!condition) throw new Error(message); }
function hex(value, length, prefix = false) {
  requireCheck(typeof value === 'string' && (prefix ? /^0x[\da-f]+$/i : /^[\da-f]*$/i).test(value), 'Invalid hexadecimal verification data.');
  const bytes = hexToBytes(prefix ? value.slice(2) : value);
  requireCheck(bytes.length === length, 'Incorrect length of hexadecimal verification data.');
  return bytes;
}
const equal = (left, right) => bytesToHex(left) === bytesToHex(right);
function field(bytes) {
  const size = new Uint8Array(4);
  new DataView(size.buffer).setUint32(0, bytes.length);
  return concatBytes(size, bytes);
}

/** Bound SSH wire-format reads before parsing untrusted key and signature frames. */
function sshReader(bytes) {
  let offset = 0;
  const uint32 = () => {
    requireCheck(offset + 4 <= bytes.length, 'Truncated SSH signature or public key.');
    const value = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0);
    offset += 4;
    return value;
  };
  return {
    uint32,
    field() {
      const size = uint32();
      requireCheck(size <= bytes.length - offset, 'Truncated SSH signature or public key.');
      const value = bytes.slice(offset, offset + size); offset += size;
      return value;
    },
    end() { requireCheck(offset === bytes.length, 'Unexpected trailing SSH data.'); }
  };
}

/** Verify the OpenSSH signature over exact text (plain) or ciphertext (encrypted/scheduled). */
export async function verifyStatementSignature(statement, signature) {
  requireCheck(object(statement) && ['plain', 'encrypted', 'scheduled'].includes(statement.kind), 'Unsupported statement type.');
  const content = statement.kind === 'plain' ? statement.text : statement.ciphertext;
  requireCheck(typeof content === 'string' && content.length > 0 && encode(content).length <= 65536, 'The signed statement content is missing or too large.');
  requireCheck(['blake2b-256', 'sha256', 'blake3'].includes(statement.hash_algorithm), 'Unsupported statement hash algorithm.');
  const hash = statement.hash_algorithm === 'blake3' ? blake3(encode(content)) : statement.hash_algorithm === 'sha256' ? sha256(encode(content)) : blake2b(encode(content), { dkLen: 32 });
  requireCheck(equal(hash, hex(statement.hash, 32)), 'Content hash verification failed: the statement content was changed.');
  requireCheck(object(signature) && signature.format === 'sshsig' && signature.namespace === namespace, 'A statement SSH signature in the expected namespace is required.');
  const sodium = await loadSodium();
  const fromBase64 = value => {
    requireCheck(typeof value === 'string' && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value), 'Invalid SSH base64 data.');
    return sodium.from_base64(value, sodium.base64_variants.ORIGINAL);
  };
  requireCheck(typeof signature.public_key === 'string' && signature.public_key.length <= 2048, 'Invalid SSH public key.');
  const parts = signature.public_key.trim().split(/\s+/);
  requireCheck(parts[0] === 'ssh-ed25519' && parts.length >= 2, 'Only Ed25519 SSH statement signatures are supported.');
  const blob = fromBase64(parts[1]);
  const key = sshReader(blob);
  requireCheck(decode(key.field()) === 'ssh-ed25519', 'SSH public-key type mismatch.');
  const publicKey = key.field(); key.end();
  requireCheck(publicKey.length === 32, 'Invalid Ed25519 public key.');
  const fingerprint = `SHA256:${sodium.to_base64(sha256(blob), sodium.base64_variants.ORIGINAL).replace(/=+$/, '')}`;
  requireCheck(signature.fingerprint === fingerprint, 'Signing-key fingerprint verification failed.');
  requireCheck(typeof signature.signature === 'string' && signature.signature.length <= 65536, 'Invalid SSH signature.');
  const pem = signature.signature.trim().match(/^-----BEGIN SSH SIGNATURE-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END SSH SIGNATURE-----$/);
  requireCheck(pem, 'Invalid SSH signature envelope.');
  const bytes = fromBase64(pem[1].replace(/[\r\n]/g, ''));
  requireCheck(decode(bytes.slice(0, 6)) === 'SSHSIG', 'Invalid SSH signature framing.');
  const envelope = sshReader(bytes.slice(6));
  requireCheck(envelope.uint32() === 1 && equal(envelope.field(), blob), 'SSH signature version or public-key mismatch.');
  requireCheck(decode(envelope.field()) === namespace && envelope.field().length === 0, 'SSH signature namespace or reserved-field mismatch.');
  const algorithm = decode(envelope.field());
  requireCheck(['sha256', 'sha512'].includes(algorithm), 'Unsupported SSH signature hash algorithm.');
  const signed = sshReader(envelope.field()); envelope.end();
  requireCheck(decode(signed.field()) === 'ssh-ed25519', 'Unsupported SSH signature type.');
  const detached = signed.field(); signed.end();
  requireCheck(detached.length === 64, 'Invalid Ed25519 signature length.');
  const digest = algorithm === 'sha512' ? sha512(encode(content)) : sha256(encode(content));
  const framed = concatBytes(encode('SSHSIG'), field(encode(namespace)), field(new Uint8Array()), field(encode(algorithm)), field(digest));
  requireCheck(sodium.crypto_sign_verify_detached(detached, framed, publicKey), 'Signature verification failed: the content or signature was changed.');
  return { hash, fingerprint };
}

/** Reproduce Arbo's SHA-256 or BLAKE3 tree, packed sibling encoding, and least-significant-bit path. */
export function verifyStatementMerkleProof(proof, hash) {
  requireCheck(object(proof) && proof.version === 1 && ['sha256', 'blake3'].includes(proof.tree_hash) && ['blake2b-256', 'sha256', 'blake3'].includes(proof.statement_hash) && proof.max_levels === 256 && proof.siblings_encoding === 'arbo-packed-hex', 'Unsupported Merkle proof format.');
  requireCheck(proof.exists === true && proof.value === '', 'An inclusion proof with an empty leaf value is required.');
  const key = hex(proof.key, 32), root = hex(proof.root, 32);
  requireCheck(equal(key, hash), 'Merkle proof leaf does not match the statement content hash.');
  requireCheck(typeof proof.siblings === 'string' && proof.siblings.length <= 16456, 'Merkle proof is too large.');
  const packed = hex(proof.siblings, proof.siblings.length / 2);
  requireCheck(packed.length >= 4, 'Truncated packed Merkle proof.');
  const header = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
  const bitmapLength = header.getUint16(2, true);
  requireCheck(header.getUint16(0, true) === packed.length && bitmapLength <= 32 && bitmapLength + 4 <= packed.length, 'Invalid packed Merkle proof length.');
  let offset = 4 + bitmapLength;
  const siblings = [];
  for (let level = 0; level < bitmapLength * 8; level++) {
    const present = packed[4 + (level >> 3)] & (1 << (level % 8));
    if (offset === packed.length) {
      requireCheck(!present, 'Merkle proof bitmap references missing siblings.');
      continue;
    }
    if (present) {
      requireCheck(offset + 32 <= packed.length, 'Truncated Merkle sibling.');
      siblings.push(packed.slice(offset, offset + 32)); offset += 32;
    } else siblings.push(new Uint8Array(32));
  }
  requireCheck(offset === packed.length, 'Unexpected trailing Merkle siblings.');
  const treeHash = proof.tree_hash === 'blake3' ? blake3 : sha256;
  let node = treeHash(concatBytes(key, new Uint8Array([1])));
  for (let level = siblings.length - 1; level >= 0; level--) {
    const right = key[level >> 3] & (1 << (level % 8));
    node = treeHash(right ? concatBytes(siblings[level], node) : concatBytes(node, siblings[level]));
  }
  requireCheck(equal(node, root), 'Merkle proof verification failed: the statement is not included in this root.');
  return root;
}

/** Reject duplicate JSON fields and excessive nesting before interpreting a pasted bundle. */
function parseVerificationObject(text) {
  requireCheck(typeof text === 'string' && encode(text).length <= 262144, 'Paste a statement JSON bundle up to 256 KiB.');
  let bundle;
  try { bundle = JSON.parse(text); } catch { throw new Error('Invalid JSON. Paste the complete downloaded statement JSON.'); }
  let offset = 0;
  const space = () => { while (/\s/.test(text[offset] || '') && offset < text.length) offset++; };
  function string() {
    const start = offset++;
    while (offset < text.length) {
      const character = text[offset++];
      if (character === '\\') offset++;
      else if (character === '"') break;
    }
    const value = JSON.parse(text.slice(start, offset));
    requireCheck(!/[\uD800-\uDFFF]/u.test(value.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, '')), 'JSON contains invalid Unicode.');
    return value;
  }
  function value(depth = 0) {
    requireCheck(depth <= 32, 'Statement JSON is too deeply nested.'); space();
    if (text[offset] === '"') { string(); return; }
    if (text[offset] === '{' || text[offset] === '[') {
      const objectValue = text[offset++] === '{', end = objectValue ? '}' : ']', seen = new Set(); space();
      while (text[offset] !== end) {
        if (objectValue) {
          const name = string();
          requireCheck(!seen.has(name), `Duplicate JSON field: ${name}.`); seen.add(name);
          space(); offset++;
        }
        value(depth + 1); space();
        if (text[offset] === ',') { offset++; space(); } else break;
      }
      offset++;
    } else { while (offset < text.length && !/[\s,}\]]/.test(text[offset])) offset++; }
  }
  value();
  return bundle;
}

export function parseStatementBundle(text) {
  const bundle = parseVerificationObject(text);
  requireCheck(object(bundle) && bundle.version === 1 && (object(bundle.statement) || object(bundle.external_account) || object(bundle.organization_membership)), 'Paste the full version 1 statement, external account, or organization membership download, including its Merkle proof.');
  requireCheck(!(bundle.statement && bundle.external_account), 'A bundle cannot contain both a statement and an external account.');
  requireCheck([bundle.statement, bundle.external_account, bundle.organization_membership].filter(value => value !== undefined && value !== null).length === 1, 'A bundle must contain exactly one record type.');
  return bundle;
}

/** Validate caller-owned configuration without assigning meaning to the network. */
export function ethereumRPCURL(value) {
  requireCheck(typeof value === 'string' && value.length > 0, 'ethereumVerificationRPC must be a single Ethereum RPC URL.');
  const url = new URL(value);
  requireCheck(['https:', 'http:'].includes(url.protocol) && !url.username && !url.password && !url.hash,
    'Use an HTTP(S) Ethereum RPC URL without embedded credentials or a fragment.');
  return url.href;
}

/** Use the caller's RPC URL without backend credentials; bundles cannot select destinations. */
export function createVerificationRPC(ethereumVerificationRPC, signal, request = fetch) {
  const endpoint = ethereumRPCURL(ethereumVerificationRPC);
  let id = 0;
  return async (method, params) => {
    signal?.throwIfAborted();
    const requestID = ++id;
    let response;
    try {
      response = await request(endpoint, { method: 'POST', credentials: 'omit', referrerPolicy: 'no-referrer', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: requestID, method, params }), signal });
    } catch (failure) {
      if (signal?.aborted) throw failure;
      throw new Error('The public Ethereum RPC could not be reached. Try again.');
    }
    requireCheck(response.ok, 'The public Ethereum RPC is unavailable. Try again.');
    const reply = await response.json();
    requireCheck(reply.jsonrpc === '2.0' && reply.id === requestID && !reply.error && Object.hasOwn(reply, 'result'), 'The Ethereum RPC could not complete the verification request. Try again.');
    return reply.result;
  };
}

function quantity(value) {
  requireCheck(typeof value === 'string' && /^0x(?:0|[1-9a-f][\da-f]*)$/i.test(value), 'Invalid Ethereum numeric response.');
  return BigInt(value);
}

/** Check publication using append-only contract storage, without requiring archived receipts. */
export async function verifyStatementEthereum(anchor, root, publishing, rpc) {
  requireCheck(object(anchor) && ['mined', 'confirmed'].includes(anchor.status), 'The statement has no mined Ethereum publication yet.');
  requireCheck(publishing?.chain_id === anchor.chain_id && typeof publishing.contract_address === 'string' && publishing.contract_address.toLowerCase() === anchor.contract_address?.toLowerCase(), 'The Ethereum network or contract does not match this registry.');
  const contract = '0x' + bytesToHex(hex(anchor.contract_address, 20, true));
  requireCheck(equal(hex(anchor.root, 32, true), root), 'The Ethereum root does not match the verified Merkle proof.');
  const blockHash = '0x' + bytesToHex(hex(anchor.block_hash, 32, true));
  requireCheck(typeof anchor.block_number === 'string' && /^[1-9]\d{0,77}$/.test(anchor.block_number), 'Invalid Ethereum inclusion block number.');
  const blockNumber = BigInt(anchor.block_number), blockTag = '0x' + blockNumber.toString(16);
  requireCheck(blockNumber < 2n ** 256n, 'Ethereum block number exceeds the contract integer range.');
  requireCheck(quantity(await rpc('eth_chainId', [])) === BigInt(anchor.chain_id), 'The Ethereum RPC returned the wrong network.');
  const [block, storedRoot] = await Promise.all([
    rpc('eth_getBlockByNumber', [blockTag, false]),
    // publishRoot writes only at block.number and never overwrites a publication block.
    rpc('eth_call', [{ to: contract, data: '0x' + bytesToHex(keccak_256(encode('rootsByBlock(uint256)'))).slice(0, 8) + blockNumber.toString(16).padStart(64, '0') }, 'latest'])
  ]);
  requireCheck(object(block) && quantity(block.number) === blockNumber && block.hash?.toLowerCase() === blockHash, 'Ethereum block verification failed: the expected block is not canonical.');
  const seconds = quantity(block.timestamp);
  requireCheck(seconds <= 8640000000000n, 'Invalid Ethereum block timestamp.');
  const timestamp = new Date(Number(seconds) * 1000).toISOString();
  requireCheck(typeof anchor.block_timestamp === 'string' && Date.parse(anchor.block_timestamp) === Number(seconds) * 1000, 'Ethereum timestamp verification failed: the claimed timestamp differs from the block.');
  requireCheck(equal(hex(storedRoot, 32, true), root), 'Ethereum contract verification failed: rootsByBlock does not contain the expected root.');
  const current = await rpc('eth_getBlockByNumber', [blockTag, false]);
  requireCheck(current?.hash?.toLowerCase() === blockHash, 'The Ethereum block changed during verification. Try again.');
  return { blockNumber: blockNumber.toString(), timestamp };
}

/** Perform every cryptographic check locally; registry reads only establish username attribution. */
export async function verifyStatementJSON(text, { api, publishing, rpc, ethereumVerificationRPC, signal, progress = _message => {} }) {
  const bundle = parseStatementBundle(text);
  if (bundle.organization_membership) return verifyOrganizationMembershipBundle(bundle, { api, publishing, rpc, ethereumVerificationRPC, signal, progress });
  if (bundle.external_account) return verifyExternalAccountBundle(bundle, { api, publishing, rpc, ethereumVerificationRPC, signal, progress });
  progress('Verifying content hash and SSH signature…');
  const { hash, fingerprint } = await verifyStatementSignature(bundle.statement, bundle.signature);
  signal?.throwIfAborted();
  progress('Verifying Merkle inclusion proof…');
  requireCheck(bundle.merkle_proof?.statement_hash === bundle.statement.hash_algorithm, 'Statement and Merkle proof hash algorithms do not match.');
  const root = verifyStatementMerkleProof(bundle.merkle_proof, hash);
  const statement = bundle.statement;
  requireCheck(typeof statement.id === 'string' && statement.id.length <= 128 && typeof statement.author === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,38}$/.test(statement.author), 'Invalid statement ID or author.');
  progress('Checking the signing key’s registry attribution…');
  const saved = await api(`/statements/${encodeURIComponent(statement.id)}`, { signal });
  const keyIdentity = key => typeof key === 'string' ? key.trim().split(/\s+/).slice(0, 2).join(' ') : '';
  requireCheck(object(saved) && saved.author === statement.author && saved.kind === statement.kind && (!saved.hash_algorithm || saved.hash_algorithm === statement.hash_algorithm) && saved.hash?.toLowerCase() === bytesToHex(hash) && saved.signature?.fingerprint === fingerprint && keyIdentity(saved.signature?.public_key) === keyIdentity(bundle.signature.public_key), 'Author verification failed: the registry does not associate this signed statement with the claimed username.');
  progress('Checking the Ethereum publication, block, and timestamp…');
  const evidence = await verifyStatementEthereum(bundle.ethereum_anchor, root, publishing, rpc || createVerificationRPC(ethereumVerificationRPC, signal));
  signal?.throwIfAborted();
  return { author: statement.author, fingerprint, chainID: bundle.ethereum_anchor.chain_id, transactionHash: bundle.ethereum_anchor.transaction_hash, ...evidence };
}

export function statementVerificationMessage(result) {
  if (result.type === 'organization-membership-verification') return `Organization membership verification successful: registry record linking @${result.author} to @${result.organization}, included at Ethereum block number ${result.blockNumber} with timestamp ${result.timestamp}.`;
  if (result.type === 'external-account-verification') return `External account verification successful: registry record linking @${result.author} to ${result.service} account ${result.account}, included at Ethereum block number ${result.blockNumber} with timestamp ${result.timestamp}.`;
  return `Cryptographic statement verification successful: signed by ${result.fingerprint} from @${result.author}, included at Ethereum block number ${result.blockNumber} with timestamp ${result.timestamp}.`;
}

/** External verification records are registry attestations, not user SSH signatures. */
async function verifyExternalAccountBundle(bundle, { api, publishing, rpc, ethereumVerificationRPC, signal, progress }) {
  const entry = bundle.external_account;
  requireCheck(entry.hash_algorithm === 'blake3' && typeof entry.content === 'string' && encode(entry.content).length <= 65536, 'Invalid external account verification content.');
  progress('Verifying the external account record hash…');
  const hash = blake3(concatBytes(new Uint8Array([255]), encode('ontic.space/external-account-verification/v1\n' + entry.content)));
  requireCheck(equal(hash, hex(entry.hash, 32)), 'External account content hash verification failed: the record was changed.');
  const record = parseVerificationObject(entry.content);
  requireCheck(object(record) && record.type === 'external-account-verification' && record.version === 1, 'Unsupported external account verification record.');
  requireCheck(typeof record.username === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,38}$/.test(record.username), 'Invalid external account username.');
  for (const name of ['entry_id', 'service', 'account', 'identity_key', 'verified_at']) {
    requireCheck(typeof record[name] === 'string' && record[name].length > 0, `Missing external account field: ${name}.`);
  }
  requireCheck(Number.isFinite(Date.parse(record.verified_at.replace(' ', 'T') + (record.verified_at.includes('T') ? '' : 'Z'))), 'Invalid ownership verification date.');
  requireCheck(bundle.merkle_proof?.statement_hash === 'blake3', 'External account and proof hash algorithms do not match.');
  progress('Verifying Merkle inclusion proof…');
  const root = verifyStatementMerkleProof(bundle.merkle_proof, hash);
  signal?.throwIfAborted();
  // Confirm the record ID against the registry as well as verifying the typed hash.
  requireCheck(typeof entry.id === 'string' && /^[a-f0-9]{32}$/.test(entry.id), 'Invalid external verification ID.');
  progress('Checking the registry’s external account attestation…');
  const saved = await api(`/external-verifications/${encodeURIComponent(entry.id)}`, { signal });
  requireCheck(saved?.external_account?.id === entry.id && saved.external_account.hash === entry.hash && saved.external_account.content === entry.content && saved.external_account.hash_algorithm === 'blake3', 'The registry does not attest to this external account verification.');
  progress('Checking the Ethereum publication, block, and timestamp…');
  const evidence = await verifyStatementEthereum(bundle.ethereum_anchor, root, publishing, rpc || createVerificationRPC(ethereumVerificationRPC, signal));
  signal?.throwIfAborted();
  return { type: 'external-account-verification', author: record.username, service: record.service, account: record.account, verifiedAt: evidence.timestamp, chainID: bundle.ethereum_anchor.chain_id, transactionHash: bundle.ethereum_anchor.transaction_hash, ...evidence };
}

/** Accepted membership is a historical registry attestation, not a user signature. */
async function verifyOrganizationMembershipBundle(bundle, { api, publishing, rpc, ethereumVerificationRPC, signal, progress }) {
  const entry = bundle.organization_membership;
  requireCheck(object(entry) && entry.hash_algorithm === 'blake3' && typeof entry.content === 'string' && encode(entry.content).length <= 65536, 'Invalid organization membership content.');
  requireCheck(typeof entry.id === 'string' && /^[a-f0-9]{32}$/.test(entry.id), 'Invalid membership verification ID.');
  progress('Verifying the organization membership record hash…');
  const hash = blake3(concatBytes(new Uint8Array([255]), encode('ontic.space/organization-membership-verification/v1\n' + entry.content)));
  requireCheck(equal(hash, hex(entry.hash, 32)), 'Organization membership content hash verification failed: the record was changed.');
  const record = parseVerificationObject(entry.content);
  requireCheck(object(record) && record.type === 'organization-membership-verification' && record.version === 1, 'Unsupported organization membership record.');
  for (const name of ['username', 'organization']) {
    requireCheck(typeof record[name] === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,38}$/.test(record[name]), 'Invalid organization membership identity.');
  }
  requireCheck(record.username !== record.organization && typeof record.membership_id === 'string' && /^[a-f0-9]{32}$/.test(record.membership_id), 'Invalid organization membership relation.');
  for (const name of ['invited_at', 'recorded_at']) {
    requireCheck(typeof record[name] === 'string' && Number.isFinite(Date.parse(record[name].replace(' ', 'T') + (record[name].includes('T') ? '' : 'Z'))), 'Invalid membership record date.');
  }
  requireCheck(bundle.merkle_proof?.statement_hash === 'blake3' && bundle.merkle_proof?.tree_hash === 'blake3', 'Membership and proof hash algorithms do not match.');
  progress('Verifying Merkle inclusion proof…');
  const root = verifyStatementMerkleProof(bundle.merkle_proof, hash);
  signal?.throwIfAborted();
  progress('Checking the registry’s historical membership attestation…');
  const saved = await api(`/organization-membership-verifications/${encodeURIComponent(entry.id)}`, { signal });
  const attestation = saved?.organization_membership;
  requireCheck(attestation?.id === entry.id && attestation.hash === entry.hash && attestation.content === entry.content && attestation.hash_algorithm === 'blake3', 'The registry does not attest to this organization membership.');
  progress('Checking the Ethereum publication, block, and timestamp…');
  const evidence = await verifyStatementEthereum(bundle.ethereum_anchor, root, publishing, rpc || createVerificationRPC(ethereumVerificationRPC, signal));
  signal?.throwIfAborted();
  return { type: 'organization-membership-verification', author: record.username, organization: record.organization, membershipID: record.membership_id, chainID: bundle.ethereum_anchor.chain_id, transactionHash: bundle.ethereum_anchor.transaction_hash, ...evidence };
}
