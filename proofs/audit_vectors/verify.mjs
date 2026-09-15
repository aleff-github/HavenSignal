// Independent offline verification: node-cbor and noble, no Python calls.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import cbor from 'cbor';
import { ed25519 } from '@noble/curves/ed25519.js';

const CONTENT_TYPE = 'application/vnd.anonymous-reporting.audit-acceptance+cbor;v=1';
const read = name => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const hex = value => {
  assert.equal(typeof value, 'string');
  assert.match(value, /^(?:[a-f0-9]{2})*$/);
  return Buffer.from(value, 'hex');
};
const encode = value => cbor.encodeCanonical(value);
const decode = raw => cbor.decodeFirstSync(raw, {
  preferMap: true, preventDuplicateKeys: true, max_depth: 8,
});
const semantic = value => {
  if (Array.isArray(value)) return value.map(semantic);
  if (value !== null && typeof value === 'object') {
    if (Object.keys(value).join() === 'bytes') return hex(value.bytes);
    if (Object.keys(value).join() === 'integer') return BigInt(value.integer);
    throw new Error('unknown_fixture_shape');
  }
  return value;
};
const uint = value => (
  (typeof value === 'bigint' && value >= 0n && value <= 0xffffffffffffffffn) ||
  (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
);
const octets = (value, size) => Buffer.isBuffer(value) && value.length === size;

function wireMatchesFixture(raw, publicKey, kid, expected) {
  // This result is wire syntax/signature/fixture evidence, never authority.
  try {
    if (raw.length === 0 || raw.length > 2048) return false;
    const tagged = decode(raw);
    if (!(tagged instanceof cbor.Tagged) || tagged.tag !== 18 ||
        !Array.isArray(tagged.value) || tagged.value.length !== 4) return false;
    const [protectedBytes, unprotected, payload, signature] = tagged.value;
    if (!Buffer.isBuffer(protectedBytes) || !Buffer.isBuffer(payload) ||
        !(unprotected instanceof Map) || unprotected.size !== 0 ||
        !octets(signature, 64) || !encode(tagged).equals(raw)) return false;
    const headers = decode(protectedBytes);
    if (!(headers instanceof Map) || headers.size !== 3 ||
        ![1, 3, 4].every(label => headers.has(label)) ||
        headers.get(1) !== -8 || headers.get(3) !== CONTENT_TYPE ||
        !octets(headers.get(4), 16) || !headers.get(4).equals(kid) ||
        !encode(headers).equals(protectedBytes)) return false;
    const claims = decode(payload);
    if (!Array.isArray(claims) || claims.length !== 7 || claims[0] !== 1 ||
        !octets(claims[1], 32) || !octets(claims[2], 16) || !uint(claims[3]) ||
        !octets(claims[4], 32) || !uint(claims[5]) ||
        !(claims[6] === null || (uint(claims[6]) && claims[6] >= claims[5])) ||
        !encode(claims).equals(payload) || !encode(expected).equals(payload)) return false;
    const input = encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
    return ed25519.verify(signature, input, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

const standards = read('standards.json');
for (const vector of standards.cbor) {
  assert.deepEqual(encode(semantic(vector.value)), hex(vector.hex), vector.id);
  assert.deepEqual(encode(decode(hex(vector.hex))), hex(vector.hex), vector.id);
}
for (const vector of standards.ed25519) {
  const seed = hex(vector.seed_hex);
  assert.deepEqual(Buffer.from(ed25519.getPublicKey(seed)), hex(vector.public_hex), vector.id);
  assert.deepEqual(Buffer.from(ed25519.sign(hex(vector.message_hex), seed)), hex(vector.signature_hex), vector.id);
  assert.equal(ed25519.verify(hex(vector.signature_hex), hex(vector.message_hex),
    hex(vector.public_hex), { zip215: false }), true, vector.id);
}

const corpus = read('vectors.json');
const seed = hex(standards.ed25519[0].seed_hex);
const publicKey = hex(standards.ed25519[0].public_hex);
const publicCose = encode(new Map([[1, 1], [-1, 6], [-2, publicKey]]));
const kid = createHash('sha256').update(publicCose).digest().subarray(0, 16);
const published = standards.cose_wg;
const publishedRaw = hex(published.receipt_hex);
const publishedBody = decode(publishedRaw).value;
const publishedInput = encode(['Signature1', publishedBody[0], Buffer.alloc(0), publishedBody[2]]);
assert.deepEqual(publishedInput, hex(published.signature_input_hex), published.id);
assert.deepEqual(publishedBody[2], hex(published.message_hex), published.id);
assert.equal(ed25519.verify(publishedBody[3], publishedInput, publicKey, { zip215: false }), true, published.id);
assert.equal(wireMatchesFixture(publishedRaw, publicKey, kid, []), false, 'generic COSE is not audit');
assert.equal(corpus.format, 'havensignal-offline-audit-wire-v1');
assert.deepEqual(hex(corpus.public_key_hex), publicKey);
assert.deepEqual(hex(corpus.public_cose_key_hex), publicCose);
assert.deepEqual(hex(corpus.kid_hex), kid);
assert.equal(corpus.content_type, CONTENT_TYPE);
assert.ok(corpus.vectors.length > 3);
for (const vector of corpus.vectors) {
  const raw = hex(vector.receipt_hex);
  assert.equal(typeof vector.expected_wire_valid, 'boolean');
  assert.equal(vector.authorizes_protected_action, false);
  if (vector.requires_valid_signature) {
    // Duplicate-header negatives need permissive raw decoding only for this
    // cryptographic assertion; the profile verifier above remains strict.
    const body = cbor.decodeFirstSync(raw, { preferMap: true, max_depth: 8 }).value;
    const input = encode(['Signature1', body[0], Buffer.alloc(0), body[2]]);
    assert.equal(ed25519.verify(body[3], input, publicKey, { zip215: false }), true, vector.id);
  }
  assert.equal(wireMatchesFixture(raw, publicKey, kid, semantic(vector.expected_claims)),
    vector.expected_wire_valid, vector.id);
  if (vector.expected_wire_valid) {
    const [protectedBytes, unprotected, payload, signature] = decode(raw).value;
    assert.deepEqual(protectedBytes, hex(vector.protected_hex), vector.id);
    assert.deepEqual(payload, hex(vector.payload_hex), vector.id);
    const input = encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
    assert.deepEqual(input, hex(vector.signature_input_hex), vector.id);
    // Independently reproduce the complete artifact, not only verify its signature.
    const signed = Buffer.from(ed25519.sign(input, seed));
    assert.deepEqual(signed, signature, vector.id);
    assert.deepEqual(encode(new cbor.Tagged(18, [protectedBytes, unprotected, payload, signed])), raw, vector.id);
  }
}
console.log(`JavaScript: PASS (${standards.cbor.length} CBOR, ${standards.ed25519.length} Ed25519, 1 published COSE, ${corpus.vectors.length} receipt cases; no authorization)`);
