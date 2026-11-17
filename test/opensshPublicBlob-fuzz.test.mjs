// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Seeded fuzz for opensshPublicBlob (lib/iocs.mjs), refs #33. The function reads the public key blob out of an OpenSSH
// private key file ("openssh-key-v1") and returns it, or null; every short read throws inside and is caught, so it must
// never throw. Whatever the input, the return is null or a Buffer (never undefined, never a string), and where the input
// is a good key, with whatever junk around it or whitespace inside it, the bytes are exactly the blob that went in.
// The key file is built by hand (node:crypto can't export an OpenSSH private key); the public blob is a real ed25519
// key's. The generator is mulberry32, inline, from three fixed seeds, so a failure names its seed and iteration and
// replays exactly. The 1 MB cases run once, not per iteration.
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { opensshPublicBlob } from '../lib/iocs.mjs';

const SEEDS = [0x0D15EA5E, 0xC0FFEE11, 0x5EED0033];
const ITERATIONS = 2000;                 // per seed; each iteration runs cases 1 to 9
const BEGIN = '-----BEGIN OPENSSH PRIVATE KEY-----';
const END = '-----END OPENSSH PRIVATE KEY-----';

/** mulberry32: a small seeded generator. Returns a function giving floats in [0, 1). */
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const int = (rnd, n) => Math.floor(rnd() * n);                       // 0 .. n-1
const pick = (rnd, list) => list[int(rnd, list.length)];

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const field = (bytes) => { const b = Buffer.from(bytes); return Buffer.concat([u32(b.length), b]); };

// A real ed25519 public key: the last 32 bytes of its SPKI DER are the raw key. The blob is field "ssh-ed25519", field raw.
const raw32 = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
const BLOB = Buffer.concat([field('ssh-ed25519'), field(raw32)]);

/** The decoded key file: magic and NUL, cipher "none", kdf "none", kdf options empty, count 1, then the public blob.
 *  → { bytes, lenAt: the offset of each of the four length fields read before the blob's end, blobAt, blobEnd }. */
function keyBytes(blob = BLOB) {
  const head = Buffer.from('openssh-key-v1\0', 'latin1');
  const parts = [head, field('none'), field('none'), field(''), u32(1), field(blob)];
  const lenAt = [];
  let o = 0;
  parts.forEach((p, i) => { if (i === 1 || i === 2 || i === 3 || i === 5) lenAt.push(o); o += p.length; });
  const bytes = Buffer.concat(parts);
  return { bytes, lenAt, blobAt: bytes.length - blob.length, blobEnd: bytes.length };
}
const wrap = (bytes) => `${BEGIN}\n${bytes.toString('base64').match(/.{1,70}/g)?.join('\n') ?? ''}\n${END}\n`;
const KEY = keyBytes();
const VALID = wrap(KEY.bytes);

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=-_ \n\t!#$%&*.:;<>?@[]{}~';
const text = (rnd, max = 300) => { let s = ''; for (let n = int(rnd, max + 1); n > 0; n--) s += ALPHABET[int(rnd, ALPHABET.length)]; return s; };
const digest = (r) => (r === null ? 'null' : createHash('sha256').update(r).digest('hex'));

/** Calls opensshPublicBlob and holds it to the two rules for every input: it doesn't throw, and it returns null or a Buffer. */
function call(input, ctx) {
  let r;
  try { r = opensshPublicBlob(input); } catch (e) { assert.fail(`${ctx}: threw ${e && e.stack ? e.stack : e}`); }
  assert.ok(r === null || Buffer.isBuffer(r), `${ctx}: returned ${r === undefined ? 'undefined' : typeof r}, not null or a Buffer`);
  return r;
}
const expectNull = (input, ctx) => assert.equal(call(input, ctx), null, `${ctx}: expected null`);
function expectBytes(input, want, ctx) {
  const r = call(input, ctx);
  assert.ok(r !== null, `${ctx}: expected the ${want.length} blob bytes, got null`);
  assert.ok(r.equals(want), `${ctx}: bytes differ: want ${want.toString('hex')}, got ${r.toString('hex')}`);
}

/** One pass over a seed: cases 1 to 9, ITERATIONS times. → one digest per call, in order, for the determinism check. */
function pass(seed) {
  const rnd = mulberry32(seed);
  const out = [];
  const run = (input, ctx, expect) => {
    if (expect === null) expectNull(input, ctx); else if (expect) expectBytes(input, expect, ctx); else call(input, ctx);
    out.push(digest(opensshPublicBlob(input)));
  };
  for (let i = 0; i < ITERATIONS; i++) {
    const at = (c) => `seed=0x${seed.toString(16)} iteration=${i} case ${c}`;

    // 1. random text with no markers
    run(text(rnd), at('1 no markers'), null);
    // 2. random text with a BEGIN and no END
    run(`${text(rnd)}\n${BEGIN}\n${text(rnd)}`, at('2 BEGIN, no END'), null);
    // 3. a valid key, untouched
    run(VALID, at('3 valid key'), BLOB);
    // 3b. the same key wrapped in junk text
    run(`${text(rnd)}\n${VALID}${text(rnd)}`, at('3b valid key in junk'), BLOB);

    // 4. truncated at a random offset: the file text, then the decoded bytes (re-encoded)
    const cutText = int(rnd, VALID.length);
    run(VALID.slice(0, cutText), at(`4 text cut at ${cutText}`), cutText >= VALID.indexOf(END) + END.length ? BLOB : null);
    const cutBytes = int(rnd, KEY.bytes.length);
    run(wrap(KEY.bytes.subarray(0, cutBytes)), at(`4 bytes cut at ${cutBytes}`), cutBytes >= KEY.blobEnd ? BLOB : null);

    // 5. one random bit flipped in the decoded bytes. The magic, the length fields and the count may turn it into
    //    anything (null or a Buffer); a bit inside the blob must come back as exactly that bit changed.
    const flipAt = int(rnd, KEY.bytes.length), bit = int(rnd, 8);
    const flipped = Buffer.from(KEY.bytes); flipped[flipAt] ^= 1 << bit;
    let want;
    if (flipAt >= KEY.blobAt) { want = Buffer.from(BLOB); want[flipAt - KEY.blobAt] ^= 1 << bit; }
    run(wrap(flipped), at(`5 bit ${bit} of byte ${flipAt}`), want);

    // 6. one of the length fields set to 0xFFFFFFFF: it reads past the end, so null
    const lenAt = pick(rnd, KEY.lenAt);
    const big = Buffer.from(KEY.bytes); big.writeUInt32BE(0xFFFFFFFF, lenAt);
    run(wrap(big), at(`6 length field at ${lenAt}`), null);

    // 7. markers with an empty body, and markers around text that is not base64
    run(`${BEGIN}${END}`, at('7 empty body'), null);
    run(`${BEGIN}\n${pick(rnd, ['', ' ', '\n', '\r\n\t '])}\n${END}\n`, at('7 blank body'), null);
    run(`${BEGIN}\n${text(rnd).replace(/[A-Za-z0-9+/=_\s-]/g, '!')}\n${END}\n`, at('7 not base64'), null);

    // 8. a BEGIN inside a BEGIN (the lazy match starts at the first, so its body holds the second marker: whatever
    //    that decodes to, null or a Buffer), and text after the END line (the first END ends it: the blob is the first key's)
    run(`${BEGIN}\n${VALID}`, at('8 BEGIN inside BEGIN'));
    run(`${BEGIN}\n${text(rnd)}\n${VALID}`, at('8 BEGIN, junk, BEGIN'));
    run(`${VALID}${text(rnd)}\n${BEGIN}\n${text(rnd)}\n${END}\n${text(rnd)}`, at('8 text and markers after END'), BLOB);
    run(`${VALID}${wrap(keyBytes(Buffer.concat([field('ssh-ed25519'), field(Buffer.alloc(32, 7))])).bytes)}`, at('8 a second key after the first'), BLOB);

    // 9. whitespace and newlines sprinkled through the body: it must still parse
    let body = KEY.bytes.toString('base64');
    for (let n = 1 + int(rnd, 40); n > 0; n--) {
      const p = int(rnd, body.length + 1);
      body = body.slice(0, p) + pick(rnd, [' ', '\t', '\n', '\r\n', '  \n', '\n\n ']) + body.slice(p);
    }
    run(`${BEGIN}${pick(rnd, ['\n', ' ', '\r\n'])}${body}${pick(rnd, ['\n', ' ', ''])}${END}`, at('9 whitespace in body'), BLOB);
  }
  return out;
}

for (const seed of SEEDS) {
  test(`opensshPublicBlob fuzz, seed 0x${seed.toString(16)}: ${ITERATIONS} iterations of cases 1 to 9, never throws, null or a Buffer, exact bytes for a good key`, () => {
    const first = pass(seed);
    assert.ok(first.length >= ITERATIONS * 9, `seed 0x${seed.toString(16)}: only ${first.length} calls made`);
    assert.ok(first.some((d) => d !== 'null'), 'no call returned a key: the fixture is not being read');
    assert.ok(first.includes('null'), 'no call returned null: the bad inputs are not bad');
    // the same seed again gives the same result for every call, so the suite is not flaky
    const second = pass(seed);
    assert.equal(second.length, first.length, `seed 0x${seed.toString(16)}: a second pass made a different number of calls`);
    const diff = first.findIndex((d, k) => d !== second[k]);
    assert.equal(diff, -1, `seed 0x${seed.toString(16)}: the second pass differs from the first at call ${diff}`);
  });
}

test('opensshPublicBlob fuzz, case 10: about 1 MB of filler between the markers, and 1 MB of junk around a good key', () => {
  const rnd = mulberry32(SEEDS[0]);
  const MB = 1024 * 1024;
  const b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let filler = '';
  while (filler.length < MB) { let line = ''; for (let k = 0; k < 70; k++) line += b64[int(rnd, 64)]; filler += `${line}\n`; }
  const ctx = (c) => `seed=0x${SEEDS[0].toString(16)} case 10 ${c}`;
  expectNull(`${BEGIN}\n${filler}${END}\n`, ctx('1 MB of base64 between the markers'));
  expectNull(`${BEGIN}\n${' \n\t'.repeat(Math.ceil(MB / 3))}${END}\n`, ctx('1 MB of whitespace between the markers'));
  expectNull(`${BEGIN}\n${filler}`, ctx('1 MB after a BEGIN, no END'));
  expectNull(`${filler}\n${filler.replace(/\n/g, ' ')}`, ctx('2 MB of text, no markers'));
  expectBytes(`${filler}${VALID}${filler}`, BLOB, ctx('a good key between two 1 MB runs of junk'));
  // a good key whose body carries 1 MB of whitespace
  const spaced = `${BEGIN}\n${KEY.bytes.toString('base64')}${' \n'.repeat(MB / 2)}${END}\n`;
  expectBytes(spaced, BLOB, ctx('a good key followed by 1 MB of whitespace'));
});
