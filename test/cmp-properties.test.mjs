// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cmp } from '../lib/binaries.mjs';

const DEFAULT_SEED = 0x32c0ffee;
const SEED = Number.parseInt(process.env.CMP_SEED ?? String(DEFAULT_SEED), 10) >>> 0;
const RUNS = Number.parseInt(process.env.CMP_RUNS ?? '5000', 10);

function random(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x100000000;
  };
}

function generators(seed) {
  const next = random(seed);
  const integer = (max) => Math.floor(next() * (max + 1));
  const version = () => {
    const count = 1 + integer(5);
    const parts = Array.from({ length: count }, () => String(integer(1000000)));
    if (next() < 0.3) parts[parts.length - 1] += ['-ee', '-c6bbc1b53', '+build.7', '-rc1'][integer(3)];
    return parts.join('.');
  };
  const arbitraryString = () => {
    const count = integer(32);
    let value = '';
    for (let i = 0; i < count; i++) {
      const code = integer(0x10ffff);
      value += String.fromCodePoint(code);
    }
    if (next() < 0.2) value += String.fromCharCode(0xd800 + integer(0x7ff));
    return value;
  };
  return { next, integer, version, arbitraryString };
}

function context(seed, iteration, property) {
  return `seed=${seed} iteration=${iteration} property=${property}`;
}

test('cmp has the expected numeric and dotted-version boundaries', () => {
  assert.equal(cmp('1.2.10', '1.2.9'), 1);
  assert.equal(cmp('1.2.9', '1.2.10'), -1);
  assert.equal(cmp('1.2', '1.2.0'), 0);
  assert.equal(cmp('1.2.0.0', '1.2'), 0);
  assert.equal(cmp('1-ee', '1.0'), 0);
  assert.equal(cmp('9200-c6bbc1b53', '9199'), 1);
  assert.equal(cmp('', '0'), 0);
});

test('cmp satisfies seeded properties across generated versions', () => {
  const { version } = generators(SEED);
  for (let i = 0; i < RUNS; i++) {
    const a = version();
    const b = version();
    const c = version();
    const where = context(SEED, i, 'version properties');

    assert.equal(cmp(a, a), 0, where);
    assert.equal(cmp(a, b), -cmp(b, a), where);

    const triples = [[a, b, c], [a, c, b], [b, a, c], [b, c, a], [c, a, b], [c, b, a]];
    for (const [left, middle, right] of triples) {
      if (cmp(left, middle) <= 0 && cmp(middle, right) <= 0) {
        assert.ok(cmp(left, right) <= 0, `${where}: ${left} <= ${middle} <= ${right}`);
      }
    }
  }
});

test('cmp never throws for arbitrary strings, including empty and Unicode input', () => {
  const { arbitraryString } = generators(SEED ^ 0xa5a5a5a5);
  for (let i = 0; i < RUNS; i++) {
    const a = arbitraryString();
    const b = arbitraryString();
    const where = context(SEED, i, 'arbitrary strings');
    assert.doesNotThrow(() => cmp(a, b), where);
    assert.doesNotThrow(() => cmp(a, a), where);
  }
});

test('cmp treats any number of trailing zero components as equal', () => {
  const { version, integer } = generators(SEED ^ 0x5a5a5a5a);
  for (let i = 0; i < RUNS; i++) {
    const base = version();
    const zeros = 1 + integer(5);
    const where = context(SEED, i, 'trailing zero components');
    assert.equal(cmp(base, `${base}${'.0'.repeat(zeros)}`), 0, where);
  }
});
