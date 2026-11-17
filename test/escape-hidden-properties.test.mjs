// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHidden } from '../lib/escape.mjs';

const DEFAULT_SEED = 0x34c0ffee;
const SEED = Number.parseInt(process.env.ESCAPE_HIDDEN_SEED ?? String(DEFAULT_SEED), 10) >>> 0;
const RUNS = Number.parseInt(process.env.ESCAPE_HIDDEN_RUNS ?? '5000', 10);
const HIDDEN = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u2800\u{E0000}-\u{E007F}]/u;

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
  const codePoint = () => integer(0x10ffff);
  const arbitraryString = () => {
    const count = integer(40);
    let value = '';
    for (let i = 0; i < count; i++) value += String.fromCodePoint(codePoint());
    if (next() < 0.25) value += String.fromCharCode(0xd800 + integer(0x7ff));
    return value;
  };
  return { next, integer, codePoint, arbitraryString };
}

function decodeEscaped(value) {
  let decoded = '';
  for (let i = 0; i < value.length; i++) {
    if (value[i] !== '\\') {
      decoded += value[i];
      continue;
    }

    if (value[i + 1] === '\\') {
      decoded += '\\';
      i++;
      continue;
    }

    const byte = /^x([\da-f]{2})/i.exec(value.slice(i + 1));
    if (byte) {
      decoded += String.fromCodePoint(Number.parseInt(byte[1], 16));
      i += 3;
      continue;
    }

    const unicode = /^u\{([\da-f]+)\}/i.exec(value.slice(i + 1));
    if (unicode) {
      decoded += String.fromCodePoint(Number.parseInt(unicode[1], 16));
      i += unicode[0].length;
      continue;
    }

    decoded += '\\';
  }
  return decoded;
}

function context(seed, iteration, property) {
  return `seed=0x${seed.toString(16)} iteration=${iteration} property=${property}`;
}

test('escapeHidden leaves visible ASCII text unchanged', () => {
  const visible = Array.from({ length: 0x7f - 0x20 }, (_, i) => String.fromCharCode(0x20 + i))
    .filter((character) => character !== '\\').join('');
  assert.equal(escapeHidden(visible), visible);

  for (let code = 0x20; code <= 0x7e; code++) {
    const character = String.fromCharCode(code);
    assert.equal(escapeHidden(character), character, `ASCII U+${code.toString(16).padStart(4, '0')}`);
  }
});

test('escapeHidden removes every hidden character from generated code points', () => {
  const { codePoint } = generators(SEED);
  const boundaries = [
    0x00, 0x1f, 0x7f, 0x80, 0x9f, 0xad, 0x34f, 0x061c, 0x115f, 0x1160,
    0x17b4, 0x17b5, 0x200b, 0x2028, 0x2029, 0x202a, 0x202e, 0x2066,
    0x2800, 0xfe0f, 0xffa0, 0xe000, 0xe0001, 0xe007f, 0xe0100, 0x10ffff,
    0xd800, 0xdfff
  ];

  for (let i = 0; i < RUNS + boundaries.length; i++) {
    const point = i < boundaries.length ? boundaries[i] : codePoint();
    const input = String.fromCodePoint(point);
    const output = escapeHidden(input);
    assert.equal(HIDDEN.test(output), false, context(SEED, i, `hidden code point U+${point.toString(16)}`));
  }
});

test('escapeHidden is deterministic and reversible for seeded arbitrary strings', () => {
  const { arbitraryString } = generators(SEED ^ 0xa5a5a5a5);
  for (let i = 0; i < RUNS; i++) {
    const input = arbitraryString();
    const where = context(SEED, i, 'determinism and round trip');
    let output;
    assert.doesNotThrow(() => {
      output = escapeHidden(input);
    }, where);
    assert.equal(escapeHidden(input), output, where);
    assert.equal(HIDDEN.test(output), false, where);
    assert.equal(decodeEscaped(output), input, where);
  }
});

test('escapeHidden handles lone surrogates without throwing or losing code units', () => {
  const values = [
    String.fromCharCode(0xd800),
    String.fromCharCode(0xdc00),
    `before${String.fromCharCode(0xdfff)}after`,
    String.fromCharCode(0xd800, 0x0061, 0xdc00)
  ];

  for (const input of values) {
    const output = escapeHidden(input);
    assert.equal(HIDDEN.test(output), false, `input code units: ${[...input].map((ch) => ch.charCodeAt(0).toString(16)).join(',')}`);
    assert.equal(decodeEscaped(output), input);
  }
});

test('escapeHidden preserves literal backslashes and escape-looking text', () => {
  const values = ['\\', '\\x41', '\\u{202e}', 'path\\name', 'literal \\\\ sequence'];
  for (const input of values) assert.equal(decodeEscaped(escapeHidden(input)), input);
});
