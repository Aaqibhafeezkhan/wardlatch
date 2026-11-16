// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Every source file carries its own licence and copyright lines (OpenSSF Gold: license_per_file, copyright_per_file).
// REUSE.toml also declares a licence for every file, so `reuse lint` passes on a source file that has lost its header;
// this test is the part that insists on the header in the file itself. CI runs it in the reuse job as well as with
// the rest of the suite. Up to 15 Nov 2026 the check lived in test/conventions.test.mjs and matched .mjs, .sh and .yml
// only, so the nine .cjs files in test/support/ were never checked (a .cjs with its header removed passed).
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { escapeRegExp } from '../lib/escape.mjs';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => {
  if (['.git', 'node_modules'].includes(e.name)) return [];
  const p = join(d, e.name);
  return e.isDirectory() ? walk(p) : [relative(ROOT, p)];
});
const FILES = walk(ROOT);
const read = (f) => readFileSync(join(ROOT, f), 'utf8');
// The one source file without an in-file header: www.deimoscore.com publishes this file's SHA-256, so a header
// comment would break the published checksum. REUSE.toml declares its licence and copyright instead.
const EXEMPT = ['fix/fix-macos.sh'];
const KINDS = ['mjs', 'cjs', 'js', 'sh', 'yml', 'yaml'];
const SOURCE = FILES.filter((f) => KINDS.some((k) => f.endsWith(`.${k}`)) && !EXEMPT.includes(f));

test('every source file opens with its licence and copyright, in the file itself', () => {
  // a pattern that quietly matched nothing would pass every file: each kind the repository holds must be found
  for (const k of ['mjs', 'cjs', 'sh', 'yml']) assert.ok(SOURCE.some((f) => f.endsWith(`.${k}`)), `no .${k} file found`);
  assert.ok(SOURCE.length >= 100, `only ${SOURCE.length} source files found`);
  for (const f of SOURCE) {
    const head = read(f).split('\n').slice(0, 4).join('\n');   // after a shebang, if any
    // REUSE-IgnoreStart (a pattern, not this file's licence)
    assert.match(head, /SPDX-License-Identifier: Apache-2\.0/, f);
    // REUSE-IgnoreEnd
    assert.match(head, /Copyright 2026 Deimos AI LLC/, f);
  }
});

test('the one exempt file is declared in REUSE.toml, and is the only one', () => {
  const toml = read('REUSE.toml');
  for (const f of EXEMPT) assert.match(toml, new RegExp(`path = "${escapeRegExp(f)}"`), f);
  assert.deepEqual(EXEMPT, ['fix/fix-macos.sh']);
});
