// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The machine-speed moves (release/0.1.19-candidate), 3: bridge advice, as text only. When a package bundles a Brotli
// without the fix and has shipped no fixed release (Pillow, opencv-python, opencv-contrib-python), the EXPOSED line's fix
// points to docs/BRIDGE-BROTLI.md: an opt-in, reversible swap with exact commands, a backup and an undo, and the
// warning that a reinstall reverts it. Wardlatch itself changes nothing (test/conventions.test.mjs "changes nothing"
// still holds over the shipped code). The rows themselves are tested in test/brotli.test.mjs.
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, cpSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'brotli-2026-10.json'), 'utf8'));
const DOC = readFileSync(join(ROOT, 'docs', 'BRIDGE-BROTLI.md'), 'utf8');
const SRC = readFileSync(join(ROOT, 'lib', 'brotli.mjs'), 'utf8');

test('B1 the three packages with no fixed release carry the bridge; it names the page, the reinstall and that Wardlatch changes nothing', () => {
  for (const k of ['pillow', 'opencv-python', 'opencv-contrib-python']) {
    const b = INC.dists[k].bridge;
    assert.match(b, /docs\/BRIDGE-BROTLI\.md/, k); assert.match(b, /opt-in, reversible/, k);
    assert.match(b, /A reinstall or upgrade of the package puts its own copy back/, k); assert.match(b, /Wardlatch changes nothing itself/, k);
  }
  // a package whose own fixed release exists gets none
  for (const k of ['brotli', 'brotlicffi']) assert.equal(INC.dists[k].bridge, undefined, k);
});

test('B2 the page: opt-in, a backup before any change, exact commands, a check, an undo, and the reinstall warning', () => {
  assert.match(DOC, /\*\*Wardlatch never does this for you\.\*\*/);
  const backup = DOC.indexOf('cp -p "$f" "$f.wardlatch-backup"'), swap = DOC.indexOf('mv "$f.new" "$f"');
  assert.ok(backup > 0 && swap > backup, 'the backup comes before the swap');
  for (const cmd of ['install_name_tool -id "@loader_path/$f" "$f.new"', 'install_name_tool -change @rpath/libbrotlicommon.1.dylib "@loader_path/$common" "$f.new"', 'codesign --force --sign - "$f.new"', 'codesign -v "$f"', 'npx wardlatch@latest --incident brotli-2026-10']) assert.ok(DOC.includes(cmd), cmd);
  assert.match(DOC, /## Undo\n\n```bash\ncd "\$DIR" \|\| exit 1\nfor b in libbrotli\*\.dylib\.wardlatch-backup; do mv "\$b" "\$\{b%\.wardlatch-backup\}"; done\n```/);
  assert.match(DOC, /## A reinstall reverts it/); assert.match(DOC, /pip install --force-reinstall/);
  assert.match(DOC, /\*\*macOS only\.\*\*/);
  // it says what its own trial did and did not prove
  assert.match(DOC, /proved the mechanics \(names, links, signatures, undo\), not a change from unfixed to fixed/);
});

test('B2m mutation proof: test/brotli.test.mjs\'s site-packages rows fail when lib/brotli.mjs no longer joins the bridge to the fix', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'wardlatch-bridge-'));
  try {
    for (const d of ['lib', 'test/support']) cpSync(join(ROOT, d), join(tmp, d), { recursive: true });
    cpSync(join(ROOT, 'test', 'brotli.test.mjs'), join(tmp, 'test', 'brotli.test.mjs'));
    cpSync(join(ROOT, 'package.json'), join(tmp, 'package.json'));
    const p = join(tmp, 'lib', 'brotli.mjs');
    assert.ok(SRC.includes(': bridged;'));
    const name = ['--test-name-pattern', 'site-packages: every copy found'];
    const runIt = () => spawnSync(process.execPath, ['--test', ...name, join(tmp, 'test', 'brotli.test.mjs')], { encoding: 'utf8', env: Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'NODE_TEST_CONTEXT' && k !== 'NODE_OPTIONS')) });   // a child of node --test reports to its parent and exits 0 unless NODE_TEST_CONTEXT is dropped
    const ok = runIt();
    assert.equal(ok.status, 0, `the copied test passes on the real lib: ${ok.stdout.slice(-600)}`);
    writeFileSync(p, SRC.replace(': bridged;', ': ownFix;'));
    assert.notEqual(runIt().status, 0, 'mutant survived: the bridge not joined to the fix');
  } finally { rmSync(tmp, { recursive: true, force: true }); }
  // and the shipped code still writes nothing: no write function in it
  assert.doesNotMatch(SRC, /\b(?:writeFileSync|renameSync|unlinkSync|copyFileSync|chmodSync|rmSync)\b/);
});
