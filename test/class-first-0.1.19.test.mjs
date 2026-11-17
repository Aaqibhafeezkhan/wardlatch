// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The machine-speed moves (release/0.1.19-candidate), 4: class first. The coverage report lists identity- and
// equivalence-class gaps before the others (scripts/coverage/check.mjs classFirst): the "logic issue … improved
// checks" fixes and the name and path folding are what an attacker diffing an update reads first. A mutant that drops
// the ordering must fail.
import './support/no-real-home.cjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { report, check, classFirst } from '../scripts/coverage/check.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SNAP = { read: '2026-11-17T00:00:00Z', since: '2026-05-17', sources: [], apple: [{ name: 'macOS Tahoe 26.9', date: '2026-11-10', url: 'u', entries: [
  { component: 'A', impact: 'An app may be able to access sensitive user data', description: 'x', cves: ['CVE-2026-90001'] },
  { component: 'B', impact: 'An app may be able to break out of its sandbox', description: 'x', cves: ['CVE-2026-90002'] },
  { component: 'C', impact: 'An app may be able to access protected user data', description: 'A logic issue was addressed with improved checks.', cves: ['CVE-2026-90003'] },
  { component: 'D', impact: 'A file may be written outside', description: 'This issue was addressed with improved handling of symlinks.', cves: ['CVE-2026-90004'] },
] }], kev: [], cert: [] };
const gapsIn = (rep, ck) => rep(ck({ snapshot: SNAP, named: new Map(), declined: { entries: [] }, today: '2026-11-17' })).split('\n').filter((l) => l.startsWith('GAP ')).map((l) => l.split(' ')[1]);

test('W4 class first: the coverage report lists identity-class gaps, then equivalence-class gaps, then the rest', () => {
  const order = gapsIn(report, check);
  assert.deepEqual(order, ['CVE-2026-90003', 'CVE-2026-90004', 'CVE-2026-90001', 'CVE-2026-90002']);
  const r = check({ snapshot: SNAP, named: new Map(), declined: { entries: [] }, today: '2026-11-17' });
  assert.deepEqual(classFirst(r.gaps).map((g) => g.key), order);
  // the control: in key order, the identity-class gap is not first, so the order above is the rule's doing
  assert.notDeepEqual([...r.gaps].sort((a, b) => a.key.localeCompare(b.key)).map((g) => g.key), order);
});

test('W4m mutation proof: with the report back in the check\'s own order, the identity-class gap is not first', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'wardlatch-classfirst-'));
  try {
    cpSync(join(ROOT, 'scripts'), join(dir, 'scripts'), { recursive: true });
    const p = join(dir, 'scripts', 'coverage', 'check.mjs'), src = readFileSync(p, 'utf8'), from = 'for (const g of classFirst(r.gaps)) out.push(`GAP';
    assert.ok(src.includes(from));
    writeFileSync(p, src.replace(from, 'for (const g of r.gaps) out.push(`GAP'));
    const m = await import(pathToFileURL(p).href);
    assert.notEqual(gapsIn(m.report, m.check)[0], 'CVE-2026-90003', 'mutant survived: no class-first order');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
