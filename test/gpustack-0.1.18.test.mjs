// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18: gpustack-2026-11. GHSA-gj9m-f8ph-pmhr (CVE-2026-102895, in CISA's catalog since 9 Nov 2026): GPUStack before
// 2.2.0. Later advisories (CVE-2026-102894 fixed in 2.2.2; more fixed in 2.3.0 and 2.3.1, none in the catalog) make
// 2.2.0 up to 2.3.1 REVIEW. The version is read from the gpustack-<version>.dist-info folder's name in site-packages;
// Python is never started.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkSitePackages } from '../lib/installs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'gpustack-2026-11.json'), 'utf8'));
const SP = INC.sitePackages;
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-gpustack-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
const site = (names) => { const d = fresh('site'); for (const n of names) { mkdirSync(join(d, n), { recursive: true }); writeFileSync(join(d, n, 'METADATA'), 'Metadata-Version: 2.1\nName: gpustack\n'); } return d; };
const judge = (names, rule = SP) => checkSitePackages(rule, [site(names)]).map((r) => [r.status, r.version]);

test('P1 the facts are GPUStack\'s and CISA\'s: 2.2.0 for the exploited flaw, 2.3.1 for the later ones', () => {
  assert.deepEqual(INC.kev, [{ cve: 'CVE-2026-102895', vendorProject: 'GPUStack', product: 'GPUStack', dateAdded: '2026-11-09', dueDate: '2026-11-12' }]);
  const d = SP.distVersions[0];
  assert.deepEqual([d.name, d.minVersion, d.reviewBelow, d.cve], ['gpustack', '2.2.0', '2.3.1', 'CVE-2026-102895']);
  assert.equal(INC.advisory, 'https://github.com/gpustack/gpustack/security/advisories/GHSA-gj9m-f8ph-pmhr');
  // only the KEV-listed CVE is called exploited
  assert.doesNotMatch(d.reviewNote, /exploited/);
});

test('P2 every verdict around the two boundaries, from the install record\'s name in any case', () => {
  for (const [v, want] of [['2.1.1', 'EXPOSED'], ['0.7.1', 'EXPOSED'], ['2.2.0rc1', 'EXPOSED'], ['2.2.0', 'REVIEW'], ['2.2.2', 'REVIEW'], ['2.3.0', 'REVIEW'], ['2.3.1', null], ['2.4.0', null]]) {
    const got = judge([`gpustack-${v}.dist-info`]);
    assert.deepEqual(got, want ? [[want, v]] : [], v);
  }
  assert.deepEqual(judge(['GPUStack-2.1.1.dist-info']), [['EXPOSED', '2.1.1']]);
  const r = checkSitePackages(SP, [site(['gpustack-2.1.1.dist-info'])])[0];
  assert.match(r.reason, /^GPUStack 2\.1\.1 is below 2\.2\.0, which fixes CVE-2026-102895, an authentication bypass CISA lists as exploited$/);
  const v = checkSitePackages(SP, [site(['gpustack-2.2.2.dist-info'])])[0];
  assert.match(v.reason, /^GPUStack 2\.2\.2 has the fix for CVE-2026-102895, but is below 2\.3\.1/);
  // other packages, and names that only start alike, say nothing
  assert.deepEqual(judge(['gpustack_runtime-0.1.0.dist-info', 'gpustack-helper-1.0.dist-info', 'litellm-1.0.0.dist-info']), []);
  // the control: without reviewBelow, 2.2.2 reads clean
  assert.deepEqual(judge(['gpustack-2.2.2.dist-info'], { ...SP, distVersions: SP.distVersions.map(({ reviewBelow, ...d }) => d) }), []);
});

test('P3 the command: a venv with GPUStack 2.1.1 is EXPOSED, exit 1, with CISA\'s line and the fix', () => {
  const root = fresh('proj'); const venv = join(root, 'venv'); mkdirSync(venv, { recursive: true });
  writeFileSync(join(venv, 'pyvenv.cfg'), 'home = /usr/bin\n');
  const sp = join(venv, 'lib', 'python3.12', 'site-packages'); mkdirSync(join(sp, 'gpustack-2.1.1.dist-info'), { recursive: true });
  const { NODE_OPTIONS, ...rest } = process.env;
  const cli = (args) => spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'gpustack-2026-11', ...args], { encoding: 'utf8', env: { ...rest, HOME: fresh('home'), PATH: fresh('p'), WARDLATCH_TEST_OWN_DIR: dir } });
  const t = cli(['--paths', root]);
  assert.equal(t.status, 1, t.stdout + t.stderr);
  assert.match(t.stdout, /^CISA KEV: GPUStack GPUStack CVE-2026-102895 is known to be exploited · added 9 Nov 2026/m);
  assert.match(t.stdout, /^EXPOSED +gpustack-2\.1\.1\.dist-info /m);
  assert.match(t.stdout, /fix: Update GPUStack to 2\.3\.1 or later/);
  const clean = fresh('clean');
  const s = cli(['--paths', clean, '--json']);
  assert.equal(s.status, 0, s.stdout + s.stderr);
  assert.deepEqual(JSON.parse(s.stdout).results.map((r) => r.status), ['SAFE']);
});
