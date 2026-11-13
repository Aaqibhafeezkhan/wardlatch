// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18: claude-code-2026-11. GHSA-5xjx-9qx6-jcrv (CVE-2026-88968): @anthropic-ai/claude-code before 2.1.251, on
// macOS only, fixed in 2.1.251; not in CISA's catalog. The installs are read from files (lib/claudecode.mjs) and claude
// is never run. The copy that runs (the native installer's link target, an npm or cask install) below the fix is
// EXPOSED on a Mac; a copy left beside it and an editor extension's own copy are REVIEW; a link that can't be read is
// UNKNOWN; off a Mac the flaw does not apply. On the Mac this was written on: the link named 2.1.284, beside 2.1.280 and
// 2.1.126.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkClaudeCode } from '../lib/claudecode.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'claude-code-2026-11.json'), 'utf8'));
// the home-folder places only: the machine-wide npm and cask folders are read in the command, under the preload
const RULE = { ...INC.claudeCode, npmPackages: INC.claudeCode.npmPackages.filter((p) => p.startsWith('~')), casks: [] };
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-cc-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
// a stand-in for an installed version: a script that leaves a mark if anything ever runs it
const native = (home, versions, active) => {
  const vd = join(home, '.local', 'share', 'claude', 'versions'); mkdirSync(vd, { recursive: true });
  for (const v of versions) writeFileSync(join(vd, v), `#!/bin/sh\necho ran > '${join(home, 'ran')}'\n`, { mode: 0o755 });
  if (active !== undefined) { mkdirSync(join(home, '.local', 'bin'), { recursive: true }); symlinkSync(join(vd, active), join(home, '.local', 'bin', 'claude')); }
  return vd;
};
const npm = (home, v) => { const f = join(home, '.npm-global', 'lib', 'node_modules', '@anthropic-ai', 'claude-code', 'package.json'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, JSON.stringify({ name: '@anthropic-ai/claude-code', version: v })); return f; };
const run = (home, os = 'darwin', rule = RULE) => checkClaudeCode(rule, { home, os });
const st = (r) => r.rows.map((x) => [x.status, x.version]);

test('C1 the facts are the advisory\'s: 2.1.251, macOS only, not in KEV, and 2.1.260 for the second advisory', () => {
  assert.equal(INC.claudeCode.fixed, '2.1.251');
  assert.equal(INC.claudeCode.alsoBelow.version, '2.1.260');
  assert.equal(INC.advisory, 'https://github.com/anthropics/claude-code/security/advisories/GHSA-5xjx-9qx6-jcrv');
  assert.match(INC.summary, /on macOS, code running inside Claude Code's Bash sandbox/);
  assert.equal(INC.kev, undefined);
  assert.match(INC.summary, /CISA's catalog \(version 2026\.11\.10\) does not list it, so Wardlatch says "fixed in", not "exploited"/);
});

test('C2 the native installer: the link names the copy that runs; copies beside it below the fix are REVIEW', () => {
  // this Mac's shape: 2.1.284 runs, 2.1.280 and 2.1.126 sit beside it
  const h = fresh('n'); native(h, ['2.1.126', '2.1.280', '2.1.284'], '2.1.284');
  const r = run(h);
  assert.deepEqual(st(r), [['SAFE', '2.1.284'], ['REVIEW', '2.1.126']]);
  assert.match(r.rows[1].reason, /a copy left beside the one ~\/\.local\/bin\/claude runs/);
  // the link at the old one: EXPOSED, and the newer copies beside it say nothing
  const o = fresh('n'); native(o, ['2.1.126', '2.1.284'], '2.1.126');
  assert.deepEqual(st(run(o)), [['EXPOSED', '2.1.126']]);
  assert.match(run(o).rows[0].reason, /below 2\.1\.251, which fixes CVE-2026-88968 \(reported, not in CISA's catalog\); it is also below 2\.1\.260/);
  // at the boundary
  for (const [v, want] of [['2.1.250', 'EXPOSED'], ['2.1.251', 'SAFE'], ['2.1.259', 'SAFE'], ['2.2.0', 'SAFE']]) { const x = fresh('b'); native(x, [v], v); assert.equal(run(x).rows[0].status, want, v); }
  const b = fresh('b'); native(b, ['2.1.255'], '2.1.255'); assert.match(run(b).rows[0].reason, /also below 2\.1\.260/);
  // no link: every copy below the fix is REVIEW, since any may be the one that runs
  const n = fresh('n'); native(n, ['2.1.126']);
  assert.deepEqual(st(run(n)), [['REVIEW', '2.1.126']]); assert.match(run(n).rows[0].reason, /may be the one that does/);
  // a broken link, a link elsewhere, a program in its place: UNKNOWN
  const br = fresh('n'); const vd = native(br, ['2.1.284']); mkdirSync(join(br, '.local', 'bin'), { recursive: true }); symlinkSync(join(vd, '2.1.999'), join(br, '.local', 'bin', 'claude'));
  assert.deepEqual(st(run(br)), [['UNKNOWN', '2.1.999']]);
  const el = fresh('n'); native(el, []); mkdirSync(join(el, '.local', 'bin'), { recursive: true }); writeFileSync(join(el, 'claude-x'), ''); symlinkSync(join(el, 'claude-x'), join(el, '.local', 'bin', 'claude'));
  assert.deepEqual(run(el).rows.map((x) => x.status), ['UNKNOWN']);
  const pg = fresh('n'); mkdirSync(join(pg, '.local', 'bin'), { recursive: true }); writeFileSync(join(pg, '.local', 'bin', 'claude'), '#!/bin/sh\n', { mode: 0o755 });
  assert.deepEqual(run(pg).rows.map((x) => x.status), ['UNKNOWN']);
  // a versions folder that can't be opened
  const lk = fresh('n'); const lvd = native(lk, ['2.1.126']); chmodSync(lvd, 0);
  try { assert.deepEqual(run(lk).rows.map((x) => x.status), ['UNKNOWN']); } finally { chmodSync(lvd, 0o755); }
  assert.deepEqual(run(fresh('empty')).rows, []);
});

test('C3 npm installs by their package.json, and editor extensions, which are REVIEW', () => {
  const h = fresh('npm'); npm(h, '2.1.250');
  assert.deepEqual(st(run(h)), [['EXPOSED', '2.1.250']]);
  const g = fresh('npm'); const f = npm(g, '2.1.251');
  assert.deepEqual(run(g).rows.map((x) => [x.status, x.searched]), [['SAFE', [f, 'version 2.1.251']]]);
  const bad = fresh('npm'); writeFileSync(npm(bad, 'x'), '{ not json');
  assert.deepEqual(run(bad).rows.map((x) => x.status), ['UNKNOWN']);
  const e = fresh('ext'); mkdirSync(join(e, '.vscode', 'extensions', 'anthropic.claude-code-2.1.240-darwin-arm64'), { recursive: true }); mkdirSync(join(e, '.cursor', 'extensions', 'anthropic.claude-code-2.1.300-darwin-arm64'), { recursive: true });
  const r = run(e);
  assert.deepEqual(st(r), [['REVIEW', '2.1.240']]);
  assert.match(r.rows[0].reason, /the advisory names only the npm package, so this is not judged EXPOSED/);
});

test('C4 off a Mac the flaw does not apply: below the fix is SAFE, and says why', () => {
  const h = fresh('lin'); native(h, ['2.1.126', '2.1.200'], '2.1.200'); npm(h, '2.1.100');
  const r = run(h, 'linux');
  assert.deepEqual(r.rows.map((x) => x.status), ['SAFE', 'SAFE']);
  for (const x of r.rows) assert.match(x.reason, /the advisory says the flaw is in Claude Code on macOS only, and this is linux/);
  // the control: the same home on a Mac
  assert.deepEqual(run(h, 'darwin').rows.map((x) => x.status), ['EXPOSED', 'REVIEW', 'EXPOSED']);
});

test('C5 the command: EXPOSED exit 1 with the fix, a stale copy REVIEW, nothing run; none found is one receipted SAFE', () => {
  const { NODE_OPTIONS, ...rest } = process.env;
  const cli = (home, args = []) => spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'claude-code-2026-11', ...args], { encoding: 'utf8', env: { ...rest, HOME: home, PATH: fresh('p'), WARDLATCH_TEST_OWN_DIR: dir } });
  const h = fresh('cli'); native(h, ['2.1.126', '2.1.284'], '2.1.126');
  const t = cli(h);
  if (process.platform === 'darwin') {
    assert.equal(t.status, 1, t.stdout + t.stderr);
    assert.match(t.stdout, /^EXPOSED +Claude Code native install \(the copy ~\/\.local\/bin\/claude runs\) 2\.1\.126 +~\/\.local\/share\/claude\/versions\/2\.1\.126$/m);
    assert.match(t.stdout, /fix: Update Claude Code to 2\.1\.251 or later/);
    assert.doesNotMatch(t.stdout, /CISA KEV/);
  } else assert.equal(t.status, 0, t.stdout + t.stderr);
  assert.ok(!existsSync(join(h, 'ran')), 'a Claude Code copy was run');
  const s = fresh('cli'); native(s, ['2.1.126', '2.1.284'], '2.1.284');
  const j = cli(s, ['--json']);
  assert.equal(j.status, 0, j.stdout + j.stderr);
  if (process.platform === 'darwin') assert.deepEqual(JSON.parse(j.stdout).results.map((x) => [x.status, x.version, x.fix]), [['SAFE', '2.1.284', undefined], ['REVIEW', '2.1.126', INC.reviewFix]]);
  const none = cli(fresh('none'), ['--json']);
  assert.equal(none.status, 0, none.stdout + none.stderr);
  const rows = JSON.parse(none.stdout).results;
  assert.deepEqual(rows.map((x) => x.status), ['SAFE']); assert.match(rows[0].reason, /^no Claude Code install found/); assert.ok(rows[0].searched.length);
});
