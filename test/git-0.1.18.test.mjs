// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18: git-2026-11. Git's fixes of 10 Nov 2026 for six CVEs (CVE-2026-111760: code execution on a recursive clone)
// are in 2.56.1, backported to 2.55.1, 2.54.1, 2.53.1, 2.52.1, 2.51.3 and 2.50.2; none is in CISA's catalog. Homebrew's
// git is read from the keg its opt link names; Apple's from the "x.y.z (Apple Git-n)" string in the program's bytes; a
// distribution's from dpkg. git is never run. Apple's and the distributions' builds below a fix are REVIEW, since they
// backport. On the Mac this was written on, both Apple copies said "2.54.0 (Apple Git-157)".
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, realpathSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkVersionFiles } from '../lib/installs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'git-2026-11.json'), 'utf8'));
const V = INC.versionFiles;
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-git-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
const only = (pred) => ({ ...V, files: V.files.filter(pred) });
const BREW = only((f) => f.path === '/opt/homebrew/opt/git');
const CLT = only((f) => f.path.startsWith('/Library/Developer'));
const XCODE = only((f) => f.path.includes('Xcode'));
const DPKG = only((f) => f.path.includes('dpkg'));
const keg = (root, v) => { const k = join(root, 'opt', 'homebrew', 'Cellar', 'git', v); mkdirSync(join(k, 'bin'), { recursive: true }); mkdirSync(join(root, 'opt', 'homebrew', 'opt'), { recursive: true }); symlinkSync(k, join(root, 'opt', 'homebrew', 'opt', 'git')); return k; };
// a program file with Apple's version string inside, among other bytes, and a script that marks if it is ever run
const appleGit = (f, v, mark) => { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, Buffer.concat([Buffer.from(`#!/bin/sh\necho ran > '${mark}'\nexit 0\n`), Buffer.alloc(4096, 0), Buffer.from(`usage: git\0git version\0${v}\0`), Buffer.alloc(1024, 7)]), { mode: 0o755 }); return f; };
const clt = (root, v) => appleGit(join(root, 'Library', 'Developer', 'CommandLineTools', 'usr', 'bin', 'git'), v, join(root, 'ran'));

test('G1 the facts are git\'s and GitHub\'s: the fix and the six backports, six CVEs, none in KEV', () => {
  assert.deepEqual(V.fixedIn, ['2.56.1', '2.55.1', '2.54.1', '2.53.1', '2.52.1', '2.51.3', '2.50.2']);
  for (const c of ['CVE-2026-111760', 'CVE-2026-113408', 'CVE-2026-114466', 'CVE-2026-114467', 'CVE-2026-114469', 'CVE-2026-105437']) assert.ok(INC.summary.includes(c), c);
  assert.equal(INC.kev, undefined);
  assert.doesNotMatch(JSON.stringify(INC), /\bexploited\b|in the wild/i);
});

test('G2 Homebrew: the linked keg\'s version, each line against its own backport, an end-of-life line EXPOSED', () => {
  for (const [v, want] of [['2.54.0', 'EXPOSED'], ['2.54.0_1', 'EXPOSED'], ['2.54.1', 'SAFE'], ['2.55.0', 'EXPOSED'], ['2.56.0', 'EXPOSED'], ['2.56.1', 'SAFE'], ['2.57.0', 'SAFE'],
    ['2.51.2', 'EXPOSED'], ['2.51.3', 'SAFE'], ['2.50.2', 'SAFE'], ['2.49.1', 'EXPOSED']]) {
    const root = fresh('brew'); const k = keg(root, v);
    const rows = checkVersionFiles(BREW, { root });
    assert.equal(rows.length, 1, JSON.stringify(rows));
    assert.equal(rows[0].status, want, v);
    assert.equal(rows[0].path, k, 'the keg the link names is the row\'s place');
    if (want === 'SAFE') assert.deepEqual(rows[0].searched, [k, `version ${v.replace(/_\d+$/, '')}`]);
  }
  const e = fresh('brew'); keg(e, '2.49.1');
  assert.match(checkVersionFiles(BREW, { root: e })[0].reason, /no fix for the 2\.49 line \(end of life\)/);
  // an opt/git that leads to no versioned keg: UNKNOWN
  const odd = fresh('brew'); mkdirSync(join(odd, 'opt', 'homebrew', 'opt', 'git'), { recursive: true });
  assert.deepEqual(checkVersionFiles(BREW, { root: odd }).map((r) => r.status), ['UNKNOWN']);
  assert.deepEqual(checkVersionFiles(BREW, { root: fresh('none') }), []);
});

test('G3 Apple\'s git: read from the program\'s bytes, REVIEW below the fix (Apple backports), SAFE at or past it, never run', () => {
  const root = fresh('clt'); clt(root, '2.54.0 (Apple Git-157)');
  const r = checkVersionFiles(CLT, { root });
  assert.deepEqual(r.map((x) => [x.status, x.version]), [['REVIEW', '2.54.0']]);
  assert.match(r[0].reason, /^fixed in 2\.54\.1, by its upstream number; this is Apple's build of git/);
  assert.ok(!existsSync(join(root, 'ran')), 'git was run');
  const ok = fresh('clt'); clt(ok, '2.56.1 (Apple Git-160)');
  assert.deepEqual(checkVersionFiles(CLT, { root: ok }).map((x) => x.status), ['SAFE']);
  // a program with no Apple version string in it: UNKNOWN, never SAFE
  const none = fresh('clt'); clt(none, 'git version 2.56.1');
  assert.deepEqual(checkVersionFiles(CLT, { root: none }).map((x) => [x.status, x.reason]), [['UNKNOWN', 'found, but no version could be read from it']]);
  // Xcode's, by its own pattern
  const x = fresh('xc'); appleGit(join(x, 'Applications', 'Xcode.app', 'Contents', 'Developer', 'usr', 'bin', 'git'), '2.54.0 (Apple Git-157)', join(x, 'ran'));
  assert.deepEqual(checkVersionFiles(XCODE, { root: x }).map((y) => [y.status, y.label]), [['REVIEW', 'Apple, Xcode']]);
  // the control: without reviewBelow, Apple's 2.54.0 would be EXPOSED on its number alone
  const strip = { ...CLT, files: CLT.files.map(({ reviewBelow, ...f }) => f) };
  assert.deepEqual(checkVersionFiles(strip, { root }).map((y) => y.status), ['EXPOSED']);
});

test('G4 dpkg\'s git: the epoch is stripped, and below the fix is REVIEW (distributions backport)', () => {
  const run = (text) => { const root = fresh('dpkg'); const f = join(root, 'var', 'lib', 'dpkg', 'status'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); return checkVersionFiles(DPKG, { root }); };
  const st = (pkg, v) => `Package: ${pkg}\nStatus: install ok installed\nArchitecture: amd64\nVersion: ${v}\n\n`;
  assert.deepEqual(run(st('git-man', '1:2.39.5-0+deb12u2') + st('git', '1:2.39.5-0+deb12u2')).map((r) => [r.status, r.version]), [['REVIEW', '2.39.5']]);
  assert.match(run(st('git', '1:2.39.5-0+deb12u2'))[0].reason, /check your distribution's security tracker for CVE-2026-111760/);
  assert.deepEqual(run(st('git', '1:2.56.1-1')).map((r) => r.status), ['SAFE']);
  assert.deepEqual(run(st('gitk', '1:2.39.5-1')), []);
});

test('G5 the command: Apple\'s git REVIEW at exit 0; Homebrew below the fix EXPOSED at exit 1; none found one receipted SAFE', { skip: process.platform !== 'darwin' && 'the preload maps /Library only on a Mac test run' }, () => {
  // the machine's own /Library, /Applications and /opt are hidden by the preload, so a test's own git is mapped in
  const own = fresh('own'); const f = clt(own, '2.54.0 (Apple Git-157)');
  const pre = join(fresh('pre'), 'map.cjs');
  writeFileSync(pre, `const fs = require('node:fs'); const P = '/Library/Developer/CommandLineTools/usr/bin/git', F = ${JSON.stringify(f)};
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'openSync', 'existsSync']) { const o = fs[k]; fs[k] = (p, ...a) => o(String(p) === P ? F : p, ...a); }
require('node:module').syncBuiltinESMExports();\n`);
  const { NODE_OPTIONS, ...rest } = process.env;
  const cli = (args, extra = []) => spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), ...extra, BIN, '--incident', 'git-2026-11', ...args], { encoding: 'utf8', env: { ...rest, HOME: fresh('home'), PATH: fresh('p'), WARDLATCH_TEST_OWN_DIR: dir } });
  const t = cli([], ['--require', pre]);
  assert.equal(t.status, 0, t.stdout + t.stderr);
  assert.match(t.stdout, /^REVIEW +Git \(Apple, Command Line Tools\) 2\.54\.0 +\/Library\/Developer\/CommandLineTools\/usr\/bin\/git$/m);
  assert.match(t.stdout, /check: Until Apple \(or your distribution\) ships a git/);
  assert.ok(!existsSync(join(own, 'ran')), 'git was run');
  const none = cli(['--json']);
  assert.equal(none.status, 0, none.stdout + none.stderr);
  assert.deepEqual(JSON.parse(none.stdout).results.map((r) => r.status), ['SAFE']);
});
