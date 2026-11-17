// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 16 Nov 2026: CERT/CC VU#604762, "Unicode Normalization Collision on macOS (APFS)". A Mac's disk opens one file for
// many spellings of its name; tools that compared names as bytes let a file through under another spelling. Three
// incidents (deno-2026-06, terraform-2026-08, setuptools-2026-07), the audit of Wardlatch's own comparisons for the same
// bug (lockfile names, `*` patterns, a program on PATH asked for by name), and the lint that keeps every remaining exact
// comparison classified (test/support/equivalence-lint.mjs). docs/PATTERN-IDENTITY-EQUIVALENCE.md has the why.
// Each verdict table below is also run against planted mutants, which it must fail.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, realpathSync, symlinkSync, statSync, readdirSync, cpSync, openSync, writeSync, closeSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkVersionFiles, checkSitePackages, expand } from '../lib/installs.mjs';
import { wideFold, sameNameOnDisk, segmentTester } from '../lib/files.mjs';
import { lockfilesUnder } from '../lib/lockfiles.mjs';
import { copiesMatching } from '../lib/binaries.mjs';
import { lint, lintText, CLASSIFIED } from './support/equivalence-lint.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const inc = (id) => JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', `${id}.json`), 'utf8'));
const DENO = inc('deno-2026-06'), TF = inc('terraform-2026-08'), ST = inc('setuptools-2026-07');
// made when the file loads, not in before(): the skip conditions below measure the disk as the tests are declared, and
// Node 18 runs before() only after that (it threw ERR_INVALID_ARG_TYPE there; Node 20 and later did not)
const dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-equiv-')));
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
const id = (p) => { try { const s = statSync(p, { bigint: true }); return `${s.dev}:${s.ino}`; } catch { return null; } };
/** Whether the disk under the temp folder opens `b` as the file named `a` (it is made, then `b` is asked for). */
const diskFolds = (a, b) => { const d = fresh('probe'); writeFileSync(join(d, a), 'x'); return id(join(d, b)) === id(join(d, a)); };
let CI_DISK;   // whether this test's disk ignores case (a Mac's default); measured, never assumed
before(() => { CI_DISK = diskFolds('Probe', 'probe'); });

// ---------------------------------------------------------------- the three incidents

test('E1 the facts are the vendors\' and CERT/CC\'s, and none says "exploited" (none is in CISA\'s catalog)', () => {
  assert.deepEqual([DENO.versionFiles.minVersion, DENO.versionFiles.onlyOn], ['2.7.14', ['darwin']]);
  assert.deepEqual([TF.versionFiles.minVersion, TF.versionFiles.affectedFrom, TF.versionFiles.onlyOn], ['0.18.3', '0.4.0', ['darwin']]);
  const d = ST.sitePackages.distVersions[0];
  assert.deepEqual([d.name, d.minVersion, d.cve, d.onlyOn], ['setuptools', '83.0.0', 'CVE-2026-59890', ['darwin']]);
  for (const [i, cve, adv] of [[DENO, 'CVE-2026-49401', 'GHSA-8xpq-cjcf-3wh9'], [TF, 'CVE-2026-14978', 'node/7284170'], [ST, 'CVE-2026-59890', 'GHSA-h35f-9h28-mq5c']]) {
    assert.ok(i.title.includes(cve) && i.summary.includes(cve), i.id);
    assert.ok(i.advisory.includes(adv), i.id);
    assert.ok(i.sources.includes('https://kb.cert.org/vuls/id/604762'), `${i.id}: names the CERT/CC note`);
    assert.match(i.summary, /CISA's catalog \(2026\.11\.13\) does not list it/, i.id);
    assert.doesNotMatch(JSON.stringify(i), /exploited/i, `${i.id}: the house rule: "exploited" only for a KEV row`);
  }
  // Terraform's fixed releases, from its own go.mod (HashiCorp names none): the advice says them
  assert.match(TF.versionFiles.fix, /1\.15\.9, 1\.16\.0 or later/);
});

const DENO_BIN = DENO.versionFiles.files.find((f) => f.label === 'deno.land installer');
const DENO_KEG = DENO.versionFiles.files.find((f) => f.path === '/opt/homebrew/opt/deno');
const DENO_MISE = DENO.versionFiles.files.find((f) => f.label === 'mise');
const TF_BIN = TF.versionFiles.files[0];
const rule = (base, f, path) => ({ ...base, files: [{ ...f, path }] });
const bytes = (content, pad = 0) => { const p = join(fresh('bin'), 'prog'); writeFileSync(p, Buffer.concat([Buffer.alloc(pad, 0xcf), Buffer.from(content, 'latin1'), Buffer.alloc(64, 0)])); return p; };
const verdict = (base, f, path, os) => checkVersionFiles(rule(base, f, path), { os }).map((r) => [r.status, r.version]);
// a keg holds its program (A3t: the keg is judged by the program's bytes, which must agree with its folder's name)
const keg = (version, inside = version.replace(/_\d+$/, '')) => {
  const d = fresh('brew'); const cellar = join(d, 'Cellar', 'deno', version); mkdirSync(join(cellar, 'bin'), { recursive: true });
  writeFileSync(join(cellar, 'bin', 'deno'), Buffer.concat([Buffer.alloc(256, 0xcf), Buffer.from(`Deno/${inside}+a1b2c3d`, 'latin1'), Buffer.alloc(64)]));
  mkdirSync(join(d, 'opt')); symlinkSync(cellar, join(d, 'opt', 'deno')); return join(d, 'opt', 'deno');
};

/** The Deno table: every verdict this incident gives, on a Mac and on Linux. `v` is the incident's versionFiles. */
const denoTable = (v = DENO.versionFiles, F = { keg: DENO_KEG, mise: DENO_MISE, bin: DENO_BIN }) => {
  const rows = [];
  const want = (got, exp, what) => rows.push([what, JSON.stringify(got) === JSON.stringify(exp)]);
  want(verdict(v, F.keg, keg('2.7.13'), 'darwin'), [['EXPOSED', '2.7.13']], 'keg 2.7.13 on a Mac');
  want(verdict(v, F.keg, keg('2.7.14'), 'darwin'), [['SAFE', '2.7.14']], 'keg 2.7.14');
  want(verdict(v, F.keg, keg('2.7.14_1'), 'darwin'), [['SAFE', '2.7.14']], 'a revised keg');
  want(verdict(v, F.keg, keg('2.7.13'), 'linux'), [['SAFE', '2.7.13']], 'keg 2.7.13 on Linux: not affected');
  want(verdict(v, F.keg, keg('2.7.14', '2.7.13'), 'darwin'), [['UNKNOWN', '']], 'keg: a folder named 2.7.14 holding 2.7.13 (A3t)');
  // mise and asdf (release/0.1.19-candidate, the never-false-safe suite's H9b): the program inside the install folder is
  // read, never the folder's name. A folder named 2.7.14 holding a 2.7.13 deno is EXPOSED; one whose program can't be
  // read, or carries no version, is UNKNOWN
  const miseAt = (folder, content) => { const m = fresh('mise'); const d = join(m, 'installs', 'deno', folder, 'bin'); mkdirSync(d, { recursive: true }); if (content !== null) writeFileSync(join(d, 'deno'), Buffer.concat([Buffer.alloc(256, 0xcf), Buffer.from(content, 'latin1'), Buffer.alloc(64)])); return join(m, 'installs', 'deno', '*', 'bin', 'deno'); };
  want(verdict(v, F.mise, miseAt('1.46.3', 'Deno/1.46.3+a1b2c3d\0'), 'darwin'), [['EXPOSED', '1.46.3']], 'mise 1.46.3');
  want(verdict(v, F.mise, miseAt('2.7.14', 'Deno/2.7.13+a1b2c3d\0'), 'darwin'), [['EXPOSED', '2.7.13']], 'mise: a folder named 2.7.14 holding 2.7.13');
  want(verdict(v, F.mise, miseAt('2.7.13', 'Deno/2.7.14+a1b2c3d\0'), 'darwin'), [['SAFE', '2.7.14']], 'mise: judged by the bytes the other way too');
  want(verdict(v, F.mise, miseAt('2.7.14', 'deno 2.7.14 (stable)'), 'darwin'), [['UNKNOWN', '']], 'mise: a program without the constant is UNKNOWN');
  {
    const p = miseAt('2.7.14', 'Deno/2.7.14+a1b2c3d\0'), real = p.replace('*', '2.7.14');
    chmodSync(real, 0o000);
    const root = process.getuid?.() === 0;
    want(verdict(v, F.mise, p, 'darwin'), root ? [['SAFE', '2.7.14']] : [['UNKNOWN', '']], 'mise: a program that can\'t be read is UNKNOWN');
    chmodSync(real, 0o644);
  }
  // the constant Deno compiles in: Deno/<version>+<commit>. A bare Deno/<version> beside another constant that starts
  // with digits (TYPESCRIPT "5.9.2", laid out next to it) would read 2.7.145: the +<commit> anchor is what prevents it
  want(verdict(v, F.bin, bytes('xxDeno/2.7.145.9.2\0Deno/2.7.13+a1b2c3d\0'), 'darwin'), [['EXPOSED', '2.7.13']], 'the anchored constant, not the bare one');
  want(verdict(v, F.bin, bytes('Deno/2.7.14+0123456789abcdef'), 'darwin'), [['SAFE', '2.7.14']], 'binary 2.7.14');
  want(verdict(v, F.bin, bytes('deno 2.7.13 (stable)'), 'darwin'), [['UNKNOWN', '']], 'a build without the constant is UNKNOWN, never SAFE');
  // past the first 4 MB piece, across its edge: eachPiece's overlap sees it
  want(verdict(v, F.bin, bytes('Deno/2.7.10+abcdef0', 4 * 1024 * 1024 - 7), 'darwin'), [['EXPOSED', '2.7.10']], 'across a piece edge');
  want(verdict(v, F.bin, bytes('Deno/2.7.13+abcdef0'), 'linux'), [['SAFE', '2.7.13']], 'binary on Linux');
  return rows;
};
const allTrue = (rows) => rows.every(([, ok]) => ok);

test('E2 Deno: below 2.7.14 on a Mac is EXPOSED, from a keg, a mise install or the program\'s own bytes; Linux SAFE with the advisory\'s reason; an unread build UNKNOWN', () => {
  const rows = denoTable();
  for (const [what, ok] of rows) assert.ok(ok, what);
  const [linux] = checkVersionFiles(rule(DENO.versionFiles, DENO_KEG, keg('2.7.13')), { os: 'linux' });
  assert.match(linux.reason, /fixed in 2\.7\.14, but Deno's advisory says this flaw is on macOS only/);
  assert.ok(linux.searched.includes('this system (linux)'), 'the receipt names the system it judged on');
});

test('E2m Deno mutation proof: each planted mistake fails the table', () => {
  const v = DENO.versionFiles;
  const mutants = {
    'fix one release early (2.7.13)': [{ ...v, minVersion: '2.7.13' }],
    'onlyOn dropped (Linux EXPOSED)': [{ ...v, onlyOn: undefined }],
    'onlyOn inverted (a Mac SAFE)': [{ ...v, onlyOn: ['linux'] }],
    'the +commit anchor dropped': [v, { keg: DENO_KEG, mise: DENO_MISE, bin: { ...DENO_BIN, re: 'Deno/(\\d+\\.\\d+\\.\\d+)' } }],
    'scan off (the program read whole, over its cap)': [v, { keg: DENO_KEG, mise: DENO_MISE, bin: { ...DENO_BIN, scan: false, maxBytes: 1024 } }],
    'the keg revision suffix not stripped': [v, { keg: { ...DENO_KEG, versionFromRealPath: '/Cellar/deno/([^/]+)$' }, mise: DENO_MISE, bin: DENO_BIN }],
    // H9b: mise's Deno judged by the folder it sits in, as before release/0.1.19-candidate
    'mise judged by its folder name (H9b)': [v, { keg: DENO_KEG, mise: { label: 'mise', versionFromRealPath: '/installs/deno/(\\d+\\.\\d+\\.\\d+)/bin/deno$' }, bin: DENO_BIN }],
    // A3t: Homebrew's keg judged by its folder's name alone, as before release/0.1.19-candidate
    'the keg judged by its folder name (A3t)': [v, { keg: { ...DENO_KEG, programRe: undefined }, mise: DENO_MISE, bin: DENO_BIN }],
    'mise read whole, not scanned (the cap)': [v, { keg: DENO_KEG, mise: { ...DENO_MISE, scan: false, maxBytes: 64 }, bin: DENO_BIN }],
  };
  assert.ok(allTrue(denoTable()), 'the true rules pass');
  for (const [name, args] of Object.entries(mutants)) assert.equal(allTrue(denoTable(...args)), false, `mutant survived: ${name}`);
});

// Go's module list, as Go writes it into a program and `go version -m` prints it
const modinfo = (slug, sum = '\th1:QmFzZTY0c3VtPQ==') => `\x30\x77\xaf\x0c\x92\x74\x08\x02path\tgithub.com/hashicorp/terraform\nmod\tgithub.com/hashicorp/terraform\t(devel)\t\ndep\tgithub.com/hashicorp/go-retryablehttp\tv0.7.8\th1:x=\n${slug}${sum}\ndep\tgithub.com/zclconf/go-cty\tv1.16.4\th1:y=\n`;
const tfTable = (v = TF.versionFiles, f = TF_BIN) => {
  const rows = [];
  const want = (got, exp, what) => rows.push([what, JSON.stringify(got) === JSON.stringify(exp)]);
  want(verdict(v, f, bytes(modinfo('dep\tgithub.com/hashicorp/go-slug\tv0.18.1')), 'darwin'), [['EXPOSED', '0.18.1']], '1.15.8 builds v0.18.1');
  want(verdict(v, f, bytes(modinfo('dep\tgithub.com/hashicorp/go-slug\tv0.18.2')), 'darwin'), [['EXPOSED', '0.18.2']], 'v0.18.2, the last affected');
  want(verdict(v, f, bytes(modinfo('dep\tgithub.com/hashicorp/go-slug\tv0.18.3')), 'darwin'), [['SAFE', '0.18.3']], 'v0.18.3');
  want(verdict(v, f, bytes(modinfo('dep\tgithub.com/hashicorp/go-slug\tv0.18.2', '')), 'darwin'), [['EXPOSED', '0.18.2']], 'a dep line with no sum');
  want(verdict(v, f, bytes(modinfo('dep\tgithub.com/hashicorp/go-slug\tv0.3.0')), 'darwin'), [['SAFE', '0.3.0']], 'older than the CVE\'s range');
  want(verdict(v, f, bytes(modinfo('dep\tgithub.com/hashicorp/go-slugger\tv0.1.0')), 'darwin'), [['UNKNOWN', '']], 'another module that starts alike');
  want(verdict(v, f, bytes('Terraform v1.15.8'), 'darwin'), [['UNKNOWN', '']], 'no module list: UNKNOWN');
  want(verdict(v, f, bytes(modinfo('dep\tgithub.com/hashicorp/go-slug\tv0.18.2')), 'linux'), [['SAFE', '0.18.2']], 'Linux: not affected');
  return rows;
};

test('E3 Terraform: judged by the go-slug it was built with, read from the module list in its own bytes; never run', () => {
  for (const [what, ok] of tfTable()) assert.ok(ok, what);
  // every place the incident reads uses the same pattern, scanned, with a cap a real Terraform fits under
  for (const f of TF.versionFiles.files) { assert.equal(f.re, TF_BIN.re, f.path); assert.ok(f.scan && f.maxBytes >= 256 * 1024 * 1024, f.path); }
});

test('E3m Terraform mutation proof', () => {
  const v = TF.versionFiles;
  const mutants = {
    'fixed at 0.18.2': [{ ...v, minVersion: '0.18.2' }],
    'affectedFrom raised to 0.18.2 (0.18.1 SAFE)': [{ ...v, affectedFrom: '0.18.2' }],
    'the module path not ended (go-slugger read)': [v, { ...TF_BIN, re: '\\bdep\\tgithub\\.com/hashicorp/go-slug\\S*\\tv(\\d+\\.\\d+\\.\\d+)' }],
    'a sum required after the version': [v, { ...TF_BIN, re: '\\bdep\\tgithub\\.com/hashicorp/go-slug\\tv(\\d+\\.\\d+\\.\\d+)\\th1:' }],
    'onlyOn dropped': [{ ...v, onlyOn: undefined }],
  };
  assert.ok(allTrue(tfTable()), 'the true rules pass');
  for (const [name, args] of Object.entries(mutants)) assert.equal(allTrue(tfTable(...args)), false, `mutant survived: ${name}`);
});

const site = (names) => { const d = fresh('site'); for (const n of names) { mkdirSync(join(d, n), { recursive: true }); writeFileSync(join(d, n, 'METADATA'), 'Name: setuptools\n'); } return d; };
const stTable = (sp = ST.sitePackages) => {
  const rows = [];
  const want = (names, os, exp) => rows.push([`${names} ${os}`, JSON.stringify(checkSitePackages(sp, [site(names)], [], { os }).map((r) => [r.status, r.version])) === JSON.stringify(exp)]);
  want(['setuptools-82.0.1.dist-info'], 'darwin', [['EXPOSED', '82.0.1']]);
  want(['setuptools-58.0.4.dist-info'], 'darwin', [['EXPOSED', '58.0.4']]);
  want(['setuptools-83.0.0rc1.dist-info'], 'darwin', [['EXPOSED', '83.0.0rc1']]);
  want(['setuptools-83.0.0.dist-info'], 'darwin', []);
  want(['setuptools-84.1.0.dist-info'], 'darwin', []);
  want(['Setuptools-82.0.1.dist-info'], 'darwin', [['EXPOSED', '82.0.1']]);
  want(['setuptools_scm-8.0.0.dist-info', 'setuptools-rust-1.0.0.dist-info'], 'darwin', []);
  want(['setuptools-82.0.1.dist-info'], 'linux', []);
  return rows;
};

test('E4 setuptools: below 83.0.0 on a Mac is EXPOSED, from the install record\'s name; Linux adds no row; look-alike packages say nothing', () => {
  for (const [what, ok] of stTable()) assert.ok(ok, what);
  const [r] = checkSitePackages(ST.sitePackages, [site(['setuptools-82.0.1.dist-info'])], [], { os: 'darwin' });
  assert.match(r.reason, /^setuptools 82\.0\.1 is below 83\.0\.0, which fixes CVE-2026-59890 \(on a Mac/);
  assert.match(ST.safeText, /on Linux and Windows this flaw does not apply/);
});

test('E4m setuptools mutation proof', () => {
  const d = ST.sitePackages.distVersions[0];
  const with_ = (x) => ({ ...ST.sitePackages, distVersions: [{ ...d, ...x }] });
  const mutants = { 'fixed at 82.0.1': with_({ minVersion: '82.0.1' }), 'onlyOn dropped': with_({ onlyOn: undefined }), 'onlyOn inverted': with_({ onlyOn: ['linux'] }) };
  assert.ok(allTrue(stTable()), 'the true rule passes');
  for (const [name, sp] of Object.entries(mutants)) assert.equal(allTrue(stTable(sp)), false, `mutant survived: ${name}`);
});

// ---------------------------------------------------------------- the audit of Wardlatch's own comparisons

// MEASURED on this Mac, 16 Nov 2026 (docs/PATTERN-IDENTITY-EQUIVALENCE.md): what case-insensitive APFS opens as one file
const APFS_SAME = [['secret', 'SECRET'], ['straße', 'strasse'], ['masse', 'maße'], ['groß', 'groẞ'], ['café', 'café'], ['ﬁle', 'file'], ['oﬀ', 'off'], ['Key', 'key'], ['ſsh', 'ssh'], ['σοφος', 'ΣΟΦΟΣ']];
const APFS_APART = [['confıg', 'config'], ['İd', 'id'], ['Ａbc', 'Abc'], ['trail', 'trail.'], ['space', 'space '], ['x2', 'x²']];

test('A1 wideFold is never narrower than a Mac\'s disk: every pair the disk opens as one file folds together (the sieve may be wider; the disk decides)', () => {
  for (const [a, b] of APFS_SAME) assert.equal(wideFold(a), wideFold(b), `${a} / ${b}`);
  // wider on purpose, and harmless: the disk is then asked (fullwidth and superscripts fold by NFKD; the disk says no)
  assert.equal(wideFold('Ａbc'), wideFold('Abc'));
  // never wider than this: a trailing dot or space is a different name on every disk measured
  assert.notEqual(wideFold('trail'), wideFold('trail.'));
  assert.notEqual(wideFold('space'), wideFold('space '));
});

test('A1d on this disk: the table above is what it does (a Mac\'s default APFS), measured, not assumed', { skip: !diskFolds('Probe', 'probe') && 'this disk keeps case (Linux, or a case-sensitive APFS volume)' }, () => {
  for (const [a, b] of APFS_SAME) assert.ok(diskFolds(a, b), `the disk opens ${a} as ${b}`);
  for (const [a, b] of APFS_APART) assert.ok(!diskFolds(a, b), `the disk does not open ${a} as ${b}`);
});

test('A2 sameNameOnDisk says what the disk says: one file on a disk that folds, two names on one that keeps case', () => {
  for (const [a, b] of [...APFS_SAME, ['Package-Lock.json', 'package-lock.json']]) {
    const d = fresh('same'); writeFileSync(join(d, a), 'x');
    assert.equal(sameNameOnDisk(d, a, b), id(join(d, b)) === id(join(d, a)), `${a} / ${b}`);
  }
  // names that fold apart are never compared on disk, even through a planted link: the sieve decides first
  const d = fresh('link'); writeFileSync(join(d, 'anything'), 'x'); symlinkSync(join(d, 'anything'), join(d, 'package-lock.json'));
  assert.equal(sameNameOnDisk(d, 'anything', 'package-lock.json'), false);
  assert.equal(sameNameOnDisk(d, 'gone', 'gone2'), false);
});

const lockTable = (under = lockfilesUnder) => {
  const d = fresh('proj'); writeFileSync(join(d, 'Package-Lock.json'), '{}');
  const e = fresh('proj2'); writeFileSync(join(e, 'yarn.lock'), '');
  const nfd = fresh('proj3'); const sub = join(nfd, 'café'); mkdirSync(sub); writeFileSync(join(sub, 'pnpm-lock.yaml'), '');
  const got = (r) => under([r], 10, [], [], { deep: [] }).map((x) => [x.path.slice(r.length + 1), x.kind]);
  return [
    JSON.stringify(got(d)) === JSON.stringify(CI_DISK ? [['Package-Lock.json', 'npm']] : []),
    JSON.stringify(got(e)) === JSON.stringify([['yarn.lock', 'yarn']]),
    JSON.stringify(got(nfd)) === JSON.stringify([['café/pnpm-lock.yaml', 'pnpm']]),
  ];
};

test('A3 lockfiles: a lockfile npm opens under another spelling is found on a disk that folds, and not on one that keeps case', () => {
  assert.deepEqual(lockTable(), [true, true, true]);
});

test('A4 a `*` pattern on a Mac matches a folder in another case or Unicode form; on Linux it is exact', () => {
  const mac = segmentTester('Xcode*.app', 'darwin'), linux = segmentTester('Xcode*.app', 'linux');
  for (const n of ['Xcode.app', 'Xcode-beta.app', 'xcode.app', 'XCODE-16.APP', 'Xcode–béta.app', 'Xcode–béta.app']) assert.ok(mac(n), n);
  for (const n of ['Xcode.ap', 'MyXcode.app', 'Xcode.app.bak']) assert.ok(!mac(n), n);
  assert.ok(linux('Xcode-beta.app') && !linux('xcode.app') && !linux('XCODE.APP'));
  if (process.platform === 'darwin') {
    const d = fresh('apps'); mkdirSync(join(d, 'xcode.app', 'Contents'), { recursive: true });
    assert.deepEqual(expand(join(d, 'Xcode*.app', 'Contents')), [join(d, 'xcode.app', 'Contents')]);
  }
});

test('A5 a program on PATH asked for by its exact name is the file the shell runs, in whatever case the disk lists it', { skip: process.platform === 'win32' }, () => {
  const d = fresh('path'); writeFileSync(join(d, 'PHP'), '#!/bin/sh\n', { mode: 0o755 });
  const r = copiesMatching('^php(?:\\d+(?:\\.\\d+)?)?$', d, [], [], 'php', []);
  assert.deepEqual(r.run.concat(r.notRun), CI_DISK ? [`${d}/php`] : []);
});

// The planted mutations of the audit's fixes: each is applied to a copy of lib/ and must turn its table red.
const mutatedLib = async (file, from, to) => {
  const copy = fresh('mut'); cpSync(join(ROOT, 'lib'), join(copy, 'lib'), { recursive: true });
  const p = join(copy, 'lib', file), src = readFileSync(p, 'utf8');
  assert.ok(src.includes(from), `the mutation's text is in ${file}: ${from}`);
  writeFileSync(p, src.replace(from, to));
  return (m) => import(pathToFileURL(join(copy, 'lib', m)).href);
};
test('A6 mutation proof of the audit fixes: each planted regression is caught', { skip: !diskFolds('Probe', 'probe') && 'the fixes act only on a disk that folds; this one keeps case' }, async () => {
  assert.deepEqual(lockTable(), [true, true, true], 'the true code passes');
  // 1. lockfile names compared exactly again (the code before this fix)
  let load = await mutatedLib('lockfiles.mjs', 'Object.keys(LOCK_NAMES).find((k) => sameNameOnDisk(dir, name, k))', 'undefined');
  assert.notDeepEqual(lockTable((await load('lockfiles.mjs')).lockfilesUnder), [true, true, true], 'mutant survived: exact lockfile names');
  // 2. the disk not asked: the sieve alone decides (a case-sensitive disk would then be read as folding)
  load = await mutatedLib('files.mjs', 'return mine !== null && mine === id(join(dir, wanted));', 'return true;');
  const f2 = await load('files.mjs');
  const kd = fresh('keep'); writeFileSync(join(kd, 'a'), 'x');
  assert.equal(f2.sameNameOnDisk(kd, 'A-gone', 'a-gone'), true, 'the mutant says yes without the disk');
  assert.equal(sameNameOnDisk(kd, 'A-gone', 'a-gone'), false, 'the true code asks the disk, which has neither');
  // 3. the `*` segments exact on a Mac again
  load = await mutatedLib('files.mjs', "if (os !== 'darwin') return (name) => exact.test(name);", 'return (name) => exact.test(name);');
  assert.equal((await load('files.mjs')).segmentTester('Xcode*.app', 'darwin')('xcode.app'), false, 'mutant survived: exact * segments');
  // 4. the PATH program not asked for by its exact name
  load = await mutatedLib('binaries.mjs', "if (l.entries && exact && !found.includes(exact) && pathState(`${d}/${exact}`) === 'file') found.unshift(exact);", '');
  const pd = fresh('path'); writeFileSync(join(pd, 'PHP'), '#!/bin/sh\n', { mode: 0o755 });
  const r = (await load('binaries.mjs')).copiesMatching('^php$', pd, [], [], 'php', []);
  assert.deepEqual(r.run.concat(r.notRun), [], 'mutant survived: PATH program by pattern only');
  // 5. ß left as ß after case folding (ẞ upper-cases to itself and lowers to ß, which the disk opens as ss)
  load = await mutatedLib('files.mjs', ".replace(/\\u00DF/g, 'ss')", '');
  assert.notEqual((await load('files.mjs')).wideFold('groẞ'), wideFold('gross'), 'mutant survived: ẞ not taken to ss');
});

// ---------------------------------------------------------------- the lint

const shipped = () => ['lib', 'bin'].flatMap((d) => readdirSync(join(ROOT, d)).filter((n) => n.endsWith('.mjs')).map((n) => [`${d}/${n}`, readFileSync(join(ROOT, d, n), 'utf8')]));

test('L1 every exact name or path-prefix comparison in the shipped code is classified (fixed to ask the disk, or harmless with its reason), and no classification is stale', () => {
  const r = lint(shipped());
  assert.ok(r.found.length >= 40, `the lint found ${r.found.length}: it can see the code`);
  assert.deepEqual(r.unclassified.map((x) => `${x.file}:${x.line} [${x.shape}] ${x.text}`), [], 'classify each new comparison in test/support/equivalence-lint.mjs (docs/PATTERN-IDENTITY-EQUIVALENCE.md says how)');
  assert.deepEqual(r.stale.map((x) => `${x[0]}: ${x[1]}`), [], 'a classified comparison is no longer in the code: remove its entry');
  for (const [f, piece, verdict, why] of CLASSIFIED) assert.ok(f && piece && ['fixed', 'harmless'].includes(verdict) && why.length >= 20, `${f}: ${piece}`);
});

test('L1m the lint can fail: each comparison this audit fixed, put back, is flagged; a comment is not', () => {
  for (const planted of [
    "      if (Object.hasOwn(LOCK_NAMES, e.name) && !e.isDirectory()) out.push(p);",
    "      for (const e of l.entries ?? []) if (e.name === 'package-lock.json') out.push(p);",
    "      if (names.has('cook.pth')) out.push(x);",
    "      if (basename(p) === 'node_modules') continue;",
    "      if (real.startsWith(`${home}/`)) read(real);",
    "      const keep = l.entries.filter((e) => e.name.endsWith('.lock'));",
  ]) assert.equal(lintText('lib/x.mjs', planted).length, 1, planted);
  assert.equal(lintText('lib/x.mjs', "  // e.name === 'x' in a comment").length, 0);
  // a planted comparison in a real file is unclassified
  const files = shipped().map(([f, t]) => (f === 'lib/lockfiles.mjs' ? [f, `${t}\nconst planted = (e) => e.name === 'yarn.lock';\n`] : [f, t]));
  assert.equal(lint(files).unclassified.length, 1);
});
