// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// NEVER A FALSE SAFE, the attacker's pass (attack/rc0119-2026-11-16): fixtures built to make release/0.1.19-candidate say
// SAFE while what is there is exposed, or not known. Each test below made the candidate say SAFE before its fix (or does
// still, as a todo with the reason), and each fix has a planted mutation, in the same test or in Am, that turns it red.
//   A1 a program that names two versions (a fixed one's text ahead of its own): the first one answered
//   A2 Terraform built with go-slug replaced (a => line under the dep line): the dep line's version answered
//   A3 Homebrew's bin/deno leading to an old keg while opt/deno leads to the new one: only opt was read
//   A3t (todo) Homebrew's keg folder named for the fix, over a program that isn't: the folder's name answers
//   A4 a PATH entry written ~/bin, which bash and /bin/sh search: dropped as relative, and its php never checked
//   A5 SSL_CERT_FILE set in a shell start-up file, absent from the run's environment: cert.pem read in the control's place
//   A6 a PYTHONPATH folder holding a stealer's install record or an old setuptools: never searched
//   A7 lockfile aliases: classic yarn's npm: alias with no registry path, and a listed name installed from another package
//   A7t (todo) the same alias in pnpm-lock.yaml (importers section, which the reader does not read)
//   A8 a pnpm-lock.yaml re-indented, or with packages written inline: read as pinning nothing
//   A9 H11c's control made of this machine's own update files: "today" came from them, not from the test's clock
// The command runs on a stand-in home (HOME and PATH in this test's folder; the real home is never read: no-real-home.cjs).
import '../support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, symlinkSync, chmodSync, readFileSync, cpSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { scratch, cli, incident, mutatedLib, realLib, todo, MAC, HERE, ROOT } from './support.mjs';

const T = scratch('attack');
after(() => T.done());
const { checkVersionFiles, sitePackagesDirs, checkSitePackages, pythonPathDirs } = await realLib('installs.mjs');
const { checkLockfile } = await realLib('lockfiles.mjs');
const { appleFileCheck } = await realLib('macos.mjs');
const DENO = incident('deno-2026-06'), TF = incident('terraform-2026-08'), GIT = incident('git-2026-11');
const RSC = incident('react-rsc-2026-11').lockfiles;
const statusOf = (rows) => rows.map((r) => [r.status, r.version]);
const prog = (...parts) => Buffer.concat([Buffer.alloc(512, 0xcf), ...parts.map((p) => Buffer.concat([Buffer.from(p), Buffer.alloc(300, 0)]))]);
/** A program at `root` + the entry's path (its one `*` filled in), with these bytes. */
const plant = (root, f, bytes, star = '2.7.14') => { const p = T.put(`${root}${f.path.replace('*', star)}`, bytes); chmodSync(p, 0o755); return p; };
const mise = DENO.versionFiles.files.find((x) => x.label === 'mise');
const appleGit = GIT.versionFiles.files.find((x) => x.label === 'Apple, Command Line Tools');
const tfBin = TF.versionFiles.files.find((x) => x.label === 'Homebrew');
const modinfo = (lines) => `\x30\x77\xaf\x0c\x92\x74\x08\x02path\tgithub.com/hashicorp/terraform\nmod\tgithub.com/hashicorp/terraform\t(devel)\t\n${lines}dep\tgithub.com/zclconf/go-cty\tv1.16.4\th1:y=\n`;

// ---------------------------------------------------------------- A1 two versions in one program

test('A1 a program that names two versions that would be judged differently is UNKNOWN, never the first one\'s SAFE', () => {
  // Deno (scanned in pieces): a fixed release's user agent in some table ahead of the program's own
  const root = T.fresh('a1');
  plant(root, mise, prog('Deno/2.7.14+aaaaaaa', 'Deno/2.7.13+bbbbbbb'));
  assert.deepEqual(statusOf(checkVersionFiles({ ...DENO.versionFiles, files: [mise] }, { root, os: 'darwin' })), [['UNKNOWN', '']]);
  // the other way round is not a SAFE either, and two copies of one version still answer as one (genuinely)
  const two = T.fresh('a1b'); plant(two, mise, prog('Deno/2.7.13+bbbbbbb', 'Deno/2.7.14+aaaaaaa'));
  assert.notEqual(checkVersionFiles({ ...DENO.versionFiles, files: [mise] }, { root: two, os: 'darwin' })[0].status, 'SAFE');
  const same = T.fresh('a1c'); plant(same, mise, prog('Deno/2.7.14+aaaaaaa', 'Deno/2.7.14+aaaaaaa'));
  assert.deepEqual(statusOf(checkVersionFiles({ ...DENO.versionFiles, files: [mise] }, { root: same, os: 'darwin' })), [['SAFE', '2.7.14']]);
  // the pieces' seam: the second version 5 MB in, past the first 4 MB piece
  const far = T.fresh('a1d'); plant(far, mise, Buffer.concat([prog('Deno/2.7.14+aaaaaaa'), Buffer.alloc(5 * 1024 * 1024, 0x41), prog('Deno/2.7.13+bbbbbbb')]));
  assert.deepEqual(statusOf(checkVersionFiles({ ...DENO.versionFiles, files: [mise] }, { root: far, os: 'darwin' })), [['UNKNOWN', '']]);
  // a program read whole (Apple's git): a fixed number in a string table ahead of the build's own banner
  const g = T.fresh('a1g');
  T.put(`${g}${appleGit.path}`, prog('git version 2.56.1 (Apple Git-200)', 'git version 2.39.5 (Apple Git-154)'));
  assert.notEqual(checkVersionFiles({ ...GIT.versionFiles, files: [appleGit] }, { root: g, os: 'darwin' })[0].status, 'SAFE');
});

// ---------------------------------------------------------------- A2 a replaced go-slug

test('A2 Terraform built with go-slug replaced by another copy (a => line under the dep line) is UNKNOWN, not the dep line\'s SAFE', () => {
  const root = T.fresh('a2');
  plant(root, tfBin, prog(modinfo('dep\tgithub.com/hashicorp/go-slug\tv0.18.3\n=>\tgithub.com/acme/go-slug\tv0.18.1\th1:z=\n')));
  assert.deepEqual(statusOf(checkVersionFiles({ ...TF.versionFiles, files: [tfBin] }, { root, os: 'darwin' })), [['UNKNOWN', '']]);
  // the mutation: the rule as the candidate wrote it, (?=[\t\n]), reads the dep line and says SAFE
  const old = { ...tfBin, re: tfBin.re.replace('(?=\\t|\\n(?!=>))', '(?=[\\t\\n])') };
  assert.notEqual(old.re, tfBin.re);
  assert.deepEqual(statusOf(checkVersionFiles({ ...TF.versionFiles, files: [old] }, { root, os: 'darwin' })), [['SAFE', '0.18.3']]);
  // and an ordinary module list, with or without a sum, is still read (genuinely)
  const plain = T.fresh('a2b'); plant(plain, tfBin, prog(modinfo('dep\tgithub.com/hashicorp/go-slug\tv0.18.3\th1:s=\n')));
  assert.deepEqual(statusOf(checkVersionFiles({ ...TF.versionFiles, files: [tfBin] }, { root: plain, os: 'darwin' })), [['SAFE', '0.18.3']]);
});

// ---------------------------------------------------------------- A3 Homebrew's bin link and its keg

/** A Homebrew prefix at `root`/opt/homebrew with deno kegs `kegs`, opt/deno leading to `opt` and bin/deno to `bin`'s. */
function brew(root, kegs, opt, bin, bytes = (v) => prog(`Deno/${v}+abcdef0`)) {
  const pre = join(root, 'opt', 'homebrew');
  for (const v of kegs) { const p = T.put(join(pre, 'Cellar', 'deno', v, 'bin', 'deno'), bytes(v)); chmodSync(p, 0o755); }
  mkdirSync(join(pre, 'opt'), { recursive: true }); mkdirSync(join(pre, 'bin'), { recursive: true });
  if (opt) symlinkSync(`../Cellar/deno/${opt}`, join(pre, 'opt', 'deno'));
  if (bin) symlinkSync(`../Cellar/deno/${bin}/bin/deno`, join(pre, 'bin', 'deno'));
  return root;
}
const brewRows = (root, files = DENO.versionFiles.files.filter((f) => f.label.startsWith('Homebrew'))) => checkVersionFiles({ ...DENO.versionFiles, files }, { root, os: 'darwin' });

test('A3 Homebrew\'s bin/deno, the one a shell runs, leading to an older keg than opt/deno: that keg is EXPOSED', () => {
  const rows = brewRows(brew(T.fresh('a3'), ['2.7.13', '2.7.14'], '2.7.14', '2.7.13'));
  assert.ok(rows.some((r) => r.status === 'EXPOSED' && r.version === '2.7.13'), JSON.stringify(rows));
  // with no opt link at all (removed by hand), the bin link still answers
  assert.deepEqual(statusOf(brewRows(brew(T.fresh('a3b'), ['2.7.13'], null, '2.7.13'))), [['EXPOSED', '2.7.13']]);
  // one keg reached both ways is one row (genuinely SAFE); a bin/deno that is no keg's is not read, as before
  assert.deepEqual(statusOf(brewRows(brew(T.fresh('a3c'), ['2.7.14'], '2.7.14', '2.7.14'))), [['SAFE', '2.7.14']]);
  const other = brew(T.fresh('a3d'), ['2.7.14'], '2.7.14', null);
  T.put(join(other, 'opt', 'homebrew', 'bin', 'deno'), 'a program from elsewhere');
  assert.deepEqual(statusOf(brewRows(other)), [['SAFE', '2.7.14']]);
  // the mutation: the candidate's rule, opt/deno only, reads the first fixture SAFE
  const optOnly = DENO.versionFiles.files.filter((f) => f.label === 'Homebrew');
  assert.deepEqual(statusOf(brewRows(brew(T.fresh('a3m'), ['2.7.13', '2.7.14'], '2.7.14', '2.7.13'), optOnly)), [['SAFE', '2.7.14']]);
});

test('A3t Homebrew\'s Deno keg named 2.7.14 holding a 2.7.13 program is not SAFE', todo('A3t Homebrew keg name'), () => {
  const rows = brewRows(brew(T.fresh('a3t'), ['2.7.14'], '2.7.14', '2.7.14', () => prog('Deno/2.7.13+abcdef0')));
  assert.ok(rows.length && rows.every((r) => r.status !== 'SAFE'), JSON.stringify(rows));
});

// ---------------------------------------------------------------- A4 a PATH entry written ~/bin

const HIDE_PHP = join(ROOT, 'test', 'support', 'hide-php-places.cjs');
test('A4 PATH="~/bin:…" (the ~ kept by quotes): bash and /bin/sh run ~/bin/php, and so that php is checked: EXPOSED', () => {
  const home = T.fresh('a4home'), fixed = T.fresh('a4fixed');
  T.put(join(home, 'bin', 'php'), '#!/bin/sh\necho "PHP 8.4.26 (cli)"\n', 0o755);
  T.put(join(fixed, 'php'), '#!/bin/sh\necho "PHP 8.4.27 (cli)"\n', 0o755);
  const PATH = `~/bin:${fixed}:/usr/bin:/bin`;
  // the truth: what bash runs for php with this PATH and this home
  const runs = spawnSync('/bin/bash', ['-c', 'command -v php'], { env: { HOME: home, PATH }, encoding: 'utf8' }).stdout.trim();
  assert.equal(runs, join(home, 'bin', 'php'));
  const r = cli(['--incident', 'php-2026-10'], { home, env: { PATH }, preload: [HIDE_PHP] });
  assert.equal(r.code, 1, JSON.stringify(r.rows.map((x) => [x.status, x.bin, x.reason])));
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.bin === join(home, 'bin', 'php')), JSON.stringify(r.rows));
});

// ---------------------------------------------------------------- A5 a CA bundle set in a shell start-up file

test('A5 SSL_CERT_FILE set in ~/.zshrc but not in the run\'s environment (sudo, cron, CI): cert.pem is not read in the control\'s place', () => {
  const inc = incident('emudhra-2026-10');
  const home = T.fresh('a5');
  const ask = (rt) => appleFileCheck(inc, rt, { os: 'darwin', macos: '27.2.1', env: {}, home, exists: () => false, certsDir: 0 });
  // the control: no start-up file, so the file stands in (the instrument can give the other answer)
  assert.ok(ask({ bin: '/usr/bin/curl' }).fileCheck, 'with no start-up file the file is read');
  for (const [file, line] of [['.zshrc', 'export SSL_CERT_FILE="$HOME/certs/old-bundle.pem"\n'], ['.bash_profile', 'SSL_CERT_DIR=/opt/certs; export SSL_CERT_DIR\n'], ['.zprofile', 'export CURL_CA_BUNDLE=/usr/local/etc/ca.pem\n']]) {
    const h = T.fresh('a5h'); T.put(join(h, file), line);
    const r = appleFileCheck(inc, { bin: '/usr/bin/curl' }, { os: 'darwin', macos: '27.2.1', env: {}, home: h, exists: () => false, certsDir: 0 });
    assert.equal(r.fileCheck, undefined, `${file}: ${JSON.stringify(r)}`);
    assert.match(r.skipped, new RegExp(file.replace('.', '\\.')));
  }
  // python3 does not read CURL_CA_BUNDLE: that line alone leaves its file check as it was (genuinely)
  const h = T.fresh('a5p'); T.put(join(h, '.zprofile'), 'export CURL_CA_BUNDLE=/x.pem\n');
  assert.ok(appleFileCheck(inc, { bin: '/usr/bin/python3' }, { os: 'darwin', macos: '27.2.1', env: {}, home: h, exists: () => false, certsDir: 0 }).fileCheck);
});

// ---------------------------------------------------------------- A6 PYTHONPATH

test('A6 a PYTHONPATH folder is searched as site-packages is: a stealer\'s install record in one is EXPOSED, and an old setuptools too', () => {
  const lib = T.fresh('a6lib');
  mkdirSync(join(lib, 'litellm-1.107.0.dist-info')); mkdirSync(join(lib, 'setuptools-70.0.0.dist-info'));
  assert.deepEqual(pythonPathDirs({ PYTHONPATH: `relative/dir:${lib}:` }), [lib]);
  const dirs = sitePackagesDirs({ patterns: [], pythonPath: pythonPathDirs({ PYTHONPATH: lib }), home: '', denied: [], found: [], links: [], deep: [] });
  assert.ok(dirs.includes(lib), JSON.stringify(dirs));
  const st = checkSitePackages(incident('setuptools-2026-07').sitePackages, dirs, [], { os: 'darwin' });
  assert.ok(st.some((r) => r.status === 'EXPOSED' && r.dir === lib), JSON.stringify(st));
  // the command: PYTHONPATH in its environment, a home with nothing in it
  const r = cli(['--incident', 'litellm-2026-10'], { home: T.fresh('a6home'), env: { PYTHONPATH: lib } });
  assert.ok(r.rows.some((x) => x.status === 'EXPOSED' && x.dir === lib), JSON.stringify(r.rows.map((x) => [x.status, x.dir ?? x.path, x.what])));
  assert.equal(r.code, 1);
  // the mutation: no PYTHONPATH folders, as before
  assert.equal(sitePackagesDirs({ patterns: [], pythonPath: [], home: '', denied: [], found: [], links: [], deep: [] }).includes(lib), false);
});

// ---------------------------------------------------------------- A7, A8 lockfiles

const lockRow = (kind, name, text) => { const p = T.put(join(T.fresh('lk'), name), text); return checkLockfile({ path: p, kind }, RSC); };
const notSafe = (r, what) => { assert.ok(!r.read || r.rows.length, `${what}: read as pinning nothing`); for (const x of r.rows) assert.notEqual(x.status, 'SAFE', `${what}: ${JSON.stringify(x)}`); };
const CASES = {
  'yarn classic npm: alias, resolved with no /-/ path': ['yarn', 'yarn.lock', '# yarn lockfile v1\n\n"rsdw@npm:react-server-dom-webpack@19.0.0":\n  version "19.0.0"\n  resolved "https://npm.example.com/download/react-server-dom-webpack/19.0.0/abc.tgz"\n  integrity sha512-x\n'],
  'yarn classic npm: alias, no resolved': ['yarn', 'yarn.lock', '# yarn lockfile v1\n\n"rsdw@npm:react-server-dom-webpack@19.0.0":\n  version "19.0.0"\n'],
  'yarn Berry key in single quotes': ['yarn', 'yarn.lock', "__metadata:\n  version: 8\n\n'react-server-dom-webpack@npm:19.0.0':\n  version: 19.0.0\n"],
  'yarn: react-server-dom-webpack installed from a fork': ['yarn', 'yarn.lock', '# yarn lockfile v1\n\n"react-server-dom-webpack@npm:@acme/rsdw-fork@1.0.0":\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/@acme/rsdw-fork/-/rsdw-fork-1.0.0.tgz#x"\n'],
  'npm v3: react-server-dom-webpack installed from a fork': ['npm', 'package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/react-server-dom-webpack': { name: '@acme/rsdw-fork', version: '1.0.0' } } })],
  'npm v1: react-server-dom-webpack installed from a fork': ['npm', 'package-lock.json', JSON.stringify({ lockfileVersion: 1, dependencies: { 'react-server-dom-webpack': { version: 'npm:@acme/rsdw-fork@1.0.0' } } })],
  'pnpm re-indented to four spaces': ['pnpm', 'pnpm-lock.yaml', "lockfileVersion: '9.0'\n\npackages:\n\n    react-server-dom-webpack@19.0.0:\n      resolution: {integrity: sha512-x}\n"],
  'pnpm packages written inline': ['pnpm', 'pnpm-lock.yaml', "lockfileVersion: '9.0'\npackages: {react-server-dom-webpack@19.0.0: {resolution: {integrity: sha512-x}}}\n"],
  'pnpm top-level key in quotes': ['pnpm', 'pnpm-lock.yaml', "lockfileVersion: '9.0'\n'packages':\n  react-server-dom-webpack@19.0.0:\n    resolution: {integrity: sha512-x}\n"],
};
test('A7 A8 lockfile aliases and pnpm layouts that read as pinning nothing: each is EXPOSED or UNKNOWN', () => {
  for (const [what, [kind, name, text]] of Object.entries(CASES)) notSafe(lockRow(kind, name, text), what);
  // genuinely nothing to report: a Berry range spec and a fork under its own name pin none of the packages
  assert.deepEqual(lockRow('yarn', 'yarn.lock', '__metadata:\n  version: 8\n\n"left-pad@npm:^1.3.0":\n  version: 1.3.0\n').rows, []);
  assert.deepEqual(lockRow('npm', 'package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/rsdw': { name: 'left-pad', version: '1.3.0' } } })).rows, []);
  // and pnpm's own layout, two-space entries with blank lines and a packages: {} for an empty project, still reads
  assert.deepEqual(lockRow('pnpm', 'pnpm-lock.yaml', "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\npackages: {}\n\nsnapshots: {}\n").read, true);
});

test('A7t pnpm: react-server-dom-webpack installed from a fork (importers names it; packages has only the fork) is not SAFE', todo('A7t pnpm alias'), () => {
  notSafe(lockRow('pnpm', 'pnpm-lock.yaml', "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react-server-dom-webpack:\n        specifier: npm:@acme/rsdw-fork@1.0.0\n        version: '@acme/rsdw-fork@1.0.0'\n\npackages:\n\n  '@acme/rsdw-fork@1.0.0':\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  '@acme/rsdw-fork@1.0.0': {}\n"), 'pnpm alias to a fork');
});

// ---------------------------------------------------------------- A9 the clock's files in the never-a-false-SAFE suite

test('A9 with clock.cjs loaded, "today" rests on the clock and the files the test gave, never on this Mac\'s own update files', { skip: !MAC && 'the clock files are a Mac\'s' }, () => {
  const ms = Date.parse('2000-01-02T00:00:00Z');
  const plist = T.put(join(T.fresh('a9'), 'SystemVersion.plist'), '<plist/>');
  spawnSync('touch', ['-t', '200001010000', plist]);
  const script = T.put(join(T.fresh('a9s'), 'now.mjs'), "const { effectiveNow } = await import(process.argv[2]);\nprocess.stdout.write(JSON.stringify(effectiveNow()));\n");
  const now = (preload) => JSON.parse(spawnSync(process.execPath, ['--require', preload, script, pathToFileURL(join(ROOT, 'lib', 'clock.mjs')).href], { env: { WL_NFS_NOW: String(ms), WL_NFS_PLIST: plist, PATH: '/usr/bin:/bin' }, encoding: 'utf8' }).stdout);
  assert.deepEqual(now(join(HERE, 'clock.cjs')), { now: ms, from: 'the system clock', clock: ms });
  // the mutation: clock.cjs as the candidate had it (SystemVersion.plist only); this Mac's receipts or XProtect win
  const old = T.put(join(T.fresh('a9m'), 'clock.cjs'), readFileSync(join(HERE, 'clock.cjs'), 'utf8').replace('const m = (p) => (CLOCK.has(String(p)) ? TO : p);', 'const m = (p) => (String(p) === PLIST ? TO : p);'));
  assert.notEqual(old, null);
  assert.ok(now(old).now > ms, 'mutant survived: the real update files are not read');
});

// ---------------------------------------------------------------- Am the planted mutations of lib/

test('Am mutation proof: A1, A3, A5, A6 and A7/A8 fail on planted mutations of lib/', async () => {
  const caught = [];
  // A1: the first match answers, as before
  let get = await mutatedLib(T.dir, 'installs.mjs', 'if (verdicts.size > 1)', 'if (false)');
  {
    const { checkVersionFiles: cvf } = await get('installs.mjs');
    const root = T.fresh('am1'); plant(root, mise, prog('Deno/2.7.14+aaaaaaa', 'Deno/2.7.13+bbbbbbb'));
    assert.deepEqual(statusOf(cvf({ ...DENO.versionFiles, files: [mise] }, { root, os: 'darwin' })), [['SAFE', '2.7.14']], 'mutant survived: A1');
    caught.push('A1');
  }
  // A3: the same keg reached by bin/deno is not told apart from opt/deno's (one row for the prefix, whatever its version)
  get = await mutatedLib(T.dir, 'installs.mjs', 'const keg = `${real.slice(0, m.index)}\\0${v}`;', 'const keg = real.slice(0, m.index);');
  {
    const { checkVersionFiles: cvf } = await get('installs.mjs');
    const rows = cvf({ ...DENO.versionFiles, files: DENO.versionFiles.files.filter((f) => f.label.startsWith('Homebrew')) }, { root: brew(T.fresh('am3'), ['2.7.13', '2.7.14'], '2.7.14', '2.7.13'), os: 'darwin' });
    assert.deepEqual(statusOf(rows), [['SAFE', '2.7.14']], 'mutant survived: A3');
    caught.push('A3');
  }
  // A5: shell start-up files not read
  get = await mutatedLib(T.dir, 'macos.mjs', 'if (named.length) return', 'if (false) return');
  {
    const { appleFileCheck: afc } = await get('macos.mjs');
    const h = T.fresh('am5'); T.put(join(h, '.zshrc'), 'export SSL_CERT_FILE=/x.pem\n');
    assert.ok(afc(incident('emudhra-2026-10'), { bin: '/usr/bin/curl' }, { os: 'darwin', macos: '27.2.1', env: {}, home: h }).fileCheck, 'mutant survived: A5');
    caught.push('A5');
  }
  // A6: PYTHONPATH's folders left out of the places searched
  get = await mutatedLib(T.dir, 'installs.mjs', 'for (const p of [...patterns, ...pythonPath])', 'for (const p of patterns)');
  {
    const { sitePackagesDirs: spd } = await get('installs.mjs');
    const lib = T.fresh('am6'); mkdirSync(join(lib, 'litellm-1.107.0.dist-info'));
    assert.equal(spd({ patterns: [], pythonPath: [lib], home: '', denied: [], found: [], links: [], deep: [] }).includes(lib), false, 'mutant survived: A6');
    caught.push('A6');
  }
  // A7: the npm: alias spec not read (classic yarn without a registry path), and a fork under a listed name not flagged
  get = await mutatedLib(T.dir, 'lockfiles.mjs', 'const real = block.resolution ?? block.targets.find(Boolean) ?? null;', 'const real = block.resolution ?? null;');
  {
    const { checkLockfile: cl } = await get('lockfiles.mjs');
    const [kind, name, text] = CASES['yarn classic npm: alias, no resolved'];
    const p = T.put(join(T.fresh('am7'), name), text);
    assert.deepEqual(cl({ path: p, kind }, RSC), { read: true, rows: [] }, 'mutant survived: A7 (yarn)');
    caught.push('A7 yarn');
  }
  get = await mutatedLib(T.dir, 'lockfiles.mjs', "if (at && name !== at && names.includes(at)) pins.push({ name: at, version: '' });", '');
  {
    const { checkLockfile: cl } = await get('lockfiles.mjs');
    const [kind, name, text] = CASES['npm v3: react-server-dom-webpack installed from a fork'];
    const p = T.put(join(T.fresh('am7n'), name), text);
    assert.deepEqual(cl({ path: p, kind }, RSC), { read: true, rows: [] }, 'mutant survived: A7 (npm)');
    caught.push('A7 npm');
  }
  // A8: an entry line deeper than two spaces with no key before it taken as belonging to one
  get = await mutatedLib(T.dir, 'lockfiles.mjs', "if (!/^ {2}\\S/.test(line)) { if (!keyed) bad ??= line; continue; }", "if (!/^ {2}\\S/.test(line)) continue;");
  {
    const { checkLockfile: cl } = await get('lockfiles.mjs');
    const [kind, name, text] = CASES['pnpm re-indented to four spaces'];
    const p = T.put(join(T.fresh('am8'), name), text);
    assert.deepEqual(cl({ path: p, kind }, RSC), { read: true, rows: [] }, 'mutant survived: A8');
    caught.push('A8');
  }
  assert.equal(caught.length, 7, caught.join(', '));
});

// ---------------------------------------------------------------- A4m the command's PATH, mutated

test('A4m mutation proof: with ~ entries dropped from PATH again, A4\'s php reads SAFE', () => {
  const copy = T.fresh('a4m');
  for (const d of ['bin', 'lib']) cpSync(join(ROOT, d), join(copy, d), { recursive: true });
  cpSync(join(ROOT, 'package.json'), join(copy, 'package.json'));
  const p = join(copy, 'bin', 'wardlatch.mjs'), src = readFileSync(p, 'utf8');
  const from = "split(delimiter).map(tilde).filter(";
  assert.ok(src.includes(from));
  writeFileSync(p, src.replace(from, 'split(delimiter).filter('));
  const home = T.fresh('a4mh'), fixed = T.fresh('a4mf');
  T.put(join(home, 'bin', 'php'), '#!/bin/sh\necho "PHP 8.4.26 (cli)"\n', 0o755);
  T.put(join(fixed, 'php'), '#!/bin/sh\necho "PHP 8.4.27 (cli)"\n', 0o755);
  const r = cli(['--incident', 'php-2026-10'], { home, env: { PATH: `~/bin:${fixed}:/usr/bin:/bin` }, preload: [HIDE_PHP], bin: p });
  assert.equal(r.code, 0, `mutant survived: A4 (${JSON.stringify(r.rows.map((x) => [x.status, x.bin]))})`);
});
