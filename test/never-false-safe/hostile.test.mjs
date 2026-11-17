// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// NEVER A FALSE SAFE, part 3 of 3: hostile fixture machines. Fake homes and disks built to trick Wardlatch into SAFE.
// Each ends EXPOSED or UNKNOWN, never SAFE, unless what is there is genuinely safe (and then the test says why). The
// command runs on the stand-in (HOME and --paths in this test's folder; the real home is never read: no-real-home.cjs),
// or, where a moment must be caught (a file swapped between its stat and its read, a listing that fails part way), the
// library is run in this process with fs patched for that moment (test/never-false-safe/support.mjs).
//   H1 lookalike and homoglyph folder names      H8 a version split across lines
//   H2 a trailing space or dot                    H9 a program whose bytes and name disagree (Brotli; Deno's folders)
//   H3 NFD-named folders                          H10 an empty but present lockfile
//   H4 a case-sensitive APFS volume, and HFS+     H11 a clock set back
//   H5 a symlink loop                             H12 a stale built-in list
//   H6 a symlink out of the scan root             H13 a folder unreadable half way through
//   H7 a file swapped between its stat and its read
// Disk images (H4) are made with hdiutil in this test's folder, attached there with -nobrowse, and detached and removed
// by the test; off macOS they are skipped, with the reason. Hm plants a mutation for this file and requires it to fail.
import '../support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, symlinkSync, chmodSync, rmSync, utimesSync, unlinkSync, existsSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { scratch, cli, incident, withFs, swapAfterStat, inode, variant, gen, mutatedLib, realLib, todo, MAC, HERE } from './support.mjs';

const T = scratch('hostile');
const mounts = [];
after(() => { for (const m of mounts) spawnSync('hdiutil', ['detach', '-force', m], { stdio: 'ignore' }); T.done(); });
const AS_ROOT = process.getuid?.() === 0;
const RSC = incident('react-rsc-2026-11'), RULE = RSC.lockfiles;
const lock = (v = '19.0.0') => JSON.stringify({ name: 'app', lockfileVersion: 3, packages: { '': { name: 'app' }, 'node_modules/react-server-dom-webpack': { version: v } } });
const home = () => T.fresh('home');
const rsc = (paths, h = home()) => cli(['--incident', 'react-rsc-2026-11', ...paths.flatMap((p) => ['--paths', p])], { home: h });
const neverSafe = (r, what) => { assert.notEqual(r.code, 0, `${what}: exit 0 (SAFE): ${JSON.stringify(r.rows.map((x) => [x.status, x.reason]))}`); assert.ok(!r.rows.some((x) => x.status === 'SAFE' && x.kind === 'lockfile' && !x.file), `${what}: an all-clear`); };
const exposedFiles = (r) => r.rows.filter((x) => x.status === 'EXPOSED').map((x) => x.file ?? x.path);

// ---------------------------------------------------------------- H1, H2, H3: names

const LOOKALIKES = ['nоde_modules', 'node_modules ', 'node_modules.', '.gіt', 'Library2', 'node_modules‍', 'ｎode_modules'];
test('H1 lookalike and homoglyph folders (Cyrillic о in node_modules, і in .git, a zero-width joiner, fullwidth n) are walked: the projects in them are EXPOSED', () => {
  const root = T.fresh('h1');
  for (const n of LOOKALIKES) { try { T.put(join(root, n, 'proj', 'package-lock.json'), lock()); } catch { /* a disk that refuses the name */ } }
  const r = rsc([root]);
  const made = LOOKALIKES.filter((n) => existsSync(join(root, n, 'proj', 'package-lock.json')));
  // only a name the disk opens as node_modules or .git itself is the real thing, and is not walked
  const real = made.filter((n) => inode(join(root, n)) === inode(join(root, 'node_modules')) || inode(join(root, n)) === inode(join(root, '.git')));
  assert.equal(r.code, 1);
  assert.equal(exposedFiles(r).length, made.length - real.length, JSON.stringify({ made, real, got: exposedFiles(r) }));
});

test('H2 a trailing space or dot: lockfile lookalikes beside the real one never stand in for it; folders named "proj." and "proj " are walked', () => {
  const root = T.fresh('h2');
  const a = join(root, 'a');
  T.put(join(a, 'package-lock.json'), lock('19.0.1'));
  for (const n of ['package-lock.json ', 'package-lock.json.', 'package-lock.json​']) { try { writeFileSync(join(a, n), lock('19.0.9')); } catch { /* refused */ } }
  for (const n of ['proj.', 'proj ', 'proj\t']) { try { T.put(join(root, n, 'package-lock.json'), lock('19.1.2')); } catch { /* refused */ } }
  const r = rsc([root]);
  assert.equal(r.code, 1);
  // the real lockfile is read, whatever stands beside it: a lookalike the disk keeps apart is not a lockfile npm reads
  assert.ok(exposedFiles(r).includes(join(a, 'package-lock.json')), JSON.stringify(r.rows));
  for (const n of ['proj.', 'proj ', 'proj\t']) if (existsSync(join(root, n))) assert.ok(exposedFiles(r).some((f) => f.includes(`/${n}/`)), `${JSON.stringify(n)}: ${JSON.stringify(exposedFiles(r))}`);
  // each spelling the disk keeps apart from package-lock.json pins nothing npm installs: none has a row
  for (const x of r.rows) if (x.file) assert.equal(inode(x.file) === inode(join(x.file, '..', 'package-lock.json')), true, x.file);
});

test('H3 NFD-named folders: a project and a WordPress site in folders named in decomposed Unicode are found and EXPOSED', () => {
  const root = T.fresh('h3');
  const proj = join(root, 'café', 'Projèt');
  T.put(join(proj, 'package-lock.json'), lock());
  assert.equal(rsc([root]).code, 1);
  const site = join(root, 'sité');
  T.put(join(site, 'wp-includes', 'version.php'), "<?php $wp_version = '6.8';\n");
  T.put(join(site, 'wp-config.php'), '<?php\n');
  T.put(join(site, 'wp-content', 'plugins', 'updrаftplus', 'updraftplus.php'), '<?php\n/*\nPlugin Name: UpdraftPlus\nVersion: 1.26.10\n*/\n');
  const w = cli(['--incident', 'wordpress-plugins-2026-10', '--paths', root], { home: home() });
  assert.equal(w.code, 1, JSON.stringify(w.rows.map((x) => [x.status, x.what, x.reason])));
  assert.ok(w.rows.some((x) => x.status === 'EXPOSED' && /updr.ftplus 1\.26\.10/.test(x.what)), 'the plugin under a homoglyph folder name, found by its main file');
});

// ---------------------------------------------------------------- H4: disks that keep case, and HFS+

/** A disk image of `fs` made, attached in this test's folder and returned by its mount point; null with why when not. */
function disk(fs, tag) {
  if (!MAC) return { skip: 'disk images are made with hdiutil, on macOS only' };
  const img = join(T.dir, `${tag}.dmg`), mnt = join(T.dir, `${tag}-mnt`);
  mkdirSync(mnt, { recursive: true });
  const c = spawnSync('hdiutil', ['create', '-quiet', '-size', '24m', '-fs', fs, '-volname', `WL${tag}`, '-o', img], { encoding: 'utf8' });
  if (c.status !== 0) return { skip: `hdiutil could not make a ${fs} image: ${c.stderr.trim().slice(0, 160)}` };
  const a = spawnSync('hdiutil', ['attach', '-quiet', '-nobrowse', '-noautoopen', '-mountpoint', mnt, img], { encoding: 'utf8' });
  if (a.status !== 0) return { skip: `hdiutil could not attach it: ${a.stderr.trim().slice(0, 160)}` };
  mounts.push(mnt);
  return { mnt, done: () => { spawnSync('hdiutil', ['detach', '-force', mnt], { stdio: 'ignore' }); mounts.splice(mounts.indexOf(mnt), 1); rmSync(img, { force: true }); } };
}
/** On the disk at `mnt`: lockfiles in other spellings are read exactly when the disk opens them under the manager's
 *  name, a PATH program in another case is found exactly when the shell finds it, and sameNameOnDisk is the disk's
 *  answer for generated pairs. */
async function onDisk(mnt) {
  const { lockfilesUnder, checkLockfile } = await realLib('lockfiles.mjs');
  const { sameNameOnDisk } = await realLib('files.mjs');
  const { findOnPath } = await realLib('binaries.mjs');
  const root = join(mnt, 'root');
  for (const [p, n] of [['p1', 'Package-Lock.json'], ['p2', 'package-lock.json'], ['p3', 'PACKAGE-LOCK.JSON'], ['p4', 'packaKe-lock.json'], ['café', 'package-lock.json']]) T.put(join(root, p, n), lock());
  const found = lockfilesUnder([root], 10, [], [], { deep: [] });
  for (const p of ['p1', 'p2', 'p3', 'p4', 'café']) {
    const opens = inode(join(root, p, 'package-lock.json')) !== null;
    // by the folder's identity: HFS+ keeps café as NFD, and lists it so
    const got = found.filter((f) => inode(join(f.path, '..')) === inode(join(root, p)));
    assert.equal(got.length, opens ? 1 : 0, `${p}: the disk ${opens ? 'opens' : 'does not open'} package-lock.json there; Wardlatch found ${JSON.stringify(got)}`);
    for (const f of got) assert.equal(checkLockfile(f, RULE).rows[0]?.status, 'EXPOSED');
  }
  const bin = join(mnt, 'bin'); mkdirSync(bin); writeFileSync(join(bin, 'PHP'), '#!/bin/sh\n', { mode: 0o755 });
  const sh = spawnSync('/bin/sh', ['-c', 'command -v php'], { env: { PATH: bin }, encoding: 'utf8' }).stdout.trim() || null;
  assert.equal(findOnPath('php', bin) ?? null, sh, 'the program a shell runs for php on this disk');
  const g = gen(0x4d15c);
  const pairs = join(mnt, 'pairs');
  mkdirSync(pairs);
  for (let i = 0; i < 300; i++) {
    const a = variant(g, g.pick(['straße', 'ﬁle', 'Key', 'café', 'σοφος', 'İd', 'confıg', 'x‍y', 'Ａbc', 'trail'])), b = variant(g, a);
    const d = join(pairs, `${i}`); mkdirSync(d);
    try { writeFileSync(join(d, a), 'x'); } catch { continue; }
    const same = inode(join(d, b)) === inode(join(d, a));
    assert.equal(sameNameOnDisk(d, a, b), same, `${JSON.stringify(a)} / ${JSON.stringify(b)}: the disk says ${same ? 'one file' : 'two'}`);
  }
}
for (const [fs, tag] of [['Case-sensitive APFS', 'apfscs'], ['HFS+', 'hfs'], ['Case-sensitive HFS+', 'hfscs']]) {
  test(`H4 a ${fs} volume: lockfiles, PATH programs and spellings are what that disk opens, never what a Mac's default disk would`, async (t) => {
    const d = disk(fs, tag);
    if (d.skip) return t.skip(d.skip);
    try { await onDisk(d.mnt); } finally { d.done(); }
  });
}

// ---------------------------------------------------------------- H5, H6: links

test('H5 a symlink loop: folders that lead to each other, and a lockfile name that is a link to itself, end UNKNOWN, not SAFE', () => {
  const root = T.fresh('h5');
  mkdirSync(join(root, 'proj'));
  symlinkSync(join(root, 'b'), join(root, 'a')); symlinkSync(join(root, 'a'), join(root, 'b'));
  symlinkSync(join(root, 'proj', 'package-lock.json'), join(root, 'proj', 'package-lock.json'));
  const r = rsc([root]);
  neverSafe(r, 'a lockfile name that loops');
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && x.file === join(root, 'proj', 'package-lock.json')), JSON.stringify(r.rows));
  // the folder loop alone leads nowhere: nothing behind it to read (genuinely nothing), and the run still ends
  const only = T.fresh('h5b'); symlinkSync(join(only, 'y'), join(only, 'x')); symlinkSync(join(only, 'x'), join(only, 'y'));
  T.put(join(only, 'real', 'package-lock.json'), lock());
  assert.equal(rsc([only]).code, 1);
});

test('H6 a symlink out of the scan root: the project behind it is not passed over in silence (UNKNOWN, never SAFE)', () => {
  const root = T.fresh('h6'), outside = T.fresh('h6-outside');
  T.put(join(outside, 'proj', 'package-lock.json'), lock());
  T.put(join(root, 'clean', 'package-lock.json'), lock('19.0.9'));
  symlinkSync(outside, join(root, 'away'));
  const r = rsc([root]);
  neverSafe(r, 'a link out of the root');
  assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && JSON.stringify(x).includes(join(root, 'away'))), JSON.stringify(r.rows));
});

// ---------------------------------------------------------------- H7: a file swapped between its stat and its read

test('H7 a file swapped between its stat and its read: removed, made a folder or a FIFO in the window, it is UNKNOWN, never SAFE', async () => {
  const { checkLockfile } = await realLib('lockfiles.mjs');
  const { checkVersionFiles } = await realLib('installs.mjs');
  const { safe, withdrawUnreceipted } = await realLib('report.mjs');
  const swaps = {
    removed: (p) => unlinkSync(p),
    'made a folder': (p) => { unlinkSync(p); mkdirSync(p); },
    'made a FIFO': (p) => { unlinkSync(p); execFileSync('mkfifo', [p]); },
    'made a link to nothing': (p) => { unlinkSync(p); symlinkSync(join(p, '..', 'gone'), p); },
  };
  for (const [what, swap] of Object.entries(swaps)) {
    const p = T.put(join(T.fresh('h7'), 'package-lock.json'), lock('19.0.9'));
    const r = withFs(swapAfterStat(p, () => swap(p)), () => checkLockfile({ path: p, kind: 'npm' }, RULE));
    assert.equal(r.read, false, `lockfile ${what}: ${JSON.stringify(r)}`);
    assert.equal(r.rows[0].status, 'UNKNOWN', `lockfile ${what}`);
    // a product's version file the same way: Chrome's Info.plist
    const root = T.fresh('h7v'), inc = incident('chrome-2026-11');
    const f = inc.versionFiles.files[0], q = T.put(join(root, f.path), '<plist><dict><key>CFBundleShortVersionString</key>\n<string>157.0.8103.60</string></dict></plist>');
    const rows = withFs(swapAfterStat(q, () => swap(q)), () => checkVersionFiles({ ...inc.versionFiles, files: [f] }, { root, os: 'darwin' }));
    assert.ok(rows.length && rows.every((x) => x.status === 'UNKNOWN'), `Info.plist ${what}: ${JSON.stringify(rows)}`);
  }
  // and after the read, before the run ends: a SAFE whose file is gone by then is withdrawn on the way out
  const p = T.put(join(T.fresh('h7w'), 'package-lock.json'), lock('19.0.9'));
  const row = { kind: 'lockfile', ...safe([p], { reason: 'none of the packages' }) };
  rmSync(p);
  assert.equal(withdrawUnreceipted([row]).length, 1);
  assert.equal(row.status, 'UNKNOWN');
});

// ---------------------------------------------------------------- H8: a version split across lines

test('H8 a version split across lines (Info.plist, a WordPress header, yarn.lock, pnpm-lock.yaml, dpkg) is never read as a whole version that passes', async () => {
  const { checkVersionFiles } = await realLib('installs.mjs');
  const { checkSite } = await realLib('wordpress.mjs');
  const { checkLockfile } = await realLib('lockfiles.mjs');
  const chrome = incident('chrome-2026-11'), f = chrome.versionFiles.files[0];
  const root = T.fresh('h8');
  T.put(join(root, f.path), '<plist><dict><key>CFBundleShortVersionString</key>\n<string>156.0.\n8078.95</string></dict></plist>');
  const rows = checkVersionFiles({ ...chrome.versionFiles, files: [f] }, { root, os: 'darwin' });
  assert.deepEqual(rows.map((x) => x.status), ['UNKNOWN'], JSON.stringify(rows));
  // Rank Math PRO's compromised 3.0.123, its header split: "3.0." is no version, and must not pass for one
  const WP = incident('wordpress-plugins-2026-10');
  const site = T.fresh('h8wp');
  T.put(join(site, 'wp-includes', 'version.php'), "<?php $wp_version = '6.8';\n");
  T.put(join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro', 'rank-math-pro.php'), '<?php\n/*\nPlugin Name: Rank Math SEO PRO\nVersion: 3.0.\n123\n*/\n');
  const w = checkSite(site, WP.rules, undefined).filter((x) => /rank-math/.test(x.what));
  assert.ok(w.length && w.every((x) => x.status !== 'SAFE'), JSON.stringify(w));
  // lockfiles: a version string broken over two lines is a line left open (yarn) or a key with no version (pnpm)
  const d = T.fresh('h8l');
  writeFileSync(join(d, 'yarn.lock'), '# yarn lockfile v1\n\n"react-server-dom-webpack@^19.0.0":\n  version "19.0.\n0"\n');
  assert.notEqual(checkLockfile({ path: join(d, 'yarn.lock'), kind: 'yarn' }, RULE).rows[0]?.status ?? 'SAFE', 'SAFE');
  writeFileSync(join(d, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n\npackages:\n\n  'react-server-dom-webpack@19.0.\n    0':\n    resolution: {integrity: sha512-x}\n");
  assert.notEqual(checkLockfile({ path: join(d, 'pnpm-lock.yaml'), kind: 'pnpm' }, RULE).rows[0]?.status ?? 'SAFE', 'SAFE');
  // dpkg's record, the version broken: the part read is below every fix (EXPOSED), never past one
  const dp = chrome.versionFiles.files.find((x) => x.path === '/var/lib/dpkg/status');
  T.put(join(root, dp.path), 'Package: google-chrome-stable\nStatus: install ok installed\nVersion: 157.0.\n8103.60-1\n\n');
  const r2 = checkVersionFiles({ ...chrome.versionFiles, files: [dp] }, { root, os: 'linux' });
  assert.ok(r2.length && r2.every((x) => x.status !== 'SAFE'), JSON.stringify(r2));
});

// ---------------------------------------------------------------- H9: a program's bytes against its name

test('H9 a Brotli library named for a fixed release whose bytes lack the fix is EXPOSED: judged by its content, not its name', async () => {
  const { judgeFile } = await realLib('brotli.mjs');
  const M = incident('brotli-2026-10').markers;
  const cs = (a) => Buffer.concat(a.map((p) => Buffer.from(`\0${p}\0`)));
  const head = Buffer.alloc(64); Buffer.from('cffaedfe', 'hex').copy(head, 0);
  const d = T.fresh('h9');
  const named = join(d, 'libbrotlidec.1.2.0.dylib');
  writeFileSync(named, Buffer.concat([head, cs(['_SUCCESS', M.table, '_ERROR_UNREACHABLE']), Buffer.alloc(64)]));
  assert.equal(judgeFile(named, { markers: M }).status, 'EXPOSED');
  // and the other way round, genuinely safe: an old name over bytes that carry the fix is SAFE, by those bytes
  const old = join(d, 'libbrotlidec.1.0.9.dylib');
  writeFileSync(old, Buffer.concat([head, cs(['_SUCCESS', M.table, M.fixed, '_ERROR_UNREACHABLE']), Buffer.alloc(64)]));
  assert.equal(judgeFile(old, { markers: M }).status, 'SAFE');
});

const DENO = incident('deno-2026-06');
test('H9b a Deno that mise or asdf keeps in a folder named 2.7.14, whose program inside is 2.7.13, is not SAFE', todo('H9b deno by folder name'), async () => {
  const { checkVersionFiles } = await realLib('installs.mjs');
  const root = T.fresh('h9b');
  const mise = DENO.versionFiles.files.find((x) => x.label === 'mise');
  // checkVersionFiles puts `root` in front of the pattern as text (a ~ there is then a folder named ~)
  const bin = T.put(`${root}${mise.path.replace('*', '2.7.14')}/bin/deno`, Buffer.concat([Buffer.alloc(256, 0xcf), Buffer.from('Deno/2.7.13+a1b2c3d\0'), Buffer.alloc(64)]));
  chmodSync(bin, 0o755);
  const rows = checkVersionFiles({ ...DENO.versionFiles, files: [mise] }, { root, os: 'darwin' });
  assert.ok(rows.length && rows.every((x) => x.status !== 'SAFE'), JSON.stringify(rows.map((x) => [x.status, x.version, x.path?.slice(root.length)])));
});

// ---------------------------------------------------------------- H10: an empty lockfile

test('H10 an empty but present lockfile (npm, yarn, pnpm, Bun) is UNKNOWN: the run exits 2, never 0', () => {
  const root = T.fresh('h10');
  for (const n of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'npm-shrinkwrap.json']) T.put(join(root, n.replace(/\W/g, ''), n), '');
  const r = rsc([root]);
  assert.equal(r.code, 2, JSON.stringify(r.rows));
  assert.equal(r.rows.filter((x) => x.status === 'UNKNOWN' && x.kind === 'lockfile').length, 5, JSON.stringify(r.rows.map((x) => [x.status, x.file, x.reason])));
});

// ---------------------------------------------------------------- H11, H12: the clock

const MACOS = incident('macos-2026-11');
const DAY = 86400000;
const listDay = Date.parse(MACOS.latestListed ?? MACOS.macosLines.map((l) => l.latestDate).sort().at(-1) ?? MACOS.date);
/** The command's macOS row, its clock at `now` and SystemVersion.plist a release at the newest line's latest (with its
 *  times at `filesAt`). */
function macosAt(now, filesAt) {
  const line = MACOS.macosLines.find((l) => !l.frozen);
  const p = T.put(join(T.fresh('h11'), 'SystemVersion.plist'), `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n\t<key>ProductBuildVersion</key>\n\t<string>26B131</string>\n\t<key>ProductName</key>\n\t<string>macOS</string>\n\t<key>ProductVersion</key>\n\t<string>${line.latest}</string>\n</dict>\n</plist>\n`);
  utimesSync(p, new Date(filesAt), new Date(filesAt));
  const r = cli(['--incident', 'macos-2026-11'], { home: home(), preload: [join(HERE, 'clock.cjs')], env: { WL_NFS_NOW: String(now), WL_NFS_PLIST: p } });
  return r.rows.find((x) => x.kind === 'macos');
}
test('H11 a clock set back to the day after the list was read, on a Mac whose update files are 400 days newer, does not read SAFE', { skip: !MAC && 'the macOS row is made on a Mac', ...todo('H11 clock set back') }, () => {
  const row = macosAt(listDay + DAY, listDay + 400 * DAY);
  assert.notEqual(row.status, 'SAFE', row.reason);
});
test('H12 a stale built-in list: 400 days after Apple\'s releases were listed, macOS at the listed latest does not read SAFE', { skip: !MAC && 'the macOS row is made on a Mac', ...todo('H12 stale built-in list') }, () => {
  const row = macosAt(listDay + 400 * DAY, listDay + 400 * DAY);
  assert.notEqual(row.status, 'SAFE', row.reason);
});
test('H11c control: the same Mac on the day after the list was read is SAFE (genuinely: the list is a day old)', { skip: !MAC && 'the macOS row is made on a Mac' }, () => {
  const row = macosAt(listDay + DAY, listDay + DAY);
  assert.equal(row.status, 'SAFE', row.reason);
});

// ---------------------------------------------------------------- H13: a folder unreadable half way through

test('H13 a folder unreadable half way through: closed before the run, or refusing its listing part way through the walk, it is UNKNOWN', async () => {
  const root = T.fresh('h13');
  for (let i = 0; i < 6; i++) T.put(join(root, `p${i}`, 'src', 'package-lock.json'), lock('19.0.9'));
  T.put(join(root, 'p3', 'src', 'deep', 'package-lock.json'), lock('19.0.0'));
  if (!AS_ROOT) {
    chmodSync(join(root, 'p3', 'src'), 0o000);
    const r = rsc([root]);
    chmodSync(join(root, 'p3', 'src'), 0o755);
    assert.equal(r.code, 2, JSON.stringify(r.rows.map((x) => [x.status, x.path ?? x.file])));
    assert.ok(r.rows.some((x) => x.status === 'UNKNOWN' && (x.path === join(root, 'p3', 'src') || JSON.stringify(x).includes(join(root, 'p3', 'src')))));
  }
  // the walk's fourth listing fails (EIO, EACCES, EPERM, an NFS server that went away): that folder is a gap, not empty
  const { lockfilesUnder } = await realLib('lockfiles.mjs');
  for (const code of ['EIO', 'EACCES', 'EPERM', 'ESTALE', 'ETIMEDOUT']) {
    let n = 0, failed = null;
    const denied = [], links = [], deep = [];
    const found = withFs({ readdirSync: (o) => function (p, ...rest) { if (String(p).startsWith(root) && ++n === 4) { failed = String(p); throw Object.assign(new Error(code), { code }); } return o.call(this, p, ...rest); } },
      () => lockfilesUnder([root], 10, denied, links, { deep }));
    assert.ok(failed && denied.includes(failed), `${code}: ${failed} must be a gap (denied ${JSON.stringify(denied)})`);
    assert.ok(found.length < 7);
  }
});

// ---------------------------------------------------------------- Hm the planted mutations

test('Hm mutation proof: the hostile fixtures fail on planted mutations of lib/', async () => {
  const caught = [];
  // H6: a link to a folder passed over in silence
  let get = await mutatedLib(T.dir, 'lockfiles.mjs', 'if (e.isSymbolicLink() && mayBeFolder(p)) maybeLinks.push({ path: p, need: depth - 1 });', '');
  {
    const { lockfilesUnder } = await get('lockfiles.mjs');
    const root = T.fresh('hm6'), outside = T.fresh('hm6o'); T.put(join(outside, 'p', 'package-lock.json'), lock()); symlinkSync(outside, join(root, 'away'));
    const links = []; lockfilesUnder([root], 10, [], links, { deep: [] });
    assert.equal(links.length, 0, 'the mutant drops the link'); caught.push('H6: a link out of the root not recorded');
  }
  // H8: the WordPress header read as any run of digits and dots
  get = await mutatedLib(T.dir, 'wordpress.mjs', '(\\d+(?:\\.\\d+)*)(?![\\d.])', '([\\d.]+)');
  {
    const { checkSite } = await get('wordpress.mjs');
    const site = T.fresh('hm8');
    T.put(join(site, 'wp-includes', 'version.php'), "<?php $wp_version = '6.8';\n");
    T.put(join(site, 'wp-content', 'plugins', 'seo-by-rank-math-pro', 'rank-math-pro.php'), '<?php\n/*\nVersion: 3.0.\n123\n*/\n');
    assert.ok(checkSite(site, incident('wordpress-plugins-2026-10').rules).some((x) => x.status === 'SAFE'), 'mutant survived: H8');
    caught.push('H8: "3.0." read as a version');
  }
  // H10: an npm lockfile that is not JSON read as pinning nothing
  get = await mutatedLib(T.dir, 'lockfiles.mjs', "try { j = JSON.parse(text); } catch { return { error: 'is not valid JSON, so it could not be read as an npm lockfile' }; }", 'try { j = JSON.parse(text); } catch { return { pins: [], entries: 0 }; }');
  {
    const { checkLockfile } = await get('lockfiles.mjs');
    const p = T.put(join(T.fresh('hm10'), 'package-lock.json'), '');
    assert.equal(checkLockfile({ path: p, kind: 'npm' }, RULE).read, true, 'mutant survived: H10');
    caught.push('H10: an empty npm lockfile read as pinning nothing');
  }
  // H13: a listing that fails taken as an empty folder
  get = await mutatedLib(T.dir, 'files.mjs', "return isGone(e, dir) ? { gone: true } : { denied: true, code: e.code };", 'return { gone: true };');
  {
    const { lockfilesUnder } = await get('lockfiles.mjs');
    const root = T.fresh('hm13'); T.put(join(root, 'a', 'b', 'package-lock.json'), lock());
    const denied = [];
    const found = withFs({ readdirSync: (o) => function (p, ...rest) { if (String(p) === join(root, 'a')) throw Object.assign(new Error('EIO'), { code: 'EIO' }); return o.call(this, p, ...rest); } }, () => lockfilesUnder([root], 10, denied, [], { deep: [] }));
    assert.deepEqual([found.length, denied.length], [0, 0], 'the mutant reads a failed listing as an empty folder');
    caught.push('H13: a failed listing read as an empty folder');
  }
  assert.equal(caught.length, 4, caught.join('\n'));
});
