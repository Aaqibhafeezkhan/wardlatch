// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The sweep of 17 Nov 2026 (release/0.1.19-candidate), four incidents, each held to its sources and each with planted
// mutations that must turn it red:
//   starlette-2026-06     Starlette below 1.0.1 (CVE-2026-48710, CISA KEV 2 Sep 2026): site-packages and Python lockfiles
//   mcp-python-2026-10    the MCP Python SDK and FastMCP; at or past the fix REVIEW, never SAFE, where the fix is a
//                         setting that is off by default (pattern P9, docs/PATTERNS.md)
//   xcode-2026-10         Xcode below 27.2, read from every Xcode*.app and the one xcode-select points to, each once
//   docker-desktop-2026-10  Docker Desktop below 4.97.0; at or past it, logs left by an earlier version are REVIEW
//                         (names and dates only, never a file's contents)
// Fixtures live under a scratch root; the real home and the machine's own places are never read.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, chmodSync, utimesSync, readFileSync, writeFileSync, cpSync } from 'node:fs';
import { join } from 'node:path';
import { scratch, mutatedLib, realLib, incident, cli, MAC, ROOT } from './never-false-safe/support.mjs';

const T = scratch('sweep0119');
after(() => T.done());
const { checkVersionFiles, checkSitePackages } = await realLib('installs.mjs');
const { pinnedIn, checkLockfile, lockfilesUnder, pyLockKind, judgePinned, LOCK_DEPTH } = await realLib('lockfiles.mjs');
const STAR = incident('starlette-2026-06'), MCP = incident('mcp-python-2026-10'), XC = incident('xcode-2026-10'), DD = incident('docker-desktop-2026-10');
const HIDE = join(ROOT, 'test', 'support', 'hide-machine-places.cjs');
const st = (rows) => rows.map((r) => [r.status, r.version ?? '']);
const site = (pkgs) => { const d = T.fresh('site'); for (const p of pkgs) mkdirSync(join(d, `${p}.dist-info`)); return d; };
const siteRows = (inc, pkgs) => checkSitePackages(inc.sitePackages, [site(pkgs)]).map((r) => [r.status, r.version]);
const lock = (kind, text, rule) => { const name = { uv: 'uv.lock', poetry: 'poetry.lock', pylock: 'pylock.toml', pipfile: 'Pipfile.lock', requirements: 'requirements.txt' }[kind]; const p = T.put(join(T.fresh('proj'), name), text); return checkLockfile({ path: p, kind }, rule); };
const uv = (pkgs) => `version = 1\nrequires-python = ">=3.10"\n\n${pkgs.map(([n, v]) => `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "anyio" },\n]\nwheels = [\n    { url = "https://x/${n}.whl", hash = "sha256:00" },\n]\n`).join('\n')}`;
const poetry = (pkgs) => `${pkgs.map(([n, v]) => `[[package]]\nname = "${n}"\nversion = "${v}"\ndescription = "x"\noptional = false\n\n[package.dependencies]\nanyio = ">=3.6.2"\n`).join('\n')}\n[metadata]\nlock-version = "2.0"\ncontent-hash = "abc"\n`;

// ---------------------------------------------------------------- Starlette

test('S1 Starlette installed: below 1.0.1 EXPOSED with CISA\'s date; 1.0.1 and later no row; a pre-release UNKNOWN', () => {
  assert.deepEqual(siteRows(STAR, ['starlette-0.46.2', 'starlette-1.0.0']).sort(), [['EXPOSED', '0.46.2'], ['EXPOSED', '1.0.0']]);
  assert.deepEqual(siteRows(STAR, ['starlette-1.0.1', 'starlette-1.8.0']), []);
  assert.deepEqual(siteRows(STAR, ['starlette-1.0.1rc1']), [['UNKNOWN', '1.0.1rc1']]);
  const [r] = checkSitePackages(STAR.sitePackages, [site(['Starlette-0.27.0'])]);
  assert.match(r.reason, /CISA lists as exploited \(added 2 Sep 2026\)/);
  assert.deepEqual(STAR.kev, [{ cve: 'CVE-2026-48710', vendorProject: 'Kludex', product: 'Starlette', dateAdded: '2026-09-02', dueDate: '2026-09-16' }]);
  assert.match(STAR.summary, /Python MCP servers run on Starlette/);
});

test('S2 Python lockfiles: uv, Poetry, pylock, Pipenv and requirements pins of Starlette are judged; ranges and cut files are UNKNOWN', () => {
  const R = STAR.pyLockfiles;
  const status = (r) => [r.read, r.rows.map((x) => [x.status, x.version ?? ""])];
  assert.deepEqual(status(lock('uv', uv([['anyio', '4.6.0'], ['starlette', '0.46.2']]), R)), [true, [['EXPOSED', '0.46.2']]]);
  assert.deepEqual(status(lock('uv', uv([['starlette', '1.0.1']]), R)), [true, [['SAFE', '1.0.1']]]);
  assert.deepEqual(status(lock('poetry', poetry([['Starlette', '0.40.0']]), R)), [true, [['EXPOSED', '0.40.0']]]);
  assert.deepEqual(status(lock('pylock', 'lock-version = "1.0"\ncreated-by = "x"\n\n[[packages]]\nname = "starlette"\nversion = "1.0.0"\n', R)), [true, [['EXPOSED', '1.0.0']]]);
  assert.deepEqual(status(lock('pipfile', JSON.stringify({ _meta: { hash: {} }, default: { starlette: { version: '==0.41.3', hashes: [] } }, develop: {} }), R)), [true, [['EXPOSED', '0.41.3']]]);
  assert.deepEqual(status(lock('requirements', '# app\nfastapi==0.115.0 \\\n    --hash=sha256:00\nstarlette[full]==0.41.3 ; python_version >= "3.9"\n', R)), [true, [['EXPOSED', '0.41.3']]]);
  // named but not pinned to one version: UNKNOWN, with why, never the all-clear
  const range = lock('requirements', 'starlette>=0.40\n', R);
  assert.deepEqual(status(range), [true, [['UNKNOWN', '']]]); assert.match(range.rows[0].reason, /a range or a URL, not one version/);
  assert.deepEqual(status(lock('pipfile', JSON.stringify({ _meta: {}, default: { starlette: { git: 'https://x', ref: 'main' } } }), R)), [true, [['UNKNOWN', '']]]);
  // a file cut short, an include of a file elsewhere, a line not read: the whole file is UNKNOWN
  for (const [kind, text] of [['uv', uv([['starlette', '1.0.1']]).slice(0, -1)], ['uv', 'version = 1\n\n[[package]]\nname = "starlette"\nversion = "1.0.1"\ndependencies = [\n    { name = "anyio" },\n'],
    ['poetry', '[[package]]\nname = "starlette"\nversion = "1.0.1"\n'], ['requirements', '-r ../shared/base.txt\n'], ['requirements', 'https://example.com/pkg.whl\n'], ['pipfile', '{"default":{}}']]) {
    const r = lock(kind, text, R);
    assert.deepEqual(status(r), [false, [['UNKNOWN', '']]], `${kind}: ${text.slice(0, 40)}`);
  }
  // an include of a requirements file beside it is read on its own, not a gap
  assert.deepEqual(status(lock('requirements', '-r requirements-base.txt\nuvicorn==0.30.0\n', R)), [true, []]);
  // names as pip compares them (PEP 503)
  assert.deepEqual(pinnedIn('requirements', 'StarLette==0.40.0\nFastMCP_Slim==4.1.0\n', ['starlette', 'fastmcp-slim']).pins, [{ name: 'starlette', version: '0.40.0' }, { name: 'fastmcp-slim', version: '4.1.0' }]);
  assert.deepEqual(pinnedIn('requirements', 'star_lette==0.40.0\n', ['starlette']).pins, []);   // another name, as pip reads it
});

test('S2m mutation proof: a cut uv.lock, an unclosed list and a bare URL line each read as an all-clear when their gate is removed', async () => {
  const R = STAR.pyLockfiles;
  const cases = [
    ["if (!text.endsWith('\\n')) return { error: `is ${what} that ends part way through a line", "if (false) return { error: `is ${what} that ends part way through a line", 'uv', uv([['starlette', '1.0.1']]).slice(0, -1)],
    ['if (open) return { error: `is ${what} with a list that is never closed', 'if (false) return { error: `is ${what} with a list that is never closed', 'uv', 'version = 1\n\n[[package]]\nname = "anyio"\nversion = "4.0.0"\ndependencies = [\n    { name = "starlette" },\n'],
    ["if (!m || !/^(?:@\\s*\\S+|", "if (!m || false && !/^(?:@\\s*\\S+|", 'requirements', 'https://example.com/starlette-0.46.2.whl\n'],
  ];
  for (const [from, to, kind, text] of cases) {
    assert.equal(lock(kind, text, R).read, false, `the real reader refuses: ${from.slice(0, 40)}`);
    const get = await mutatedLib(T.dir, 'lockfiles.mjs', from, to);
    const { checkLockfile: cl } = await get('lockfiles.mjs');
    const p = T.put(join(T.fresh('m'), kind === 'uv' ? 'uv.lock' : 'requirements.txt'), text);
    const r = cl({ path: p, kind }, R);
    assert.ok(r.read && !r.rows.some((x) => x.status !== 'SAFE'), `mutant survived: ${from.slice(0, 50)} (${JSON.stringify(r)})`);
  }
});

test('S3 the walk finds Python lockfiles by name, requirements*.txt in any case, and leaves npm\'s alone', () => {
  const root = T.fresh('walk');
  for (const f of ['a/uv.lock', 'b/poetry.lock', 'c/Pipfile.lock', 'd/requirements.txt', 'd/Requirements-Dev.txt', 'e/pylock.toml', 'f/package-lock.json', 'g/node_modules/x/requirements.txt']) T.put(join(root, f), 'x\n');
  const found = lockfilesUnder([root], LOCK_DEPTH, [], [], { deep: [], kindOf: pyLockKind }).map((f) => [f.path.slice(root.length + 1), f.kind]).sort();
  assert.deepEqual(found, [['a/uv.lock', 'uv'], ['b/poetry.lock', 'poetry'], ['c/Pipfile.lock', 'pipfile'], ['d/Requirements-Dev.txt', 'requirements'], ['d/requirements.txt', 'requirements'], ['e/pylock.toml', 'pylock']]);
  // the npm walk is unchanged
  assert.deepEqual(lockfilesUnder([root], LOCK_DEPTH, [], [], { deep: [] }).map((f) => f.kind), ['npm']);
  // a Mac's disk opens UV.LOCK for uv.lock
  if (MAC) { const m = T.fresh('case'); T.put(join(m, 'UV.LOCK'), 'x\n'); assert.deepEqual(lockfilesUnder([m], 2, [], [], { deep: [], kindOf: pyLockKind }).map((f) => f.kind), ['uv']); }
});

test('S4 the command: a project pinning Starlette 0.46.2 in uv.lock is EXPOSED (exit 1); pinning 1.0.1 SAFE, with the lockfile in the receipt', () => {
  const home = T.fresh('home'), bad = T.fresh('bad'), good = T.fresh('good');
  T.put(join(bad, 'app', 'uv.lock'), uv([['starlette', '0.46.2']]));
  T.put(join(good, 'app', 'uv.lock'), uv([['starlette', '1.0.1']]));
  const r1 = cli(['--incident', 'starlette-2026-06', '--paths', bad], { home, preload: [HIDE] });
  assert.equal(r1.code, 1, JSON.stringify(r1.rows));
  assert.ok(r1.rows.some((x) => x.status === 'EXPOSED' && x.path === join(bad, 'app', 'uv.lock') && x.version === '0.46.2'), JSON.stringify(r1.rows));
  const r2 = cli(['--incident', 'starlette-2026-06', '--paths', good], { home, preload: [HIDE] });
  assert.equal(r2.code, 0, JSON.stringify(r2.rows));
  assert.ok(r2.rows.some((x) => x.status === 'SAFE' && JSON.stringify(x.searched ?? []).includes(join(good, 'app', 'uv.lock'))), JSON.stringify(r2.rows));
});

// ---------------------------------------------------------------- MCP Python SDK and FastMCP (P9)

test('M1 the MCP SDK: below each fix EXPOSED; at or past it REVIEW naming validate_token_resource, never SAFE; before 1.8.0 no row', () => {
  const rows = (v) => checkSitePackages(MCP.sitePackages, [site([`mcp-${v}`])]);
  assert.deepEqual(rows('1.7.0'), []);
  for (const v of ['1.8.0', '1.10.0', '1.29.1', '2.0.0', '2.1.1']) assert.deepEqual(rows(v).map((r) => r.status), ['EXPOSED'], v);
  for (const v of ['1.30.0', '1.31.2', '2.2.0', '2.3.0']) {
    const [r] = rows(v);
    assert.equal(r.status, 'REVIEW', v); assert.match(r.reason, /validate_token_resource=True/); assert.match(r.reason, /Upgrading alone changes nothing/);
    assert.match(r.reviewFix, /validate_token_resource=True/);
  }
  // mcp-types is another package, not the SDK
  assert.deepEqual(checkSitePackages(MCP.sitePackages, [site(['mcp_types-2.1.0'])]), []);
});

test('M2 FastMCP and fastmcp-slim: 4.0.0 to 4.1.1 EXPOSED, 4.1.2 and later REVIEW naming issuer=, 3.x no row, a pre-release UNKNOWN', () => {
  const rows = (p) => checkSitePackages(MCP.sitePackages, [site([p])]).map((r) => [r.status, r.version]);
  assert.deepEqual(rows('fastmcp-3.9.1'), []);
  assert.deepEqual(rows('fastmcp-4.1.1'), [['EXPOSED', '4.1.1']]);
  assert.deepEqual(rows('fastmcp_slim-4.0.0'), [['EXPOSED', '4.0.0']]);
  assert.deepEqual(rows('fastmcp-4.0.0a1'), [['UNKNOWN', '4.0.0a1']]);
  const [r] = checkSitePackages(MCP.sitePackages, [site(['fastmcp-4.2.0'])]);
  assert.equal(r.status, 'REVIEW'); assert.match(r.reason, /issuer=/); assert.match(r.reason, /Upgrading alone is insufficient/);
  // the same in a lockfile
  const l = lock('uv', uv([['mcp', '2.2.0'], ['fastmcp', '4.1.1']]), MCP.pyLockfiles);
  assert.deepEqual(l.rows.map((x) => [x.name, x.status]).sort(), [['fastmcp', 'EXPOSED'], ['mcp', 'REVIEW']]);
});

test('M1m mutation proof: with P9 not applied, in the code or in the incident, the SDK at its fix reads SAFE', async () => {
  const get = await mutatedLib(T.dir, 'lockfiles.mjs', 'if (c && cmp(version, c.from) >= 0) return', 'if (false) return');
  const { judgePinned: jp } = await get('lockfiles.mjs');
  const d = MCP.sitePackages.distVersions[0];
  assert.equal(judgePinned('1.30.0', { name: d.product, ranges: d.ranges, source: d.source, fixNeedsConfig: d.fixNeedsConfig }).status, 'REVIEW');
  assert.equal(jp('1.30.0', { name: d.product, ranges: d.ranges, source: d.source, fixNeedsConfig: d.fixNeedsConfig }).status, 'SAFE', 'mutant survived: the P9 branch');
  const dropped = { ...MCP.sitePackages, distVersions: MCP.sitePackages.distVersions.map(({ fixNeedsConfig, ...x }) => x) };
  assert.deepEqual(checkSitePackages(dropped, [site(['mcp-2.2.0'])]), [], 'mutant survived: fixNeedsConfig dropped from the incident');
  // and every P9 package in the incident carries it, in both halves, with the setting named
  for (const p of [...MCP.sitePackages.distVersions, ...MCP.pyLockfiles.packages]) assert.match(p.fixNeedsConfig?.reason ?? '', /validate_token_resource|issuer=/, p.name);
});

// ---------------------------------------------------------------- Xcode

const plist = (v, build = '27B52') => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n\t<key>BuildVersion</key>\n\t<string>2</string>\n\t<key>CFBundleShortVersionString</key>\n\t<string>${v}</string>\n\t<key>ProductBuildVersion</key>\n\t<string>${build}</string>\n</dict>\n</plist>\n`;
/** A root with Xcode apps (name → version) and xcode-select's link to one of them (or none). */
function xroot(apps, selected) {
  const root = T.fresh('xc');
  for (const [name, v] of Object.entries(apps)) { T.put(join(root, 'Applications', name, 'Contents', 'version.plist'), plist(v)); mkdirSync(join(root, 'Applications', name, 'Contents', 'Developer'), { recursive: true }); }
  if (selected) { mkdirSync(join(root, 'var', 'db'), { recursive: true }); symlinkSync(join(root, 'Applications', selected, 'Contents', 'Developer'), join(root, 'var', 'db', 'xcode_select_link')); }
  return root;
}
const xrows = (root, v = XC.versionFiles) => checkVersionFiles(v, { root, os: 'darwin' }).map((r) => [r.status, r.version, r.path.slice(root.length)]);

test('X1 Xcode: below 27.2 EXPOSED, 27.2 SAFE, each app once even when xcode-select points to it; a beta REVIEW', () => {
  assert.deepEqual(xrows(xroot({ 'Xcode.app': '27.2' }, 'Xcode.app')), [['SAFE', '27.2', '/Applications/Xcode.app/Contents/version.plist']]);
  assert.deepEqual(xrows(xroot({ 'Xcode.app': '27.2', 'Xcode_26.4.app': '26.4' })).map((r) => r.slice(0, 2)).sort(), [['EXPOSED', '26.4'], ['SAFE', '27.2']]);
  // xcode-select pointing to an Xcode outside /Applications is read there
  const out = T.fresh('xout'); T.put(join(out, 'Dev', 'Xcode.app', 'Contents', 'version.plist'), plist('27.0')); mkdirSync(join(out, 'Dev', 'Xcode.app', 'Contents', 'Developer'), { recursive: true });
  mkdirSync(join(out, 'var', 'db'), { recursive: true }); symlinkSync(join(out, 'Dev', 'Xcode.app', 'Contents', 'Developer'), join(out, 'var', 'db', 'xcode_select_link'));
  assert.deepEqual(xrows(out).map((r) => r.slice(0, 2)), [['EXPOSED', '27.0']]);
  // a beta at the fixed number is not the release Apple's note names, reached by name or through xcode-select
  assert.deepEqual(xrows(xroot({ 'Xcode-beta.app': '27.3' })).map((r) => r[0]), ['REVIEW']);
  const lnk = xroot({ 'Xcode-beta.app': '27.2' }, 'Xcode-beta.app');
  assert.deepEqual(xrows(lnk).map((r) => r[0]), ['REVIEW']);
  assert.deepEqual(xrows(xroot({ 'Xcode-beta.app': '27.1' })).map((r) => r[0]), ['EXPOSED']);
  // the names as a Mac's disk matches them: xcode.app is Xcode*.app there
  if (MAC) assert.deepEqual(xrows(xroot({ 'xcode.app': '26.0' })).map((r) => r[0]), ['EXPOSED']);
  // a version.plist that can't be read is UNKNOWN
  if (process.getuid?.() !== 0) { const u = xroot({ 'Xcode.app': '27.2' }); const p = join(u, 'Applications', 'Xcode.app', 'Contents', 'version.plist'); chmodSync(p, 0o000); try { assert.deepEqual(xrows(u).map((r) => r[0]), ['UNKNOWN']); } finally { chmodSync(p, 0o644); } }
});

test('X1m mutation proof: without onceByRealPath one Xcode is two rows; without the beta rule a beta at 27.2 is SAFE', async () => {
  const root = xroot({ 'Xcode.app': '26.4' }, 'Xcode.app');
  assert.equal(xrows(root, { ...XC.versionFiles, onceByRealPath: false }).length, 2, 'mutant survived: one install, two rows');
  const beta = xroot({ 'Xcode-beta.app': '27.2' });
  assert.deepEqual(xrows(beta, { ...XC.versionFiles, files: XC.versionFiles.files.map(({ reviewIfRe, ...f }) => f) }).map((r) => r[0]), ['SAFE'], 'mutant survived: the beta rule');
  const get = await mutatedLib(T.dir, 'installs.mjs', "f.reviewIfRe.inPath ? realPathAsWritten(path) ?? path : text", 'text');
  const { checkVersionFiles: cvf } = await get('installs.mjs');
  assert.deepEqual(cvf(XC.versionFiles, { root: beta, os: 'darwin' }).map((r) => r.status), ['SAFE'], 'mutant survived: the beta read from the file\'s text');
});

// ---------------------------------------------------------------- Docker Desktop

const dplist = (v) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n\t<key>CFBundleShortVersionString</key>\n\t<string>${v}</string>\n\t<key>CFBundleVersion</key>\n\t<string>226246</string>\n</dict>\n</plist>\n`;
const LOG = '~/Library/Containers/com.docker.docker/Data/log';
/** A root with Docker.app at version `v` and log files (relative path → date, YYYY-MM-DD, or 'now'). */
function droot(v, logs = null) {
  const root = T.fresh('dd');
  T.put(join(root, 'Applications', 'Docker.app', 'Contents', 'Info.plist'), dplist(v));
  if (logs) {
    mkdirSync(`${root}${LOG}`, { recursive: true });
    for (const [f, day] of Object.entries(logs)) { const p = T.put(`${root}${LOG}/${f}`, 'a line that may hold a token\n'); if (day !== 'now') { const t = new Date(`${day}T12:00:00Z`); utimesSync(p, t, t); } }
  }
  return root;
}
const drows = (root, v = DD.versionFiles) => checkVersionFiles(v, { root, os: 'darwin' });

test('D1 Docker Desktop: below 4.97.0 EXPOSED; at 4.97.0 SAFE with no old log, REVIEW naming the folder when one is left, by name and date only', () => {
  assert.deepEqual(drows(droot('4.73.0')).map((r) => [r.status, r.version]), [['EXPOSED', '4.73.0']]);
  assert.deepEqual(drows(droot('4.96.3', { 'host/old.log': '2026-10-01' })).map((r) => r.status), ['EXPOSED']);
  // no log folder, or only files written after the update: SAFE, with the folder in the receipt
  const none = drows(droot('4.97.0'));
  assert.deepEqual(none.map((r) => r.status), ['SAFE']); assert.match(JSON.stringify(none[0].searched), /Data\/log: not there/);
  assert.deepEqual(drows(droot('4.97.0', { 'host/new.log': 'now' })).map((r) => r.status), ['SAFE']);
  // a file from before 4.97.0's release, written by 4.94 or 4.95 and left by the update
  const left = drows(droot('4.97.0', { 'vm/init.log': '2026-10-10', 'host/new.log': 'now' }));
  assert.deepEqual(left.map((r) => r.status), ['REVIEW']);
  assert.match(left[0].reason, /Data\/log still holds 1 file dated before .* \(the oldest 2026-10-10\)/); assert.match(left[0].reason, /rotate the third-party API keys/);
  // after 4.97.0's release but before this copy of Docker.app came to the disk: 4.96.x wrote it, so REVIEW too
  assert.deepEqual(drows(droot('4.98.1', { 'host/x.log': '2026-11-01' })).map((r) => r.status), ['REVIEW']);
  // the contents are never read: a log file no one may read is still judged by its date
  if (process.getuid?.() !== 0) {
    const r = droot('4.97.0', { 'host/locked.log': '2026-10-05' }); chmodSync(`${r}${LOG}/host/locked.log`, 0o000);
    assert.deepEqual(drows(r).map((x) => x.status), ['REVIEW']);
    // a log folder that can't be listed (macOS protects other apps' containers): UNKNOWN, never SAFE
    const c = droot('4.97.0', { 'host/a.log': 'now' }); chmodSync(`${c}${LOG}/host`, 0o000);
    try { const [u] = drows(c); assert.equal(u.status, 'UNKNOWN'); assert.match(u.reason, /could not be listed/); } finally { chmodSync(`${c}${LOG}/host`, 0o755); }
  }
});

test('D1m mutation proof: with the residue check dropped, in the code or the incident, logs left from 4.95 read SAFE', async () => {
  const root = droot('4.97.0', { 'host/old.log': '2026-10-12' });
  assert.deepEqual(drows(root, { ...DD.versionFiles, files: DD.versionFiles.files.map(({ residueWhenFixed, ...f }) => f) }).map((r) => r.status), ['SAFE'], 'mutant survived: residueWhenFixed dropped');
  const get = await mutatedLib(T.dir, 'installs.mjs', 'else if (t.mtimeMs < cutoff) old.push', 'else if (false) old.push');
  const { checkVersionFiles: cvf } = await get('installs.mjs');
  assert.deepEqual(cvf(DD.versionFiles, { root, os: 'darwin' }).map((r) => r.status), ['SAFE'], 'mutant survived: dates not compared');
  const get2 = await mutatedLib(T.dir, 'installs.mjs', "if (l.denied) return { status: 'UNKNOWN', reason: `${cfg.what} is at a version with the fix", "if (false) return { status: 'UNKNOWN', reason: `${cfg.what} is at a version with the fix");
  const { checkVersionFiles: cvf2 } = await get2('installs.mjs');
  if (process.getuid?.() !== 0) {
    const c = droot('4.97.0', { 'host/a.log': '2026-10-01' }); chmodSync(`${c}${LOG}/host`, 0o000);
    try { assert.deepEqual(cvf2(DD.versionFiles, { root: c, os: 'darwin' }).map((r) => r.status), ['SAFE'], 'mutant survived: a closed folder read as empty'); } finally { chmodSync(`${c}${LOG}/host`, 0o755); }
  }
});
