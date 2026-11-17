// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// NEVER A FALSE SAFE, part 2 of 3: differential oracles. For each judgement Wardlatch makes about the real system, the
// operating system is asked for its own answer, and a disagreement fails the test:
//   O1 which file a name opens: the inode the disk gives a package manager's own lockfile name, against the lockfiles
//      Wardlatch's walk reads (generated trees: names in other cases and Unicode forms, links, folders of one name);
//   O2 which library a program loads: dyld (DYLD_PRINT_LIBRARIES) or ld.so (ldd), for programs this test compiles with
//      @rpath / @loader_path or $ORIGIN, against the library Wardlatch judged and the verdict it gave;
//   O3 which certificates a bundle holds: LibreSSL or OpenSSL's own reading of a CA file (crl2pkcs7), against
//      Wardlatch's (lib/macos.mjs bundleHolds), for bundles built in every shape a reader can trip on;
//   O4 which program PATH runs: `command -v` in /bin/sh with a clean environment, against lib/binaries.mjs findOnPath;
//   O5 whether Apple's trust layer accepts the 12 eMudhra test chains: SecTrustEvaluateWithError (a Swift helper,
//      offline), against the Safari and Apple apps row lib/probe.mjs check makes from nscurl's answers.
// Then R, the real-machine agreement pass: the same questions about this machine's own PATH programs, cert.pem (and
// certifi's bundle) and system keychain, read only. It REPORTS differences (as test diagnostics) and never fails, since
// a developer's machine is not a fixture. Om plants a mutation for each oracle and requires it to fail.
import '../support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync, symlinkSync, chmodSync, readFileSync, copyFileSync, realpathSync, existsSync, readdirSync, statSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import { join, delimiter } from 'node:path';
import { property, holds, scratch, inode, variant, mutatedLib, realLib, incident, todo, MAC, ROOT, RUNS } from './support.mjs';

const T = scratch('oracle');
after(() => T.done());
const has = (cmd) => spawnSync('/bin/sh', ['-c', `command -v ${cmd}`], { encoding: 'utf8' }).status === 0;
const load = async (get) => ({ files: await get('files.mjs'), lockfiles: await get('lockfiles.mjs'), binaries: await get('binaries.mjs'), brotli: await get('brotli.mjs'), macos: await get('macos.mjs'), probe: await get('probe.mjs') });
const REAL = await load(realLib);

// ---------------------------------------------------------------- O1 which file a name opens

const LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'];
/** A tree of folders whose entries are lockfiles under their own names, other spellings, lookalikes, links to lockfiles,
 *  and folders of a lockfile's name. → its root. */
function lockTree(g) {
  const root = T.fresh('o1');
  const dirs = [root];
  for (let i = 0; i < 2 + g.int(5); i++) { const d = join(g.pick(dirs), variant(g, g.pick(['app', 'café', 'Svc', 'web', 'straße']))); try { mkdirSync(d, { recursive: true }); dirs.push(d); } catch { /* a file of that name */ } }
  for (let i = 0; i < 3 + g.int(8); i++) {
    const d = g.pick(dirs), n = variant(g, g.pick(LOCKS)), p = join(d, g.chance(0.1) ? `${n}${g.pick(['.', ' ', '.bak'])}` : n);
    try {
      if (g.chance(0.15)) mkdirSync(p);
      else if (g.chance(0.15)) symlinkSync(join(g.pick(dirs), g.pick(LOCKS)), p);
      else writeFileSync(p, '{}');
    } catch { /* that spelling is already there, as a file or folder */ }
  }
  return { root, dirs };
}
/** The OS's answer: for every folder, the file each package manager opens by its lockfile's own name (a regular file,
 *  through links), as folder inode | file inode. */
const osLocks = (dirs) => {
  const out = new Set();
  for (const d of new Set(dirs.map((x) => realpathSync(x)))) for (const n of LOCKS) {
    const p = join(d, n);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isFile()) out.add(`${inode(d)}|${inode(p)}`);
  }
  return out;
};
const o1 = (L) => property('O1 lockfile names, the disk\'s answer', (g) => {
  const { root, dirs } = lockTree(g);
  const found = L.lockfiles.lockfilesUnder([root], 10, [], [], { deep: [] });
  // Wardlatch's answer: the files it would read (a found entry that is not a file is its UNKNOWN row, not a read)
  const ward = new Set(found.filter((f) => { try { return statSync(f.path).isFile(); } catch { return false; } }).map((f) => `${inode(join(f.path, '..'))}|${inode(f.path)}`));
  const os = osLocks(dirs);
  const missed = [...os].filter((k) => !ward.has(k)), extra = [...ward].filter((k) => !os.has(k));
  if (missed.length || extra.length) {
    const named = (k) => found.find((f) => `${inode(join(f.path, '..'))}|${inode(f.path)}` === k)?.path.slice(root.length) ?? k;
    return { missed: missed.length, extra: extra.map(named), listing: dirs.map((d) => [d.slice(root.length) || '/', readdirSync(d)]) };
  }
  return null;
});
test('O1 which file a name opens: Wardlatch reads exactly the files the disk opens under the lockfile names', () => holds(o1(REAL)));

// ---------------------------------------------------------------- O2 which library a program loads

const BROTLI = incident('brotli-2026-10'), M = BROTLI.markers;
const CC = has('cc') ? 'cc' : has('gcc') ? 'gcc' : null;
const LINUX_LDD = process.platform === 'linux' && has('ldd');
const o2skip = !CC ? 'no C compiler (cc or gcc) on this machine' : !MAC && !LINUX_LDD ? 'neither macOS (dyld) nor Linux with ldd' : false;
const libSrc = (fixed) => `const char *brotli_errs[] = { "_SUCCESS", "${M.table}", ${fixed ? `"${M.fixed}", ` : ''}"_ERROR_UNREACHABLE" };\nconst char *brotli_err(int i) { return brotli_errs[i]; }\n`;
let built = null;
/** The two libraries (one without the fix, one with it), compiled once. */
function libs() {
  if (built) return built;
  const b = T.fresh('o2-build');
  writeFileSync(join(b, 'old.c'), libSrc(false)); writeFileSync(join(b, 'new.c'), libSrc(true));
  writeFileSync(join(b, 'main.c'), 'const char *brotli_err(int);\n#include <stdio.h>\nint main(void){ puts(brotli_err(1)); return 0; }\n');
  const lib = MAC ? 'libbrotlidec.1.dylib' : 'libbrotlidec.so.1';
  for (const v of ['old', 'new']) {
    mkdirSync(join(b, v));
    execFileSync(CC, MAC ? ['-dynamiclib', '-o', join(b, v, lib), '-install_name', `@rpath/${lib}`, join(b, `${v}.c`)] : ['-shared', '-fPIC', '-o', join(b, v, lib), `-Wl,-soname,${lib}`, join(b, `${v}.c`)], { stdio: 'pipe' });
  }
  built = { b, lib };
  return built;
}
/** What the system loader loads for `prog`: the library's real path, or null when it loads none of that name. */
function loaderSays(prog, lib) {
  if (MAC) {
    const r = spawnSync(prog, [], { env: { DYLD_PRINT_LIBRARIES: '1' }, encoding: 'utf8' });
    const hit = r.stderr.split('\n').map((l) => /^dyld\[\d+\]: (?:<[0-9A-F-]+> )?(\/.*)$/.exec(l)?.[1]).find((p) => p?.endsWith(`/${lib}`));
    return hit ? realpathSync(hit) : null;
  }
  const r = spawnSync('ldd', [prog], { encoding: 'utf8' });
  const hit = new RegExp(`^\\s*${lib.replace(/\./g, '\\.')} => (\\/\\S+)`, 'm').exec(r.stdout)?.[1];
  return hit ? realpathSync(hit) : null;
}
const o2 = (L) => property('O2 the library a program loads', (g) => {
  const { b, lib } = libs();
  const d = T.fresh('o2');
  // one library of each kind most often, so the loader's choice between them is what is tested
  const first = g.pick(['old', 'new']);
  const places = g.chance(0.7) ? { a: first, b: first === 'old' ? 'new' : 'old' } : { a: g.pick(['old', 'new', null]), b: g.pick(['old', 'new', null]) };
  for (const [k, v] of Object.entries(places)) { mkdirSync(join(d, k, 'lib'), { recursive: true }); if (v) copyFileSync(join(b, v, lib), join(d, k, 'lib', lib)); }
  mkdirSync(join(d, 'app', 'bin'), { recursive: true });
  const order = g.shuffle(['missing', 'a', 'b']).slice(0, 1 + g.int(3));
  const prog = join(d, 'app', 'bin', 'prog');
  const at = MAC ? '@loader_path' : '$ORIGIN';
  execFileSync(CC, ['-o', prog, join(b, 'main.c'), join(b, 'old', lib), ...order.map((o) => `-Wl,-rpath,${at}/../../${o}/lib`), ...(MAC ? [] : ['-Wl,--enable-new-dtags'])], { stdio: 'pipe' });
  const loads = loaderSays(prog, lib);
  const r = L.brotli.judgeFile(prog, { markers: M, sonameDirs: [] });
  const truth = loads === null ? null : places[loads.split('/').at(-3)] === 'new' ? 'SAFE' : 'EXPOSED';
  const where = { rpaths: order, places, loaderLoads: loads?.slice(d.length) ?? 'none', wardlatch: r.status, via: r.via?.slice(d.length) };
  // a verdict is the loaded library's: SAFE or EXPOSED must be what that file holds (or UNKNOWN, which claims nothing)
  if (r.status === 'SAFE' || r.status === 'EXPOSED') {
    if (truth === null) return { ...where, why: 'a verdict on a library the loader does not find' };
    if (r.status !== truth) return { ...where, truth, why: 'the verdict is not that of the library the loader loads' };
    // `via` names the library (a universal file's builds each name theirs, joined by ", ")
    const real = (p) => { try { return realpathSync(p); } catch { return p; } };
    if (r.via && String(r.via).split(', ').some((p) => real(p) !== loads)) return { ...where, why: 'the library named is not the one the loader loads' };
  }
  return null;
}, { runs: Math.min(RUNS, 12) });
test('O2 which library a program loads: dyld\'s or ld.so\'s choice is the one Wardlatch judges, or it says UNKNOWN', { skip: o2skip }, () => holds(o2(REAL)));

// ---------------------------------------------------------------- O3 which certificates a bundle holds

const EM = incident('emudhra-2026-10');
const OPENSSL = has('openssl') ? 'openssl' : null;
const blocks = (text) => text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
const ROOTS = blocks(readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10-roots.pem'), 'utf8'));
const OTHER = blocks(readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'macos-27.2.1-cert.pem'), 'utf8'));
const WANT = new Map([...(EM.distrustedRoots ?? []), ...(EM.withdrawnKeys ?? [])].map((k) => [String(k.spkiSha256).toLowerCase(), k.name]));
const spkiOf = (pem) => createHash('sha256').update(new X509Certificate(pem).publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
/** What OpenSSL (or LibreSSL) loads from a CA file: the names of the withdrawn keys among them, and how many in all; null
 *  when it refuses the file. */
function opensslHolds(file) {
  const p7 = spawnSync(OPENSSL, ['crl2pkcs7', '-nocrl', '-certfile', file], { encoding: 'buffer' });
  if (p7.status !== 0) return null;
  const out = spawnSync(OPENSSL, ['pkcs7', '-print_certs'], { input: p7.stdout, encoding: 'utf8' });
  if (out.status !== 0) return null;
  const certs = blocks(out.stdout);
  return { count: certs.length, held: [...new Set(certs.map(spkiOf).filter((s) => WANT.has(s)).map((s) => WANT.get(s)))].sort() };
}
/** A bundle in a shape a reader can trip on. */
function bundle(g) {
  let parts = g.shuffle([...g.shuffle(OTHER).slice(0, 1 + g.int(6)), ...(g.chance(0.7) ? g.shuffle(ROOTS).slice(0, 1 + g.int(2)) : [])]);
  if (g.chance(0.2)) parts.push(g.pick(parts));                                          // a duplicate
  parts = parts.map((p) => (g.chance(0.1) ? p.replace('BEGIN CERTIFICATE', 'BEGIN TRUSTED CERTIFICATE').replace('END CERTIFICATE', 'END TRUSTED CERTIFICATE') : p));
  let text = parts.map((p) => `${g.chance(0.3) ? `# ${g.pick(['Issuer', 'Subject', 'Label'])}: x\n` : ''}${p}\n${g.chance(0.2) ? '\n\n' : ''}`).join('');
  if (g.chance(0.2)) text = text.replace(/\n/g, '\r\n');                                 // Windows line ends
  if (g.chance(0.1)) text += '-----BEGIN CERTIFICATE-----\nMIIB\n';                      // a block cut short
  if (g.chance(0.1)) text = text.replace(/-----END CERTIFICATE-----\r?\n-----BEGIN/, '-----END CERTIFICATE----------BEGIN');
  return text;
}
const o3 = (L) => property('O3 the certificates a bundle holds', (g) => {
  const text = bundle(g), f = join(T.fresh('o3'), 'ca.pem');
  writeFileSync(f, text);
  const os = opensslHolds(f);
  if (!os) return null;   // the library refuses the file: nothing it trusts from it to compare
  const w = L.macos.bundleHolds(text, EM);
  // a bundle Wardlatch calls fully read must not lack a withdrawn key the TLS library loads from it
  const missed = os.held.filter((n) => !w.held.includes(n));
  if (missed.length && w.unreadable === 0) return { missed, openssl: os, wardlatch: w, shape: text.slice(0, 200) };
  if (w.unreadable === 0 && w.read !== os.count) return { why: 'fully read, but not the count the TLS library loads', openssl: os.count, wardlatch: w };
  return null;
}, { runs: Math.min(RUNS, 40) });
test('O3 which certificates a bundle holds: Wardlatch never calls a bundle fully read while missing a withdrawn key OpenSSL loads from it', { skip: !OPENSSL && 'no openssl on this machine' }, () => holds(o3(REAL)));

// ---------------------------------------------------------------- O4 which program PATH runs

/** `command -v <name>` in /bin/sh with nothing but this PATH: the program a shell runs, or null. */
const shellRuns = (n, pathEnv) => { const r = spawnSync('/bin/sh', ['-c', `command -v "$0"`, n], { env: { PATH: pathEnv }, encoding: 'utf8' }); const o = r.stdout.trim(); return r.status === 0 && o.startsWith('/') ? o : null; };
const SHAPES = ['program', 'script', 'not executable', 'a folder', 'a link to a program', 'a link to nothing', 'executable, unreadable', 'another case'];
function pathDirs(g, n, shapes) {
  const dirs = [];
  for (let i = 0; i < 1 + g.int(4); i++) {
    const d = T.fresh('o4'), shape = g.pick(shapes);
    dirs.push(d);
    const p = join(d, shape === 'another case' ? variant(g, n) : n);
    try {
      if (shape === 'program') copyFileSync('/bin/echo', p);
      else if (shape === 'script' || shape === 'another case') writeFileSync(p, '#!/bin/sh\necho 1\n', { mode: 0o755 });
      else if (shape === 'not executable') writeFileSync(p, '#!/bin/sh\necho 1\n', { mode: 0o644 });
      else if (shape === 'a folder') mkdirSync(p);
      else if (shape === 'a link to a program') symlinkSync('/bin/echo', p);
      else if (shape === 'a link to nothing') symlinkSync(join(d, 'gone'), p);
      else if (shape === 'executable, unreadable') { writeFileSync(p, '#!/bin/sh\n', { mode: 0o755 }); chmodSync(p, 0o111); }
    } catch { /* that spelling is there */ }
    if (g.chance(0.2)) dirs.push(d);   // a folder twice on PATH
  }
  return dirs;
}
const o4 = (L, shapes = SHAPES) => property(`O4 the program PATH runs (${shapes.length} shapes)`, (g) => {
  const n = g.pick(['php', 'node', 'curl']), dirs = pathDirs(g, n, shapes), P = dirs.join(delimiter);
  const sh = shellRuns(n, P), ward = L.binaries.findOnPath(n, P) ?? null;
  const same = sh === ward || (sh && ward && inode(sh) === inode(ward) && realpathSync(join(sh, '..')) === realpathSync(join(ward, '..')));
  return same ? null : { name: n, shell: sh?.slice(T.dir.length) ?? null, wardlatch: ward?.slice(T.dir.length) ?? null, path: dirs.map((d) => [d.slice(T.dir.length), readdirSync(d).map((e) => { try { return `${e} ${(statSync(join(d, e)).mode & 0o777).toString(8)}`; } catch { return `${e} (dangling)`; } })]) };
});
const O4_PASSING = SHAPES.filter((s) => s !== 'not executable');
test('O4 which program PATH runs: findOnPath names the file `command -v` names', todo('O4 PATH non-executable'), () => holds(o4(REAL)));
test('O4x which program PATH runs, every shape but a file the shell cannot execute: findOnPath agrees with the shell', () => holds(o4(REAL, O4_PASSING)));

// ---------------------------------------------------------------- O5 the Safari and Apple apps row: Apple's trust layer
//
// The row for macOS's own trust layer (lib/probe.mjs check, kind macos-system) is SAFE when nscurl refuses every test
// host. The oracle: Apple's Security framework itself (SecTrustEvaluateWithError, test/support/sectrust.swift), given
// each of the 12 test hosts' chains as they were served on 16 Nov 2026 (test/support/fixtures/sectrust/), offline (no
// network fetch: the answer is what this Mac holds, its trust store and Apple's valid.sqlite) and as of that day. Each
// answer is played to check() through a stand-in nscurl that prints what nscurl prints for it; the row must agree with
// the OS, host by host: any chain the OS trusts makes the row EXPOSED. Controls: github.com's chain must evaluate true
// and revoked.badssl.com's false, or the instrument can't tell the two apart and the test fails. macOS only; skipped,
// with the reason, where swiftc is missing. A Mac that never fetched Apple's valid.sqlite update would trust the chains
// here, and this test would then require EXPOSED: the live nscurl probe is what catches that on a person's Mac.
const SECTRUST_DIR = join(ROOT, 'test', 'support', 'fixtures', 'sectrust');
const SECTRUST_DATE = '2026-11-16T12:00:00Z';
const EMU = incident('emudhra-2026-10');
const swiftWhy = !MAC ? 'Apple\'s Security framework is on a Mac only' : !has('swiftc') ? 'swiftc is not installed (Xcode or the Command Line Tools), so the OS oracle cannot be built' : '';
let sectrustBin = null;
/** The OS's answer for one saved chain: true (trusted), false (refused). Throws when it could not evaluate. */
function osTrusts(host) {
  if (!sectrustBin) {
    sectrustBin = join(T.fresh('sectrust'), 'sectrust');
    execFileSync('swiftc', ['-O', '-o', sectrustBin, join(ROOT, 'test', 'support', 'sectrust.swift')], { stdio: 'pipe', timeout: 300000 });
  }
  const r = spawnSync(sectrustBin, [host, 'offline', join(SECTRUST_DIR, `${host}.pem`)], { encoding: 'utf8', env: { SECTRUST_VERIFY_DATE: SECTRUST_DATE, PATH: '/usr/bin:/bin' }, timeout: 60000 });
  if (r.status === 0 && /SecTrustEvaluateWithError: true/.test(r.stdout)) return true;
  if (r.status === 1 && /SecTrustEvaluateWithError: false/.test(r.stdout)) return false;
  throw new Error(`sectrust could not evaluate ${host} (exit ${r.status}): ${r.stdout}${r.stderr}`);
}
/** A stand-in nscurl: for each URL, what nscurl prints when Apple's trust layer accepts it (the page, nothing on stderr)
 *  or refuses it ("Load failed" with NSURLErrorDomain -1202 on stderr, nscurl's refusal). Anything else loads. */
function fakeNscurl(refusedHosts) {
  const p = join(T.fresh('nscurl'), 'nscurl');
  const cases = refusedHosts.map((h) => `  "https://${h}/") echo 'Load failed with error: Error Domain=NSURLErrorDomain Code=-1202 "The certificate for this server is invalid."' >&2 ;;`).join('\n');
  writeFileSync(p, `#!/bin/sh\ncase "$1" in\n${cases}\n  *) echo '<html>ok</html>' ;;\nesac\nexit 0\n`, { mode: 0o755 });
  return p;
}
const emuCanaries = () => EMU.canaries.map((id) => {
  const host = EMU.canaryHost.replace('{id}', id);
  return { id, host, url: `https://${host}/`, root: EMU.canaryRoots.find((x) => x.canaries.includes(id))?.root, up: true };
});
/** O5 for a probe module: → null when the row agrees with the OS on every host, else the disagreement. `answers`: the
 *  OS's answer per host (true trusted), so a planted answer can show the instrument can differ. */
async function o5(probeMod, answers) {
  const canaries = emuCanaries();
  const refused = canaries.filter((c) => !answers[c.host]).map((c) => c.host);
  const trusted = canaries.filter((c) => answers[c.host]).map((c) => c.id).sort();
  const rt = { kind: 'macos-system', bin: fakeNscurl(refused), label: 'macOS system (Safari and Apple apps)' };
  const r = await probeMod.check(rt, canaries, { controlUrl: EMU.advisory, timeoutMs: 5000, systemNote: EMU.systemSafeNote });
  const want = trusted.length ? 'EXPOSED' : 'SAFE';
  const got = [...(r.trusted ?? [])].sort();
  if (r.status !== want || got.join() !== trusted.join()) return { want, got: r.status, osTrusts: trusted, wardlatchTrusted: got, reason: r.reason };
  if (want === 'SAFE' && !/refused all 12 test hosts through Apple's trust layer; Apple blocks the 12 certificates through valid\.apple\.com/.test(r.note ?? '')) return { note: r.note ?? null };
  return null;
}
let O5_ANSWERS = null;
const o5Answers = () => (O5_ANSWERS ??= Object.fromEntries(emuCanaries().map((c) => [c.host, osTrusts(c.host)])));
test('O5 the Safari and Apple apps row agrees with Apple\'s own trust evaluation of the 12 test chains (offline, as of 16 Nov 2026): a chain it trusts is EXPOSED', { skip: swiftWhy || false }, async (t) => {
  // the instrument can differ: a chain Apple trusts and one it refuses
  assert.equal(osTrusts('github.com'), true, 'control: github.com\'s chain must evaluate true');
  assert.equal(osTrusts('revoked.badssl.com'), false, 'control: revoked.badssl.com\'s chain must evaluate false');
  const answers = o5Answers();
  t.diagnostic(`OS trusts ${Object.values(answers).filter(Boolean).length} of ${Object.keys(answers).length} test chains on this Mac`);
  assert.equal(await o5(REAL.probe, answers), null);
  // and the row follows the OS when it does trust one: a Mac without Apple's block, played as one host the OS accepts
  const one = { ...answers, [emuCanaries()[0].host]: true };
  assert.equal(await o5(REAL.probe, one), null, 'one trusted chain: the row is EXPOSED, naming that host');
});
test('O5m mutation proof: nscurl\'s output always read as a load that worked turns O5 red', { skip: swiftWhy || false }, async () => {
  const get = await mutatedLib(T.dir, 'probe.mjs', "export const nscurlOk = (text) => !/Load failed|NSURLErrorDomain|error/i.test(text);", 'export const nscurlOk = (text) => true;');
  const answers = o5Answers();
  assert.ok(Object.values(answers).some((x) => !x), 'O5m needs at least one chain the OS refuses');
  assert.notEqual(await o5(await get('probe.mjs'), answers), null, 'mutant survived: O5 with nscurlOk always true');
});

// ---------------------------------------------------------------- R the real machine, read only: reported, never failed

test('R real-machine agreement pass (read-only; reports differences, never fails)', (t) => {
  const said = [];
  // PATH: this machine's PATH as the tests were started with it (no-real-home.cjs has taken the home folder's out)
  for (const n of ['node', 'python3', 'curl', 'git', 'php', 'openssl', 'deno', 'terraform', 'bun']) {
    const sh = shellRuns(n, process.env.PATH ?? ''), ward = REAL.binaries.findOnPath(n, process.env.PATH ?? '') ?? null;
    if (sh !== ward) said.push(`PATH ${n}: the shell runs ${sh ?? 'nothing'}, Wardlatch names ${ward ?? 'nothing'}`);
  }
  // CA files: the TLS library's reading against Wardlatch's
  const bundles = ['/etc/ssl/cert.pem', '/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt'].filter((f) => existsSync(f));
  const py = has('python3') ? spawnSync('python3', ['-I', '-m', 'certifi'], { encoding: 'utf8' }) : null;
  if (py?.status === 0 && py.stdout.trim().startsWith('/')) bundles.push(py.stdout.trim());
  for (const f of OPENSSL ? bundles : []) {
    let text; try { text = readFileSync(f, 'utf8'); } catch { said.push(`${f}: could not be read here`); continue; }
    const os = opensslHolds(f), w = REAL.macos.bundleHolds(text, EM);
    if (!os) { said.push(`${f}: OpenSSL refused it; Wardlatch read ${w.read}, ${w.unreadable} unreadable`); continue; }
    if (os.count !== w.read || os.held.join() !== [...w.held].sort().join() || w.unreadable) said.push(`${f}: OpenSSL loads ${os.count} (withdrawn: ${os.held.join(', ') || 'none'}); Wardlatch read ${w.read}, ${w.unreadable} unreadable (withdrawn: ${w.held.join(', ') || 'none'})`);
    else t.diagnostic(`${f}: ${os.count} certificates, OpenSSL and Wardlatch agree (withdrawn held: ${os.held.join(', ') || 'none'})`);
  }
  // macOS: the system keychain's roots, beside what Wardlatch takes Apple's fix to have done on this version
  if (MAC && has('security')) {
    const r = spawnSync('security', ['find-certificate', '-a', '-p', '/System/Library/Keychains/SystemRootCertificates.keychain'], { encoding: 'utf8' });
    const certs = blocks(r.stdout ?? '');
    const held = [...new Set(certs.map((c) => { try { return spkiOf(c); } catch { return null; } }).filter((s) => WANT.has(s)).map((s) => WANT.get(s)))];
    const rel = REAL.macos.readMacosRelease();
    const state = REAL.macos.appleFixState(rel.version, EM.appleFix.releases);
    t.diagnostic(`macOS ${rel.version} (${rel.build}): Apple's fix state as Wardlatch reads it: ${state}; SystemRootCertificates holds ${certs.length} roots, withdrawn among them: ${held.join(', ') || 'none'}`);
    if (state === 'fixed' && held.length) said.push(`the system keychain still holds ${held.join(', ')} on a release Wardlatch takes to have Apple's fix (Apple's fix blocks them in the command-line tools and cert.pem; the keychain's own trust settings are not read here)`);
  }
  for (const s of said) t.diagnostic(`DIFFERENCE: ${s}`);
  if (!said.length) t.diagnostic('no differences between the OS and Wardlatch on this machine');
});

// ---------------------------------------------------------------- Om the planted mutations

test('Om mutation proof: each oracle fails on a planted mutation of lib/', async () => {
  const plant = async (file, from, to) => load(await mutatedLib(T.dir, file, from, to));
  const caught = [];
  const red = async (label, r) => { assert.notEqual(await r, null, `mutant survived: ${label}`); caught.push(label); };
  await red('O1: links to lockfiles passed over', o1(await plant('lockfiles.mjs', "if (kind && !e.isDirectory() && pathState(p) !== 'dir') {", "if (kind && !e.isDirectory() && !e.isSymbolicLink() && pathState(p) !== 'dir') {")));
  if (!o2skip) await red('O2: a mix of fixed and unfixed candidates taken as fixed', o2(await plant('brotli.mjs', "if (!bad.length) return { all: 'fixed', libs };", "if (!bad.length || good.length) return { all: 'fixed', libs };")));
  if (OPENSSL) await red('O3: the first withdrawn key in a bundle not counted', o3(await plant('macos.mjs', '    read++;\n    if (want.has(spki)) held.add(want.get(spki));', '    read++;\n    if (want.has(spki) && read > 1) held.add(want.get(spki));')));
  await red('O4x: the last copy on PATH taken as the first', o4(await plant('binaries.mjs', 'if (!seen.has(real)) { seen.add(real); out.push(p); }', 'if (!seen.has(real)) { seen.add(real); out.unshift(p); }'), O4_PASSING));
  assert.ok(caught.length >= 2, caught.join('\n'));
});
