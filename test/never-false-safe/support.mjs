// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Shared by the never-a-false-SAFE suite (test/never-false-safe/*.test.mjs; docs in each file's head). Home-made, with no
// dependency: a seeded generator, a property runner that prints the seed and the counterexample, the test's own temp
// folder, the disk asked what it opens, a clock and a listing order the test controls, a file swapped between a stat
// and an open, the command run on a stand-in home, and a copy of lib/ with one planted mutation.
//   NFS_SEED  the seed (default 0x5afe0001); a failure prints the one to set to see it again
//   NFS_RUNS  how many generated cases each property tries (default 120; CI may raise it)
import { mkdtempSync, mkdirSync, rmSync, realpathSync, writeFileSync, readFileSync, statSync, cpSync } from 'node:fs';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { spawnSync, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
export const HERE = dirname(fileURLToPath(import.meta.url));
export const SEED = Number.parseInt(process.env.NFS_SEED ?? String(0x5afe0001), 10) >>> 0;
export const RUNS = Math.max(1, Number.parseInt(process.env.NFS_RUNS ?? '120', 10) || 120);
export const MAC = process.platform === 'darwin';
export const incident = (id) => JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', `${id}.json`), 'utf8'));

/** xorshift32, as test/cmp-properties.test.mjs: next() in [0, 1), and the helpers built on it. */
export function gen(seed) {
  let s = (seed >>> 0) || 1;
  const next = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 0x100000000; };
  const int = (n) => Math.floor(next() * n);
  const pick = (a) => a[int(a.length)];
  const shuffle = (a) => { const b = [...a]; for (let i = b.length - 1; i > 0; i--) { const j = int(i + 1); [b[i], b[j]] = [b[j], b[i]]; } return b; };
  return { next, int, pick, shuffle, chance: (p) => next() < p };
}

/**
 * A property: `fn(g, i)` is called RUNS times with a generator seeded from SEED and the property's name, and returns
 * null when the case holds or a counterexample (any value). The first counterexample fails the test with the seed to
 * set and the case, so a failure can be seen again by hand. → null, or the message (for a mutation proof).
 */
export function property(name, fn, { runs = RUNS, seed = SEED } = {}) {
  let h = seed; for (const ch of name) h = (Math.imul(h ^ ch.codePointAt(0), 0x01000193) >>> 0);
  for (let i = 0; i < runs; i++) {
    const g = gen((h + Math.imul(i + 1, 0x9e3779b9)) >>> 0);
    const ce = fn(g, i);
    if (ce !== null && ce !== undefined) return `${name}: counterexample at NFS_SEED=${seed} case ${i}: ${typeof ce === 'string' ? ce : JSON.stringify(ce)}`;
  }
  return null;
}
export const holds = (msg) => assert.equal(msg, null, msg ?? '');

// ---- the test's own folder, by its real path (macOS reaches the temp folder through /var, a link to /private/var)
export function scratch(tag) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), `wardlatch-nfs-${tag}-`)));
  let n = 0;
  return {
    dir,
    fresh: (name = 'd') => { const d = join(dir, `${name}-${++n}`); mkdirSync(d, { recursive: true }); return d; },
    put: (p, text, mode) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text, mode === undefined ? undefined : { mode }); return p; },
    // folders and files a test closed (chmod 000) are opened again first, or the removal stops at them
    done: () => { try { execFileSync('chmod', ['-R', 'u+rwX', dir], { stdio: 'ignore' }); } catch { /* some were links, or gone */ } rmSync(dir, { recursive: true, force: true }); },
  };
}

/** The file the disk opens for a path, as dev:ino, or null when it opens none. */
export const inode = (p) => { try { const s = statSync(p, { bigint: true }); return `${s.dev}:${s.ino}`; } catch { return null; } };
/** Whether the disk under `dir` opens the name `b` as the file named `a` (`a` is made, `b` is asked for). */
export function diskOpensAs(dir, a, b) {
  const d = mkdtempSync(join(dir, 'probe-'));
  try { writeFileSync(join(d, a), 'x'); } catch { return null; }
  const same = inode(join(d, b)) === inode(join(d, a));
  rmSync(d, { recursive: true, force: true });
  return same;
}

// ---- names: the spellings a disk may open as one file
const SWAPS = [['k', 'K'], ['K', 'K'], ['s', 'ſ'], ['S', 'ſ'], ['ss', 'ß'], ['ss', 'ẞ'], ['fi', 'ﬁ'], ['ff', 'ﬀ'], ['fl', 'ﬂ'], ['st', 'ﬆ'], ['i', 'ı'], ['I', 'İ'], ['a', 'а'], ['o', 'о'], ['e', 'е'], ['A', 'Ａ']];
/** A variant of `name`: its case flipped here and there, a letter swapped for one a disk may fold to it (or a lookalike it
 *  does not), its composed letters decomposed or the other way. The disk decides which are the same file. */
export function variant(g, name) {
  let v = [...name].map((ch) => (g.chance(0.4) ? (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()) : ch)).join('');
  if (g.chance(0.5)) { const [from, to] = g.pick(SWAPS); const at = v.indexOf(from); if (at >= 0) v = v.slice(0, at) + to + v.slice(at + from.length); }
  if (g.chance(0.3)) v = v.normalize(g.pick(['NFC', 'NFD']));
  // a single upper-casing can grow a name (ß to SS, ŉ to ʼN); keep it a name the disk takes
  return v.includes('/') || v.includes('\0') ? name : v;
}
export const ALPHABET = [...'abcdefghijklmnopqrstuvwxyzABCKSZ019-._', 'ß', 'ẞ', 'ﬁ', 'ﬀ', 'ſ', 'K', 'ı', 'İ', 'σ', 'ς', 'Σ', 'é', 'é', 'ö', 'Å', '‍', 'Ａ', '²', 'ǅ', 'ŉ', 'ﬆ'];
export const name = (g, min = 1, max = 10) => { let s = ''; const n = min + g.int(max - min + 1); for (let i = 0; i < n; i++) s += g.pick(ALPHABET); return s === '.' || s === '..' ? `${s}x` : s; };

// ---- a clock the test sets (every Date.now() and new Date() in this process, until it is put back)
export function withClock(ms, fn) {
  const Real = globalThis.Date;
  class Fixed extends Real { constructor(...a) { if (a.length) super(...a); else super(ms); } static now() { return ms; } }
  globalThis.Date = Fixed;
  try { return fn(); } finally { globalThis.Date = Real; }
}

/** fs patched for the length of `fn` (named imports of node:fs in lib/ see it: syncBuiltinESMExports). */
export function withFs(patch, fn) {
  const saved = {};
  for (const [k, make] of Object.entries(patch)) { saved[k] = fs[k]; fs[k] = make(saved[k]); }
  syncBuiltinESMExports();
  const back = () => { Object.assign(fs, saved); syncBuiltinESMExports(); };
  let r;
  try { r = fn(); } catch (e) { back(); throw e; }
  if (r && typeof r.then === 'function') return r.finally(back);
  back();
  return r;
}
/** Every folder listing in the order a generator chooses: a disk promises no order, and no verdict may depend on one. */
export const shuffledListings = (g) => ({
  readdirSync: (o) => function (p, ...rest) { const r = o.call(this, p, ...rest); return Array.isArray(r) ? g.shuffle(r) : r; },
});
/** The file at `target` is changed by `swap()` after it is first stat()ed and before it is opened: the window between a
 *  read of its kind and a read of its bytes. */
export function swapAfterStat(target, swap) {
  let statted = false, done = false;
  const at = (p) => String(p) === target;
  return {
    statSync: (o) => function (p, ...rest) { const r = o.call(this, p, ...rest); if (at(p)) statted = true; return r; },
    openSync: (o) => function (p, ...rest) { if (at(p) && statted && !done) { done = true; swap(); } return o.call(this, p, ...rest); },
  };
}

// ---- the command on a stand-in home
/**
 * Runs bin/wardlatch.mjs with HOME at `home`, PATH /usr/bin:/bin unless given, from `cwd`. `preload`: files given to
 * node --require (this suite's clock.cjs). `bin`: the command to run (a mutated copy, for a mutation proof).
 * → { code, rows (with --json), text, stderr }.
 */
export function cli(args, { home, cwd = home, env = {}, json = true, preload = [], bin = BIN } = {}) {
  const r = spawnSync(process.execPath, [...preload.flatMap((p) => ['--require', p]), bin, ...args, ...(json ? ['--json'] : [])], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, cwd, timeout: 180000,
    env: { HOME: home, PATH: '/usr/bin:/bin', LANG: 'C', ...(process.env.NODE_OPTIONS ? { NODE_OPTIONS: process.env.NODE_OPTIONS } : {}), ...env },
  });
  if (!json) return { code: r.status, text: r.stdout, stderr: r.stderr };
  let out; try { out = JSON.parse(r.stdout); } catch { assert.fail(`not JSON (exit ${r.status}): ${String(r.stderr).slice(0, 800)}`); }
  return { code: r.status, rows: out.results, json: out, stderr: r.stderr };
}
export const statuses = (rows) => rows.map((r) => r.status);
export const countOf = (rows) => { const c = { SAFE: 0, EXPOSED: 0, UNKNOWN: 0, REVIEW: 0 }; for (const r of rows) if (r.status in c) c[r.status]++; return c; };

// ---- planted mutations: lib/ copied, one piece of text replaced, the copy's modules imported
/** → (module) => the module from the mutated copy. Fails when the text to replace is not in the file. */
export async function mutatedLib(tmp, file, from, to) {
  const copy = mkdtempSync(join(tmp, 'mut-'));
  cpSync(join(ROOT, 'lib'), join(copy, 'lib'), { recursive: true });
  const p = join(copy, 'lib', file), src = readFileSync(p, 'utf8');
  assert.ok(src.includes(from), `the planted mutation's text is in lib/${file}: ${from}`);
  writeFileSync(p, src.replace(from, to));
  return (m) => import(pathToFileURL(join(copy, 'lib', m)).href);
}
export const realLib = (m) => import(pathToFileURL(join(ROOT, 'lib', m)).href);

/** Tests that FAIL today, each with the reason and the branch whose landing is to turn it green. Run as node:test todo
 *  tests: a todo that fails is reported and does not fail the run; one that passes is reported too, so it is noticed.
 *  release/0.1.19-candidate: c2, c3, H11, H12 (fix/no-stale-safe's lib), b4d (lib/installs.mjs) and H9b
 *  (deno-2026-06 reads mise's and asdf's program) are real tests now, each with a planted mutation that turns it red;
 *  so is A3t (Homebrew's keg judged by its program's bytes, the constant measured on Deno's release builds, D8). */
export const KNOWN_FAILING = {
  'O4 PATH non-executable': 'lib/binaries.mjs findAllOnPath takes the first regular file of the name on PATH, executable or not; the shell skips a file it cannot execute. With a mode 644 php first on PATH, Wardlatch names that file as the one that runs and the shell runs the next one. No SAFE comes of it today (the next copy is still run or reported not run), so it is left for the owner',
  'A7t pnpm alias': 'lib/lockfiles.mjs readPnpm reads only the packages and snapshots sections; a dependency installed under a listed name from another package is named only in importers (and in its dependents\' snapshots), so it pins nothing and reads SAFE. Reading importers is a new parser for a section of another shape; left for the owner',
};
export const todo = (key) => ({ todo: `KNOWN-FAILING: ${KNOWN_FAILING[key]}` });
