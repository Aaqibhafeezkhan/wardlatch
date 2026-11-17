// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// npm packages a project pins, read from its lockfile and nothing else: package-lock.json and npm-shrinkwrap.json
// (npm), yarn.lock (Yarn classic and Berry) and pnpm-lock.yaml (pnpm). From release/0.1.19-candidate, Python's too:
// uv.lock, poetry.lock, pylock.toml, Pipfile.lock and requirements*.txt (pyLockKind, for the incidents that ask). The file is read as text. Nothing in the project
// is run or imported, node_modules is not opened, and no registry is asked: a lockfile says what an install would
// fetch, which is what this reports, and all it reports.
//
// A lockfile that can't be read, or isn't one, or holds an entry this reader does not understand, is UNKNOWN for the
// whole file: a reader that skips what it can't parse reads a pinned package as absent (the shape of the 128
// certificates in, 1 decoded: a passing control beside an incomplete scan). So every parser here counts the entries
// it met and the entries it understood, and the two must agree.
import { join } from 'node:path';
import { readCapped, listDir, pathState, mayBeFolder, isSystemFolder, fileId, holdsMore, gapLists, walkedTo, unwalkedLinks, sameNameOnDisk } from './files.mjs';
import { cmp } from './binaries.mjs';
import { safe, saw } from './report.mjs';

// Folders this walk never enters, by name: a package's own files (node_modules holds the lockfiles of other people's
// packages, which pin nothing this project installs) and git's store. Said under every all-clear that rests on it.
export const NOT_WALKED = ['node_modules', '.git'];
// How deep the walk goes below each folder searched. Deeper than the other walks (4 or 5): a lockfile sits at a
// project's top, but a project's own folders run deep (src/app/components/…), and a floor at 5 would end almost every
// run on a developer's machine in "folders past the depth limit". A folder below the floor that holds more is still
// could-not-be-tested (holdsMore()).
export const LOCK_DEPTH = 10;
const MAX = 64 * 1024 * 1024;

/** Lockfile names → the reader for each. Bun's are found and named, never read: no reader for them here yet. */
export const LOCK_NAMES = { 'package-lock.json': 'npm', 'npm-shrinkwrap.json': 'npm', 'yarn.lock': 'yarn', 'pnpm-lock.yaml': 'pnpm', 'bun.lock': 'bun', 'bun.lockb': 'bun' };
/** The lockfile name (a key of LOCK_NAMES) that the entry `name` in `dir` is opened as, or null. */
export const lockNameOf = (dir, name) => (Object.hasOwn(LOCK_NAMES, name) ? name : Object.keys(LOCK_NAMES).find((k) => sameNameOnDisk(dir, name, k)) ?? null);
/** The reader for an npm-family lockfile named `name` in `dir`, or null (lockfilesUnder's default). */
export const npmLockKind = (dir, name) => { const l = lockNameOf(dir, name); return l ? LOCK_NAMES[l] : null; };

/** Python's lockfiles and pin files (release/0.1.19-candidate: Starlette, the MCP Python SDK, FastMCP): uv's, Poetry's,
 *  PEP 751's and Pipenv's, by name as the disk resolves it, and requirements files. A requirements file is any
 *  `requirements*.txt` (requirements.txt, requirements-dev.txt), matched in any case: pip reads the file it is given
 *  whatever its case, and on a Mac's disk the name a project wrote is the one it opens. */
export const PY_LOCK_NAMES = { 'uv.lock': 'uv', 'poetry.lock': 'poetry', 'pylock.toml': 'pylock', 'Pipfile.lock': 'pipfile' };
const REQUIREMENTS = /^requirements[^/]*\.txt$/i;
export const pyLockKind = (dir, name) => {
  if (REQUIREMENTS.test(name)) return 'requirements';
  const k = Object.hasOwn(PY_LOCK_NAMES, name) ? name : Object.keys(PY_LOCK_NAMES).find((n) => sameNameOnDisk(dir, name, n));
  return k ? PY_LOCK_NAMES[k] : null;
};
/** A Python package name as pip compares them (PEP 503): lower case, each run of -, _ and . one hyphen. */
export const pyName = (n) => String(n).toLowerCase().replace(/[-_.]+/g, '-');

/**
 * Every lockfile under `roots` → [{ path, kind }], kind as in LOCK_NAMES. Links to folders are recorded in `links`,
 * never followed; a folder that can't be opened goes to `denied`; a folder at the depth floor that holds more goes to
 * `deep`. An entry of a lockfile's name that is not a file this run can see as one (a folder is passed over; a link
 * that leads nowhere readable, a FIFO) is still returned, so the caller says UNKNOWN of it.
 */
export function lockfilesUnder(roots, maxDepth = LOCK_DEPTH, denied, links = denied, { deep, kindOf = npmLockKind } = {}) {
  // none of the gap lists is opt-in: one left out that the walk has something for makes it throw (lib/files.mjs gapLists())
  const gap = gapLists('lockfilesUnder()', { denied, links, deep });
  ({ denied, links, deep } = gap);
  const out = [];
  const listed = new Map(), maybeLinks = [];
  // One folder's lockfile once, and one closed folder once, however many of the roots lead to it: a folder given with
  // --paths inside another one (--paths ~/code --paths ~/code/app) was walked from both, and up to this fix each
  // lockfile under it was a row twice, so one pinned file counted as two exposed and "2 lockfiles read" (the
  // never-a-false-SAFE suite's e2, 16 Nov 2026). The key is the folder's identity on disk and the lockfile's name: a
  // second project whose lockfile is a link to the first one's is still a project of its own, and keeps its row.
  const once = new Set(), closed = new Set();
  const walk = (d, depth) => {
    const l = listDir(d);
    if (l.denied) { if (!closed.has(d)) { closed.add(d); denied?.push(d); } return; }
    walkedTo(listed, d, depth);
    const dirId = fileId(d) ?? d;
    for (const e of l.entries ?? []) {
      const p = join(d, e.name);
      // A lockfile by the name its package manager opens it by, as THIS disk resolves that name: npm opens
      // package-lock.json, and on a Mac's case-insensitive disk that is a file listed as Package-Lock.json (or with the
      // name in another Unicode form). Up to this fix the name was compared exactly, so that project's lockfile was
      // never read and a bad pin in it read SAFE while npm installed from it. On Linux the two names are two files,
      // and sameNameOnDisk says no (lib/files.mjs).
      // `kindOf` (release/0.1.19-candidate): which files are lockfiles; npm's family by default, Python's for the
      // incidents that read them (pyLockKind). Requirements files are several per folder, each its own file.
      const kind = kindOf(d, e.name);
      if (kind && !e.isDirectory() && pathState(p) !== 'dir') {
        const key = `${dirId}\0${e.name}`;
        if (!once.has(key)) { once.add(key); out.push({ path: p, kind }); }
        continue;
      }
      if (NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)) continue;
      if (e.isDirectory()) {
        // the floor: this folder's own files were listed above (a lockfile in it is found); the folders in it are not opened
        if (depth === 0) continue;
        walk(p, depth - 1);
        continue;
      }
      // a link to a folder is recorded, never followed: a project behind one would be passed over in silence otherwise
      if (e.isSymbolicLink() && mayBeFolder(p)) maybeLinks.push({ path: p, need: depth - 1 });
    }
    if (depth === 0 && deep && !deep.includes(d) && holdsMore(d, NOT_WALKED)) deep.push(d);
  };
  // one folder, one walk, however many names lead to it (lib/wordpress.mjs, AUDIT-25)
  const walked = new Set();
  for (const r of roots) {
    const id = fileId(r);
    if (id && walked.has(id)) continue;
    if (id) walked.add(id);
    walk(r, maxDepth);
  }
  if (links) links.push(...unwalkedLinks(maybeLinks, listed).map((c) => c.path));
  gap.done();
  return out;
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/** The package a spec names: "react@^19.0.0" → react, "@scope/x@npm:1.0.0" → @scope/x; null when it names none. */
const specName = (spec) => { const at = spec.indexOf('@', 1); return at > 0 ? spec.slice(0, at) : null; };
/** The package an npm: alias spec installs: "rsdw@npm:react-server-dom-webpack@^19.0.0" → react-server-dom-webpack;
 *  null for any other spec ("x@npm:^1.0.0", Berry's way of writing a plain range, names no other package). */
const aliasTarget = (spec) => { const n = specName(spec), rest = n ? spec.slice(n.length + 1) : ''; return rest.startsWith('npm:') ? specName(rest.slice(4)) : null; };

/** npm's lockfile (lockfileVersion 1, 2 or 3) → { pins: [{ name, version }], entries } or { error }. */
function readNpm(text, names) {
  let j;
  try { j = JSON.parse(text); } catch { return { error: 'is not valid JSON, so it could not be read as an npm lockfile' }; }
  if (!isObj(j) || !Number.isInteger(j.lockfileVersion) || j.lockfileVersion < 1 || j.lockfileVersion > 3) return { error: 'is not an npm lockfile this check reads (lockfileVersion 1, 2 or 3)' };
  const pins = []; let entries = 0;
  if (j.packages !== undefined) {
    // lockfileVersion 2 and 3: one entry per installed path; the name is the entry's own (an alias) or the path's end
    if (!isObj(j.packages)) return { error: 'is an npm lockfile whose packages list could not be read' };
    for (const [key, e] of Object.entries(j.packages)) {
      if (key === '') continue;
      entries++;
      if (!isObj(e)) return { error: `is an npm lockfile with an entry that could not be read (${key.slice(0, 80)})` };
      if (e.link === true) continue;   // a workspace link: the package it points at has an entry of its own
      const at = key.includes('node_modules/') ? key.slice(key.lastIndexOf('node_modules/') + 13) : null;
      const name = typeof e.name === 'string' ? e.name : at;
      if (name && names.includes(name)) pins.push({ name, version: typeof e.version === 'string' ? e.version : '' });
      // a listed name installed from another package ("react-server-dom-webpack": "npm:@acme/fork@1.0.0"): loading
      // that name loads the other package, whose version says nothing about the listed one (the attack branch, A7)
      if (at && name !== at && names.includes(at)) pins.push({ name: at, version: '' });
    }
    return { pins, entries };
  }
  // lockfileVersion 2 without a packages list is not what npm writes: its dependencies tree is a copy kept for old npms
  if (j.lockfileVersion !== 1) return { error: 'is an npm lockfile with no packages list' };
  if (j.dependencies !== undefined && !isObj(j.dependencies)) return { error: 'is an npm lockfile whose dependencies could not be read' };
  let bad = null;
  const tree = (deps) => {
    for (const [key, e] of Object.entries(deps ?? {})) {
      entries++;
      if (!isObj(e)) { bad ??= key; continue; }
      // an alias: "version": "npm:real-name@1.2.3"
      const alias = typeof e.version === 'string' && e.version.startsWith('npm:') ? e.version.slice(4) : null;
      const name = alias ? specName(alias) : key;
      const version = alias ? alias.slice((name ?? '').length + 1) : e.version;
      if (name && names.includes(name)) pins.push({ name, version: typeof version === 'string' ? version : '' });
      if (name !== key && names.includes(key)) pins.push({ name: key, version: '' });
      if (e.dependencies !== undefined) { if (isObj(e.dependencies)) tree(e.dependencies); else bad ??= key; }
    }
  };
  tree(j.dependencies);
  return bad ? { error: `is an npm lockfile with an entry that could not be read (${bad.slice(0, 80)})` } : { pins, entries };
}

// A line cut short. A lockfile whose write stopped part way (a full disk, a killed install, a copy cut off) ends inside a
// quoted string or a { } mapping, which the package manager's own parser refuses; up to this fix the readers below took
// such a line as whole, so a file cut inside an earlier entry, with the affected pin after the cut, read as pinning
// nothing: SAFE, where yarn and pnpm would not install from it at all (the never-a-false-SAFE suite's b1, 16 Nov 2026:
// a yarn.lock cut inside `resolved "https://…` and a pnpm-lock.yaml cut inside `{integrity: sha512-…`). A cut at the
// end of a line leaves a shorter file that is valid, and nothing can tell it from one; that is not claimed here.
/** Whether `line` leaves a `q` quote open: yarn quotes with " only, and writes no escaped quote inside one. */
const leftOpen = (line, q) => (line.split(q).length - 1) % 2 === 1;
/** Whether a line of YAML as pnpm writes it closes every quoted scalar and every { } and [ ] mapping or list it opens. A
 *  quote, { or [ opens one only where a value can start (the line's start, or after `:`, `-`, `?`, `{`, `[` or `,`):
 *  elsewhere it is a character of plain text ("It's", "use {x}"). '' inside '…' and \x inside "…" are escapes; a # after
 *  a space outside them starts a comment. */
function closedYaml(line) {
  let depth = 0, q = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q === '\'') { if (ch === '\'') { if (line[i + 1] === '\'') i++; else q = null; } continue; }
    if (q === '"') { if (ch === '\\') i++; else if (ch === '"') q = null; continue; }
    const starts = () => { const before = line.slice(0, i).trimEnd(); return !before || /[:{[,?-]$/.test(before); };
    if ((ch === '\'' || ch === '"') && starts()) { q = ch; continue; }
    if (ch === '#' && /\s/.test(line[i - 1] ?? ' ')) break;
    if ((ch === '{' || ch === '[') && (depth > 0 || starts())) depth++;
    else if ((ch === '}' || ch === ']') && depth > 0) depth--;
  }
  return q === null && depth === 0;
}

/** yarn.lock, classic (v1) or Berry → { pins, entries } or { error }. An entry is a block: a line at the left margin
 *  ending in a colon that lists the specs it answers, then indented lines, one of them the version. */
function readYarn(text, names) {
  const classic = /^# yarn lockfile v1\s*$/m.test(text), berry = /^__metadata:\s*$/m.test(text);
  if (!classic && !berry) return { error: 'is not a yarn.lock this check reads (neither Yarn 1\'s header nor Yarn 2+\'s __metadata)' };
  const pins = []; let entries = 0, block = null, bad = null;
  const close = () => {
    if (!block) return;
    // the package a block installs: the one its resolution names (an alias's real package), else the one an npm: spec
    // names ("rsdw@npm:react-server-dom-webpack@19.0.0", which classic yarn keeps when `resolved` names no registry
    // path: up to the attack branch of 16 Nov 2026, A7, that alias pinned nothing), else the names its specs carry
    const real = block.resolution ?? block.targets.find(Boolean) ?? null;
    for (const name of new Set(real ? [real] : block.names)) if (names.includes(name)) pins.push({ name, version: block.version ?? '' });
    // a listed name the block installs another package under (react-server-dom-webpack@npm:@acme/fork@1.0.0): what
    // loads under that name is the other package, and its version says nothing about the listed one
    if (real) for (const n of block.names) if (n !== real && names.includes(n)) pins.push({ name: n, version: '' });
    block = null;
  };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim() || line.startsWith('#')) continue;
    if (leftOpen(line, '"')) { bad ??= line; continue; }
    if (!/^\s/.test(line)) {
      close();
      if (!line.endsWith(':')) { bad ??= line; continue; }
      if (line === '__metadata:') { block = { names: [], targets: [], meta: true }; continue; }
      entries++;
      // a key in either YAML quote, as Berry's parser reads one; up to A7 only " was taken off, and a '…' key named nothing
      const specs = line.slice(0, -1).split(',').map((s) => s.trim().replace(/^(["'])(.*)\1$/, '$2').trim()).filter(Boolean);
      const got = specs.map(specName);
      if (!specs.length || got.includes(null)) { bad ??= line; continue; }
      block = { names: got, targets: specs.map(aliasTarget) };
      continue;
    }
    if (!block) { bad ??= line; continue; }
    // "  version "1.2.3"" (classic) or "  version: 1.2.3" (Berry); Berry's "  resolution: "name@npm:1.2.3""; classic's
    // "  resolved "https://registry…/name/-/name-1.2.3.tgz#…"", which names the real package behind an alias
    const v = /^ {2}version:? "?([^"\s]+)"?\s*$/.exec(line);
    if (v && !block.meta) block.version = v[1];
    const r = /^ {2}resolution: "?((?:@[^/@\s]+\/)?[^/@\s]+)@/.exec(line);
    if (r && !block.meta) block.resolution = r[1];
    // the registry path before /-/ ends in the package's name, with its scope before it when it has one: taken from the
    // end, so "@acme/react-server-dom-webpack" is not read as the package it merely ends in
    const u = /^ {2}resolved "[a-z]+:\/\/[^/"]+\/([^"]*?)\/-\/[^/"]+\.tgz/.exec(line);
    if (u && !block.meta) { const parts = u[1].split('/'); block.resolution = parts.at(-2)?.startsWith('@') ? `${parts.at(-2)}/${parts.at(-1)}` : parts.at(-1); }
  }
  close();
  return bad ? { error: `is a yarn.lock with a line this check could not read (${bad.slice(0, 80)})` } : { pins, entries };
}

/** pnpm-lock.yaml → { pins, entries } or { error }. The packages (and, from lockfileVersion 9, snapshots) sections hold
 *  one key per installed package: name@1.2.3, /name@1.2.3(peers), or /name/1.2.3_peers in old lockfiles. */
function readPnpm(text, names) {
  if (!/^lockfileVersion:/m.test(text)) return { error: 'is not a pnpm lockfile (no lockfileVersion)' };
  const pins = new Map(); let entries = 0, section = null, bad = null, keyed = false;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim() || /^\s*#/.test(line)) continue;
    if (!closedYaml(line)) { bad ??= line; continue; }
    const top = /^([A-Za-z][\w-]*):(.*)$/.exec(line);
    // Lines this reader would otherwise pass over without understanding them (the attack branch of 16 Nov 2026, A8), each
    // of which pnpm's YAML parser reads: a top-level key it can't name ('packages':), a packages or snapshots section
    // written inline (packages: {…}), and an entry indented other than two spaces (a file re-indented to four). Up to
    // this fix each read as a lockfile that pins nothing: SAFE.
    if (!/^\s/.test(line) && !top && !/^(?:---|\.\.\.)\s*$/.test(line)) { bad ??= line; continue; }
    if (top) { section = top[1]; keyed = false; if (/^(?:packages|snapshots)$/.test(section) && !/^\s*(?:\{\s*\})?\s*(?:#.*)?$/.test(top[2])) bad ??= line; continue; }
    if (section !== 'packages' && section !== 'snapshots') continue;
    // an entry's key: indented two spaces exactly; what is deeper belongs to the entry before it, and there must be one
    if (!/^ {2}\S/.test(line)) { if (!keyed) bad ??= line; continue; }
    keyed = true;
    entries++;
    // the key: quoted, or plain up to the colon that ends it (a plain key may hold a colon that no space follows)
    const body = line.slice(2), q = body[0] === '\'' || body[0] === '"' ? body.indexOf(body[0], 1) : -1;
    const key = q > 0 ? (/^:(?:\s|$)/.test(body.slice(q + 1)) ? body.slice(1, q) : null) : (/^(.*?):(?:\s|$)/.exec(body)?.[1] ?? null);
    const id = (key ?? '').replace(/^\//, '').replace(/\(.*$/, '');
    const m = /^((?:@[^/@]+\/)?[^/@]+)[@/](.+)$/.exec(id);
    if (!m) { bad ??= line; continue; }
    const name = m[1], version = m[2].split('_')[0];
    if (names.includes(name)) pins.set(`${name}@${version}`, { name, version });
    // the oldest lockfiles put the registry's host in front (registry.npmjs.org/name/1.2.3), so the name read above is
    // the host: a listed package behind one is here, and its version is not taken from a key this reader half reads
    const hosted = /^[^/@]+\.[^/@]+\/((?:@[^/@]+\/)?[^/@]+)\//.exec(id)?.[1];
    if (hosted && names.includes(hosted)) pins.set(`${hosted}@`, { name: hosted, version: '' });
  }
  return bad ? { error: `is a pnpm lockfile with an entry this check could not read (${bad.trim().slice(0, 80)})` } : { pins: [...pins.values()], entries };
}

// ---- Python (release/0.1.19-candidate). Each reader counts the entries it met and the ones it understood, as above,
// and a file cut short is an error, never a shorter list: a pin past the cut would otherwise read as absent.

/** TOML lockfiles that list packages as an array of tables (`[[package]]` in uv.lock and poetry.lock, `[[packages]]`
 *  in pylock.toml), each with `name = "…"` and `version = "…"` among its top-level keys. Only those two keys are
 *  read; sub-tables ([package.dependencies], [[package.wheels]]) belong to the entry and are passed over. */
function readTomlPackages(text, names, { table, what, marker }) {
  if (!marker.test(text)) return { error: `is not ${what} (it has no ${marker.source.replace(/\\/g, '')} line)` };
  if (!text.endsWith('\n')) return { error: `is ${what} that ends part way through a line (it may have been cut short)` };
  const want = new Set(names.map(pyName));
  const head = new RegExp(`^\\[\\[\\s*${table}\\s*\\]\\]\\s*(?:#.*)?$`);
  const pins = []; let entries = 0, cur = null, sub = false, open = 0, bad = null;
  const finish = () => {
    if (!cur) return;
    if (!cur.name) { bad ??= 'an entry with no name'; return; }
    if (want.has(pyName(cur.name))) pins.push({ name: pyName(cur.name), version: cur.version ?? '' });
  };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    // a value spread over lines ([ … ]): its lines are not keys, and the file must close every one it opens
    if (open) { if (/^\]/.test(line)) open--; else if (/=\s*\[\s*$/.test(line)) open++; continue; }
    if (!line || line.startsWith('#')) continue;
    if (head.test(line)) { finish(); cur = { name: null, version: null }; sub = false; entries++; continue; }
    if (line.startsWith('[')) {
      // a sub-table of this entry, or a table after the list ([metadata], [manifest]) that ends it
      if (cur && new RegExp(`^\\[\\[?\\s*${table}\\.`).test(line)) sub = true;
      else { finish(); cur = null; sub = false; }
      continue;
    }
    if (/=\s*\[\s*(?:#.*)?$/.test(line)) { open++; continue; }
    if (!cur || sub) continue;
    const m = /^(name|version)\s*=\s*(?:"([^"\\]*)"|'([^']*)')\s*(?:#.*)?$/.exec(line);
    if (m) cur[m[1]] = m[2] ?? m[3];
    else if (/^(name|version)\s*=/.test(line)) bad ??= line;   // a name or version this reader can't read
  }
  if (open) return { error: `is ${what} with a list that is never closed (it may have been cut short)` };
  finish();
  return bad ? { error: `is ${what} with an entry this check could not read (${bad.slice(0, 80)})` } : { pins, entries };
}
const readUv = (text, names) => readTomlPackages(text, names, { table: 'package', what: 'a uv lockfile', marker: /^version\s*=\s*\d+\s*$/m });
const readPoetry = (text, names) => readTomlPackages(text, names, { table: 'package', what: 'a Poetry lockfile', marker: /^\[metadata\]\s*$/m });
const readPylock = (text, names) => readTomlPackages(text, names, { table: 'packages', what: 'a pylock.toml', marker: /^lock-version\s*=\s*"[^"]+"\s*$/m });

/** Pipenv's Pipfile.lock: JSON, `default` and `develop` maps of name → { version: "==1.2.3" }. A package named there
 *  without "==<version>" (a git or path install) is pinned to no version this check can judge. */
function readPipfile(text, names) {
  let j;
  try { j = JSON.parse(text); } catch { return { error: 'is not valid JSON, so it could not be read as a Pipfile.lock' }; }
  if (!isObj(j) || !isObj(j._meta)) return { error: 'is not a Pipfile.lock (it has no _meta)' };
  const want = new Set(names.map(pyName));
  const pins = []; let entries = 0;
  for (const section of ['default', 'develop']) {
    if (j[section] === undefined) continue;
    if (!isObj(j[section])) return { error: `is a Pipfile.lock whose ${section} section could not be read` };
    for (const [name, e] of Object.entries(j[section])) {
      entries++;
      if (!want.has(pyName(name))) continue;
      const v = isObj(e) && typeof e.version === 'string' ? (/^===?\s*(\S+)$/.exec(e.version) ?? [])[1] : undefined;
      pins.push({ name: pyName(name), version: v ?? '', ...(v ? {} : { note: `${name} is in this Pipfile.lock with no "==<version>" (${isObj(e) ? Object.keys(e).filter((k) => k !== 'hashes').join(', ') || 'nothing' : 'not an entry'}), so the version it installs could not be read` }) });
    }
  }
  return { pins, entries };
}

/** A pip requirements file. One requirement per line (a trailing \ joins lines), comments after " #". A line naming a
 *  package looked for counts only with one exact pin (==1.2.3 or ===1.2.3); a range, a URL or no version at all names
 *  the package without saying what is installed, so it is pinned to no version (UNKNOWN, with why). A line this reader
 *  can't read, and an include (-r, -c) of a file that is not itself a requirements*.txt beside it, make the whole file
 *  UNKNOWN: what the include pins was not read. */
function readRequirements(text, names) {
  const want = new Set(names.map(pyName));
  const pins = []; let entries = 0, bad = null;
  const logical = text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const raw of logical) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;
    const inc = /^(?:-r|--requirement|-c|--constraint)(?:\s+|=)(\S+)/.exec(line);
    if (inc) { if (!REQUIREMENTS.test(inc[1].split('/').pop()) || inc[1].includes('/')) bad ??= `it includes ${inc[1]}, which this check does not read`; continue; }
    if (/^-e\s|^--editable[\s=]/.test(line)) {
      const egg = (/[#&]egg=([A-Za-z0-9._-]+)/.exec(line) ?? [])[1];
      if (!egg) { bad ??= `an editable install whose package is not named (${line.slice(0, 60)})`; continue; }
      entries++;
      if (want.has(pyName(egg))) pins.push({ name: pyName(egg), version: '', note: `${egg} is installed from a folder or repository here (${line.slice(0, 80)}), not a release, so its version could not be read` });
      continue;
    }
    if (/^-/.test(line)) continue;                                   // an option line (--index-url, --hash, -i …)
    // a name, its extras, then nothing but a version specifier, `@ <url>`, a marker after ";" and --hash options. A bare
    // URL or path (https://…/pkg.whl, ./pkg) names no package this reader can see: the whole file is UNKNOWN. Up to the
    // sweep's own test, "https://example.com/pkg.whl" read as a package named https, and the file as read.
    const m = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$/.exec(line);
    const tail = m ? m[3].replace(/(^|\s)--hash[=\s]\S+/g, ' ').trim() : '';
    if (!m || !/^(?:@\s*\S+|(?:===?|!=|<=|>=|~=|<|>)[^;@]*)?\s*(?:;.*)?$/.test(tail)) { bad ??= line.slice(0, 60); continue; }
    entries++;
    if (!want.has(pyName(m[1]))) continue;
    const rest = tail.split(';')[0].trim();
    const exact = /^===?\s*([^\s,;*]+)$/.exec(rest);
    pins.push({ name: pyName(m[1]), version: exact ? exact[1] : '', ...(exact ? {} : { note: `${m[1]} is named here as "${line.split(/\s--hash/)[0].slice(0, 80)}", ${rest ? 'a range or a URL, not one version' : 'with no version'}: what pip installs from it depends on when it runs and what the index holds, so it could not be judged` }) });
  }
  return bad ? { error: `is a requirements file with a line this check could not read: ${bad}` } : { pins, entries };
}

const READERS = { npm: readNpm, yarn: readYarn, pnpm: readPnpm, uv: readUv, poetry: readPoetry, pylock: readPylock, pipfile: readPipfile, requirements: readRequirements };

/** The pinned versions of the packages `names` in a lockfile's text → { pins: [{ name, version }], entries } with each
 *  name and version once, or { error } when the text is not a lockfile of that kind read to its end. */
export function pinnedIn(kind, text, names) {
  const r = READERS[kind]?.(text, names);
  if (!r) return { error: 'is a lockfile this check has no reader for' };
  if (r.error) return r;
  const once = new Map(r.pins.map((p) => [`${p.name}@${p.version}`, p]));
  return { pins: [...once.values()], entries: r.entries };
}

/**
 * A pinned version against a package's rule: { name, ranges: [{ introduced, fixed } | { introduced, lastAffected,
 * fixed }], source, fix }. Only a plain release (1.2.3) is judged: the advisories name releases, and a canary,
 * experimental or pre-release build, a tarball or a git commit is none of them. Judging "0.0.0-experimental-…" by its
 * number would read a build of last week as older than every affected version: SAFE, from a number that says nothing.
 * `searched`: the receipt a SAFE carries (lib/report.mjs safe(), the one place a SAFE is made): the lockfile and the
 * pin, from checkLockfile(); the pin alone when a caller has only that.
 * → { status: 'EXPOSED' | 'SAFE' | 'UNKNOWN', reason }
 */
export function judgePinned(version, rule, searched = [saw(`${rule.name} ${version}`)], note = '') {
  if (!/^\d+\.\d+\.\d+$/.test(String(version))) {
    return { status: 'UNKNOWN', reason: note || (version ? `${rule.name} is pinned to ${version}, which is not a plain release (a canary, experimental or pre-release build, or a file or repository): ${rule.source} names releases only, so it could not be judged` : `${rule.name} is in this lockfile with no version that could be read`) };
  }
  for (const r of rule.ranges) {
    const upTo = r.lastAffected !== undefined ? cmp(version, r.lastAffected) <= 0 : cmp(version, r.fixed) < 0;
    if (cmp(version, r.introduced) >= 0 && upTo) return { status: 'EXPOSED', reason: `${rule.name} ${version} is in the affected range ${r.introduced} to ${r.lastAffected ?? `before ${r.fixed}`} (${rule.source}); fixed in ${r.fixed}` };
  }
  // `fixNeedsConfig` (release/0.1.19-candidate, pattern P9: the fixed version is not the fixed state). The vendor's fix
  // is a setting that is off until someone turns it on (the MCP Python SDK's validate_token_resource, FastMCP's issuer),
  // so a version at or past it is REVIEW, naming the setting, never SAFE: Wardlatch does not read the code that would
  // set it. Below `from` the version was never affected, and that is SAFE as before.
  const c = rule.fixNeedsConfig;
  if (c && cmp(version, c.from) >= 0) return { status: 'REVIEW', reason: `${rule.name} ${version} has the fix, but ${c.reason}` };
  return safe(searched, { reason: `${rule.name} ${version} is in none of the affected ranges (${rule.ranges.map((r) => `${r.introduced} to ${r.lastAffected ?? `before ${r.fixed}`}`).join(', ')}; ${rule.source})` });
}

/**
 * One lockfile against an incident's rule: { packages: [{ name, ranges, source, fix }], bunNote }.
 * → { read, rows: [{ status, what, name?, version?, reason, fix?, searched? }] }. `read`: the file was read to its end
 * as a lockfile (so "pins none of the packages" is a statement about all of it). A row per package and version pinned;
 * none when the file was read and pins none of them (the caller's all-clear names the file).
 */
export function checkLockfile({ path, kind }, rule) {
  const unknown = (reason) => ({ read: false, rows: [{ status: 'UNKNOWN', what: 'lockfile', reason }] });
  if (kind === 'bun') return unknown(rule.bunNote ?? 'is Bun\'s lockfile, which this check does not read');
  const state = pathState(path);
  if (state !== 'file') return unknown(state === 'denied' ? 'found, but it could not be read (permission denied, or a link this run could not follow)' : 'found, but it is not a file (a link that leads nowhere, or a device), so it was not read');
  const buf = readCapped(path, MAX);
  if (!buf) return unknown('found, but it could not be read (or is larger than 64 MB)');
  const names = rule.packages.map((p) => p.name);
  const got = pinnedIn(kind, buf.toString('utf8'), names);
  if (got.error) return unknown(`${got.error}, so what it pins is not known`);
  // a Python file's pins carry PEP 503 names (pyName), and the rule's are compared the same way
  const py = Object.values(PY_LOCK_NAMES).includes(kind) || kind === 'requirements';
  const rows = got.pins.map(({ name, version, note }) => {
    const pkg = rule.packages.find((p) => (py ? pyName(p.name) === name : p.name === name));
    const what = `${name} ${version || '(no version)'}`;
    const r = judgePinned(version, pkg, [path, saw(what)], note);
    return { name, version, what, ...r, ...(r.status === 'EXPOSED' ? { fix: pkg.fix } : r.status === 'REVIEW' && pkg.reviewFix ? { fix: pkg.reviewFix } : {}) };
  });
  return { read: true, rows };
}
