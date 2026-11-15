// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18 (claude-code-2026-11): which Claude Code installs are on this machine and which version each one is, read
// from files only. `claude --version` would run the program, so it is never asked:
//   - the native installer: ~/.local/bin/claude is a link to ~/.local/share/claude/versions/<version>, so the link's
//     target names the copy that runs, and every other file in versions/ is a copy left behind;
//   - npm: <prefix>/lib/node_modules/@anthropic-ai/claude-code/package.json, its "version";
//   - Homebrew's cask: the folder names under Caskroom/claude-code;
//   - editor extensions: anthropic.claude-code-<version>-<platform> folders (lib/iocs.mjs extensionFolders).
// The advisory (GHSA-5xjx-9qx6-jcrv) names the npm package and macOS. A copy below the fix that runs (the one the link
// names, an npm or cask install) is EXPOSED on a Mac; a copy left beside it, or an editor extension's own copy, is
// REVIEW; a link that can't be read is UNKNOWN. Off a Mac the flaw does not apply, and a SAFE row says why.
import { join, basename, isAbsolute, dirname } from 'node:path';
import { readCapped, listDir, pathState, readLink } from './files.mjs';
import { expand } from './installs.mjs';
import { extensionFolders } from './iocs.mjs';
import { cmp } from './binaries.mjs';
import { safe, saw } from './report.mjs';

const VERSION = /^\d+\.\d+\.\d+$/;

/**
 * rule: the incident's `claudeCode` ({ fixed, alsoBelow?, link, versionsDir, npmPackages: [patterns], casks: [patterns],
 * extensionName, editors }). → { rows: [{ status, what, path, version, reason }], searched: [places read] }
 */
export function checkClaudeCode(rule, { home, os = process.platform }) {
  const rows = [], searched = [];
  const at = (p) => p.replace(/^~(?=\/|$)/, home);
  const mac = os === 'darwin';
  const also = (v) => (rule.alsoBelow && cmp(v, rule.alsoBelow.version) < 0 ? `; it is also below ${rule.alsoBelow.version}, ${rule.alsoBelow.note}` : '');
  // one copy that runs: EXPOSED below the fix on a Mac; SAFE at or past it, or off a Mac (with why)
  const runs = (what, path, v) => {
    if (cmp(v, rule.fixed) >= 0) { rows.push(safe([path, saw(`version ${v}`)], { what, path, version: v, reason: `version ${v} is at or past ${rule.fixed}, the fix for CVE-2026-88968${also(v)}` })); return; }
    if (!mac) { rows.push(safe([path, saw(`version ${v}`), saw(`this system is ${os}`)], { what, path, version: v, reason: `version ${v} is below ${rule.fixed}, but the advisory says the flaw is in Claude Code on macOS only, and this is ${os}${also(v)}` })); return; }
    rows.push({ status: 'EXPOSED', what, path, version: v, reason: `version ${v} is below ${rule.fixed}, which fixes CVE-2026-88968 (reported, not in CISA's catalog)${also(v)}` });
  };
  const stale = (what, path, v, why) => { if (mac && cmp(v, rule.fixed) < 0) rows.push({ status: 'REVIEW', what, path, version: v, reason: `version ${v} is below ${rule.fixed}: ${why}` }); };

  // 1. the native installer: the link names the copy that runs
  const link = at(rule.link), versions = at(rule.versionsDir);
  const l = readLink(link);
  let active = '';
  if (l.denied) rows.push({ status: 'UNKNOWN', what: 'native install', path: link, version: '', reason: 'could not be read, so which copy of Claude Code runs is not known' });
  else if (l.target) {
    const target = isAbsolute(l.target) ? l.target : join(dirname(link), l.target);
    const v = basename(target);
    searched.push(saw(`${link} -> ${target}`));
    if (dirname(target) !== versions || !VERSION.test(v)) rows.push({ status: 'UNKNOWN', what: 'native install', path: link, version: '', reason: `is a link to ${target}, which is not a version in ${versions}, so its version could not be read` });
    else if (pathState(target) !== 'file') rows.push({ status: 'UNKNOWN', what: 'native install', path: link, version: v, reason: `is a link to ${target}, which is not there (or can't be looked at), so what it runs is not known` });
    else { active = target; runs('native install (the copy ~/.local/bin/claude runs)', target, v); }
  } else if (l.notLink && pathState(link) === 'file') rows.push({ status: 'UNKNOWN', what: 'claude', path: link, version: '', reason: 'is a program, not the native installer\'s link, so its version could not be read without running it' });
  const vl = listDir(versions);
  if (vl.denied) rows.push({ status: 'UNKNOWN', what: 'native install', path: versions, version: '', reason: 'could not be opened, so the copies in it were not checked' });
  if (vl.entries) {
    searched.push(versions);
    for (const e of vl.entries) {
      const p = join(versions, e.name);
      if (!VERSION.test(e.name) || p === active) continue;
      stale('native install, not the copy that runs', p, e.name, active ? `a copy left beside the one ~/.local/bin/claude runs; it runs only if started by its own path. Delete it if nothing uses it` : `no ~/.local/bin/claude link names the copy that runs, so this one may be the one that does`);
    }
  }

  // 2. npm installs, by their package.json
  // An entry is a pattern (an npm global prefix) or { path, what }: 0.1.18's review added Claude Code's own legacy local
  // install (~/.claude/local, which its older migrate-installer made, run through a shell alias), and bun's and pnpm's
  // global folders. Each is a package Claude Code runs from, judged as npm's is.
  for (const entry of rule.npmPackages) {
    const pattern = typeof entry === 'string' ? entry : entry.path;
    const what = typeof entry === 'string' ? 'npm install' : entry.what;
    // a folder on the way that is there and can't be opened is a place an install may be: UNKNOWN, never passed over
    const denied = [], reached = [];
    const found = expand(at(pattern), denied, reached);
    searched.push(...new Set(reached));
    for (const d of [...new Set(denied)]) rows.push({ status: 'UNKNOWN', what, path: d, version: '', reason: `could not be opened, so an ${what} of Claude Code in it was not looked for` });
    for (const p of found) {
      const buf = readCapped(p, 1024 * 1024);
      let v = '';
      try { v = String(JSON.parse(buf?.toString('utf8') ?? 'null')?.version ?? ''); } catch { v = ''; }
      if (!VERSION.test(v)) { rows.push({ status: 'UNKNOWN', what, path: p, version: '', reason: 'found, but no version could be read from it' }); continue; }
      runs(what, p, v);
    }
  }

  // 3. Homebrew's cask, by its folder names
  for (const pattern of rule.casks) {
    const dir = at(pattern);
    const c = listDir(dir);
    if (c.denied) { rows.push({ status: 'UNKNOWN', what: 'Homebrew cask', path: dir, version: '', reason: 'could not be opened, so the versions in it were not read' }); continue; }
    if (!c.entries) continue;
    searched.push(dir);
    let named = 0;
    for (const e of c.entries) {
      const v = (/^(\d+\.\d+\.\d+)/.exec(e.name) ?? [])[1];
      if (v) { named++; runs('Homebrew cask', join(dir, e.name), v); }
    }
    // the cask's folder is there and names no version: something is installed whose version was not read (review N4)
    if (!named) rows.push({ status: 'UNKNOWN', what: 'Homebrew cask', path: dir, version: '', reason: 'is there, but holds no folder named for a version, so the installed version could not be read' });
  }

  // 4. editor extensions: each ships its own copy, which the advisory doesn't name
  const ex = extensionFolders(home, rule.extensionName, rule.editors);
  searched.push(...ex.listed.filter((d) => d !== home));
  for (const d of ex.denied) rows.push({ status: 'UNKNOWN', what: 'extensions folder', path: d, version: '', reason: 'could not be opened, so the Claude Code extensions in it were not read' });
  for (const { path, version } of ex.folders) {
    if (!version) continue;
    stale('editor extension', path, version, 'the extension carries its own copy of Claude Code; the advisory names only the npm package, so this is not judged EXPOSED. Update the extension from your editor');
  }
  return { rows, searched };
}
