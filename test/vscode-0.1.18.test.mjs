// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18: vscode-2026-11. Microsoft's 16 advisories of 10 Nov 2026 for Visual Studio Code each name "< 1.145.3" as
// affected and 1.145.3 as patched; three are code execution through MCP servers. None is in CISA's catalog, so nothing
// here says "exploited". The check reads the installed version from Info.plist (Mac) or dpkg's record and never starts
// VS Code. Below 1.145.3 is EXPOSED; at or past it REVIEW (an open window keeps the old version until a restart); an
// Insiders build at or past the number is REVIEW for its own reason. On the Mac this was written on, VS Code was 1.118.1.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkVersionFiles } from '../lib/installs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'vscode-2026-11.json'), 'utf8'));
const V = INC.versionFiles;
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-vscode-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
// an Info.plist as VS Code 1.118.1's has it, around the version (measured on one Mac on 13 Nov 2026)
const plist = (v) => `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n  <dict>\n    <key>CFBundleExecutable</key>\n    <string>Code</string>\n    <key>CFBundleIdentifier</key>\n    <string>com.microsoft.VSCode</string>\n    <key>CFBundleShortVersionString</key>\n    <string>${v}</string>\n    <key>CFBundleVersion</key>\n    <string>${v}</string>\n  </dict>\n</plist>\n`;
const app = (root, name, text) => { const f = join(root, 'Applications', `${name}.app`, 'Contents', 'Info.plist'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); return f; };
const sys = (pred) => ({ ...V, files: V.files.filter((f) => !f.path.startsWith('~') && pred(f)) });
const one = (name, v, rule) => { const root = fresh('r'); app(root, name, plist(v)); const rows = checkVersionFiles(rule, { root }); assert.equal(rows.length, 1, JSON.stringify(rows)); return rows[0]; };
const STABLE = sys((f) => f.path.includes('Visual Studio Code.app'));
const INSIDERS = sys((f) => f.path.includes('Insiders'));
const cli = (home, args = []) => {
  const { NODE_OPTIONS, ...rest } = process.env;
  return spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'vscode-2026-11', ...args], { encoding: 'utf8', env: { ...rest, HOME: home, PATH: fresh('p'), WARDLATCH_TEST_OWN_DIR: dir } });
};

test('V1 the facts are Microsoft\'s: the patched version, the three MCP advisories, and no word of exploitation', () => {
  assert.equal(V.minVersion, '1.145.3');
  for (const id of ['CVE-2026-120779', 'CVE-2026-114171', 'CVE-2026-119983', 'GHSA-66hq-jw93-462h', 'GHSA-crhv-2887-p3xr', 'GHSA-4x35-6qr8-ww48']) assert.ok(INC.summary.includes(id), id);
  assert.match(INC.summary, /16 security advisories/);
  assert.equal(INC.kev, undefined);
  assert.doesNotMatch(JSON.stringify(INC), /\bexploited\b|in the wild/i);
  assert.match(INC.summary, /CISA's catalog \(version 2026\.11\.10\) lists none of them/);
});

test('V2 stable VS Code: below 1.145.3 EXPOSED, at or past it REVIEW, unread UNKNOWN', () => {
  for (const [v, want] of [['1.118.1', 'EXPOSED'], ['1.145.2', 'EXPOSED'], ['1.145.0', 'EXPOSED'], ['1.145.3', 'REVIEW'], ['1.145.10', 'REVIEW'], ['1.146.0', 'REVIEW']]) {
    const r = one('Visual Studio Code', v, STABLE);
    assert.equal(r.status, want, v);
    if (want === 'EXPOSED') assert.equal(r.reason, 'fixed in 1.145.3');
    if (want === 'REVIEW') assert.match(r.reason, /a window left open from before an update keeps running the old version/);
  }
  const root = fresh('nokey'); app(root, 'Visual Studio Code', plist('1.118.1').replaceAll('CFBundleShortVersionString', 'CFBundleOther'));
  assert.deepEqual(checkVersionFiles(STABLE, { root }).map((r) => r.status), ['UNKNOWN']);
  const locked = fresh('locked'); chmodSync(app(locked, 'Visual Studio Code', plist('1.146.0')), 0);
  assert.deepEqual(checkVersionFiles(STABLE, { root: locked }).map((r) => r.status), ['UNKNOWN']);
  assert.deepEqual(checkVersionFiles(STABLE, { root: fresh('none') }), []);
  // the control: without reviewWhenFixed a fixed VS Code reads SAFE
  const strip = { ...STABLE, files: STABLE.files.map(({ reviewWhenFixed, ...f }) => f) };
  assert.equal(one('Visual Studio Code', '1.145.3', strip).status, 'SAFE');
});

test('V3 Insiders: its own product and reason, with or without "-insider" after the number', () => {
  for (const [v, want, ver] of [['1.145.0-insider', 'EXPOSED', '1.145.0'], ['1.146.0-insider', 'REVIEW', '1.146.0'], ['1.146.0', 'REVIEW', '1.146.0']]) {
    const r = one('Visual Studio Code - Insiders', v, INSIDERS);
    assert.deepEqual([r.status, r.version, r.product], [want, ver, 'Visual Studio Code - Insiders'], v);
    if (want === 'REVIEW') assert.match(r.reason, /an Insiders build's number runs ahead of the stable release/);
  }
});

test('V4 dpkg\'s code package', () => {
  const run = (text) => { const root = fresh('dpkg'); const f = join(root, 'var', 'lib', 'dpkg', 'status'); mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); return checkVersionFiles(sys((x) => x.path.includes('dpkg')), { root }); };
  const st = (pkg, v) => `Package: ${pkg}\nStatus: install ok installed\nArchitecture: amd64\nVersion: ${v}\n\n`;
  assert.deepEqual(run(st('code-insiders', '1.150.0-1') + st('code', '1.145.2-1762300000')).map((r) => r.status), ['EXPOSED']);
  assert.deepEqual(run(st('code', '1.145.3-1762800000')).map((r) => r.status), ['REVIEW']);
  assert.deepEqual(run(st('codeblocks', '20.03-1')), []);
});

test('V5 the command: EXPOSED exit 1 with Microsoft\'s fix, never started; a clean home one receipted SAFE', () => {
  const home = fresh('cli'); const f = app(home, 'Visual Studio Code', plist('1.118.1'));
  const mark = join(home, 'ran'); const exe = join(dirname(f), 'MacOS', 'Electron'); mkdirSync(dirname(exe), { recursive: true });
  writeFileSync(exe, `#!/bin/sh\necho ran > '${mark}'\n`, { mode: 0o755 });
  const t = cli(home);
  assert.equal(t.status, 1, t.stdout + t.stderr);
  assert.match(t.stdout, /^EXPOSED +Visual Studio Code \(Mac app\) 1\.118\.1 +~\/Applications\/Visual Studio Code\.app\/Contents\/Info\.plist$/m);
  assert.match(t.stdout, /fix: Update Visual Studio Code to 1\.145\.3 or later/);
  assert.match(t.stdout, /not covered: Editors built on VS Code \(Cursor, Windsurf, VSCodium/);
  assert.doesNotMatch(t.stdout, /CISA KEV/);
  assert.ok(!existsSync(mark), 'VS Code was started');
  const s = cli(fresh('none'), ['--json']);
  assert.equal(s.status, 0);
  const rows = JSON.parse(s.stdout).results;
  assert.deepEqual(rows.map((r) => r.status), ['SAFE']); assert.match(rows[0].reason, /^no Visual Studio Code found/);
});
