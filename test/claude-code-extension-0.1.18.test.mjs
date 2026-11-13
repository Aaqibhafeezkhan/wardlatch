// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18: claude-code-extension-2026-10, the tampered Claude Code extension builds 2.1.312 and 2.1.313 that Cursor's
// marketplace served on 29 Oct 2026, checked against Cursor's published indicators (notice of 29 Oct, updated 30 Oct)
// by reading files only (lib/iocs.mjs). The malicious extension.js is never in this repository: a stand-in file is
// used, and the rule's hash is pointed at the stand-in's where a hash match is tested. The attacker's PUBLIC key is
// here, as Cursor publishes it: it is an indicator, not a secret.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, chmodSync, realpathSync } from 'node:fs';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkIocs, keyFingerprint, opensshPublicBlob } from '../lib/iocs.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'claude-code-extension-2026-10.json'), 'utf8'));
const R = INC.iocs;
const ATTACKER = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry';
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-ccext-'))); });
after(() => { rmSync(dir, { recursive: true, force: true }); });
const fresh = (name) => { const d = join(dir, `${name}-${Math.random().toString(36).slice(2, 8)}`); mkdirSync(d, { recursive: true }); return d; };
const put = (f, text, mode) => { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, text); if (mode !== undefined) chmodSync(f, mode); return f; };
const sha = (s) => createHash('sha256').update(s).digest('hex');
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const str = (b) => Buffer.concat([u32(Buffer.from(b).length), Buffer.from(b)]);
const newBlob = () => Buffer.concat([str('ssh-ed25519'), str(Buffer.from(generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x, 'base64url'))]);
const pubLine = (blob, comment) => `ssh-ed25519 ${blob.toString('base64')} ${comment}`;
const privKey = (blob) => { const b = Buffer.concat([Buffer.from('openssh-key-v1\0', 'latin1'), str('none'), str('none'), str(''), u32(1), str(blob), str(Buffer.alloc(80))]); return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b.toString('base64').match(/.{1,70}/g).join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`; };
const run = (home, rule = R, tmpDirs = []) => checkIocs(rule, { home, tmpDirs });
const statuses = (r) => r.rows.map((x) => [x.status, x.what]);
// a stand-in for an extension.js: never the payload
const STANDIN = '// a stand-in for a tampered bundle, not the payload\nmodule.exports = {};\n';
const ext = (home, editor, folder, text = 'module.exports = { activate() {} };\n') => put(join(home, editor, 'extensions', folder, 'extension.js'), text);
const cli = (home, args = [], tmp = fresh('tmp')) => {
  const { NODE_OPTIONS, ...rest } = process.env;
  return spawnSync(process.execPath, ['--require', join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), BIN, '--incident', 'claude-code-extension-2026-10', ...args], { encoding: 'utf8', env: { ...rest, HOME: home, TMPDIR: tmp, PATH: fresh('p'), WARDLATCH_TEST_OWN_DIR: dir } });
};

test('I1 the indicators are Cursor\'s, character for character, and the two published forms of the attacker\'s key agree', () => {
  assert.equal(INC.advisory, 'https://cursor.com/blog/claude-code-extension-security-notice');
  assert.deepEqual(R.extensions.badVersions, ['2.1.312', '2.1.313']);
  assert.deepEqual(R.extensions.sha256, ['ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15']);
  assert.deepEqual(R.extensions.markers, ['134.209.82.225', 'svc-telemetry']);
  assert.deepEqual(R.vsixSha256, ['fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364', '3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081',
    '80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c', '6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731']);
  assert.equal(`ssh-ed25519 ${R.sshKey.blob} ${R.sshKey.comment}`, ATTACKER);
  // Cursor publishes the key and its fingerprint separately: a typo in either breaks this
  assert.equal(keyFingerprint(Buffer.from(R.sshKey.blob, 'base64')), 'SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk');
  assert.equal(R.sshKey.fingerprint, 'SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk');
  assert.equal(R.tmpKey.fingerprint, 'SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ');
  assert.deepEqual(R.files.map((f) => f.path), ['~/Library/LaunchAgents/com.apple.sysmond.plist', '~/.config/.smt', '~/.config/.smtk']);
  // not in KEV and no CVE: nothing may say exploited
  assert.equal(INC.kev, undefined);
  assert.doesNotMatch(JSON.stringify(INC), /exploited|in the wild/i);
  assert.match(R.fix, /Uninstalling the extension is not enough/);
});

test('I2 extension folders: the published file by hash, the two strings, a named version with neither, in any editor\'s folder', () => {
  const standinRule = { ...R, extensions: { ...R.extensions, sha256: [sha(STANDIN)] } };
  // the published file (a stand-in carrying its hash), in Cursor's folder
  const h1 = fresh('h'); ext(h1, '.cursor', 'anthropic.claude-code-2.1.313-darwin-arm64', STANDIN);
  assert.deepEqual(statuses(run(h1, standinRule)), [['EXPOSED', 'extension 2.1.313']]);
  assert.match(run(h1, standinRule).rows[0].reason, /this is the tampered extension\.js the vendor published/);
  // the control: with the published hash, the stand-in is not that file
  assert.deepEqual(statuses(run(h1)), [['REVIEW', 'extension 2.1.313']]);
  // both strings, in a version the vendor didn't name (the bundle keeps the real number), in VS Code's folder, any case
  const h2 = fresh('h'); ext(h2, '.vscode', 'Anthropic.claude-code-2.1.300-darwin-arm64', '(()=>{const h="134.209.82.225",k="svc-telemetry"})();\n');
  assert.deepEqual(statuses(run(h2)), [['EXPOSED', 'extension 2.1.300']]);
  // one string only: REVIEW, never EXPOSED
  const h3 = fresh('h'); ext(h3, '.windsurf', 'anthropic.claude-code-2.1.314-darwin-arm64', '// svc-telemetry\n');
  assert.deepEqual(statuses(run(h3)), [['REVIEW', 'extension 2.1.314']]);
  // a clean later version: nothing to say; a clean named version: REVIEW; an editor nobody listed is read too
  const h4 = fresh('h'); ext(h4, '.cursor', 'anthropic.claude-code-2.1.314-darwin-arm64'); ext(h4, '.someeditor', 'anthropic.claude-code-2.1.312-win32-x64');
  assert.deepEqual(statuses(run(h4)), [['REVIEW', 'extension 2.1.312']]);
  // a named version with no extension.js: REVIEW (nothing to compare), never silence
  const h5 = fresh('h'); mkdirSync(join(h5, '.cursor', 'extensions', 'anthropic.claude-code-2.1.312-darwin-arm64'), { recursive: true });
  assert.deepEqual(statuses(run(h5)), [['REVIEW', 'extension 2.1.312']]);
  // an extension.js that can't be read: UNKNOWN, whatever its version
  const h6 = fresh('h'); chmodSync(ext(h6, '.cursor', 'anthropic.claude-code-2.1.250-darwin-arm64'), 0);
  assert.deepEqual(statuses(run(h6)), [['UNKNOWN', 'extension 2.1.250']]);
  // an editor's extensions folder that can't be opened: UNKNOWN; a dot-folder of anything else that can't be: no row
  const h7 = fresh('h'); mkdirSync(join(h7, '.cursor', 'extensions'), { recursive: true }); chmodSync(join(h7, '.cursor', 'extensions'), 0);
  mkdirSync(join(h7, '.Trash'), { recursive: true }); chmodSync(join(h7, '.Trash'), 0);
  try { assert.deepEqual(run(h7).rows.map((x) => [x.status, x.what]), [['UNKNOWN', 'extensions folder']]); } finally { chmodSync(join(h7, '.cursor', 'extensions'), 0o755); chmodSync(join(h7, '.Trash'), 0o755); }
  // other extensions are not read
  const h8 = fresh('h'); ext(h8, '.vscode', 'ms-python.python-2026.4.0-darwin-arm64', '"svc-telemetry" "134.209.82.225"');
  assert.deepEqual(run(h8).rows, []);
});

test('I3 authorized_keys: the attacker\'s key by its key, whatever the comment or where on the line; the comment alone is REVIEW', () => {
  const clean1 = pubLine(newBlob(), 'me@laptop'), clean2 = pubLine(newBlob(), 'ci');
  const at = (text, name = 'authorized_keys') => { const h = fresh('ak'); put(join(h, '.ssh', name), text); return run(h); };
  assert.deepEqual(statuses(at(`${clean1}\n${ATTACKER}\n${clean2}\n`)), [['EXPOSED', 'authorized_keys']]);
  assert.deepEqual(statuses(at(`${clean1}\n${ATTACKER.replace('svc-telemetry', 'backup@host')}\n`)), [['EXPOSED', 'authorized_keys']]);
  // appended with no line break before it, as the payload does: on one line with a real key
  assert.deepEqual(statuses(at(`${clean1}${ATTACKER}\n`)), [['EXPOSED', 'authorized_keys']]);
  assert.deepEqual(statuses(at(`no-pty,command="/bin/true" ${ATTACKER}\n`)), [['EXPOSED', 'authorized_keys']]);
  assert.deepEqual(statuses(at(`${clean1}\n${ATTACKER}\n`, 'authorized_keys2')), [['EXPOSED', 'authorized_keys2']]);
  // the comment alone, on another key: a question, not a finding
  assert.deepEqual(statuses(at(`${clean1}\n${pubLine(newBlob(), 'svc-telemetry')}\n`)), [['REVIEW', 'authorized_keys']]);
  assert.deepEqual(at(`${clean1}\n${clean2}\n`).rows, []);
  // can't be read: UNKNOWN; ~/.ssh can't be opened: UNKNOWN
  const h = fresh('ak'); chmodSync(put(join(h, '.ssh', 'authorized_keys'), `${clean1}\n`), 0);
  assert.deepEqual(statuses(run(h)), [['UNKNOWN', 'authorized_keys']]);
  const s = fresh('ak'); put(join(s, '.ssh', 'authorized_keys'), `${ATTACKER}\n`); chmodSync(join(s, '.ssh'), 0);
  try { assert.deepEqual(statuses(run(s)), [['UNKNOWN', '~/.ssh']]); } finally { chmodSync(join(s, '.ssh'), 0o700); }
  // the fingerprint alone finds the key too (a blob not spelled as published, the comment changed): the control for
  // the blob being matched by the bytes it decodes to, not only as text
  const fpOnly = { ...R, sshKey: { ...R.sshKey, blob: 'not-the-published-text' } };
  const h2 = fresh('ak'); put(join(h2, '.ssh', 'authorized_keys'), `${ATTACKER.replace('svc-telemetry', 'x')}\n`);
  assert.deepEqual(statuses(run(h2, fpOnly)), [['EXPOSED', 'authorized_keys']]);
});

test('I4 the dropped files: each one there is EXPOSED; a folder on the way that can\'t be opened is UNKNOWN', () => {
  const h = fresh('drop');
  put(join(h, 'Library', 'LaunchAgents', 'com.apple.sysmond.plist'), '<?xml version="1.0"?>\n<plist version="1.0"><dict><key>Label</key><string>com.apple.sysmond</string><key>ProgramArguments</key><array><string>/bin/sh</string><string>/Users/x/.config/.smt</string></array><key>RunAtLoad</key><true/></dict></plist>\n');
  put(join(h, '.config', '.smt'), '#!/bin/sh\n'); put(join(h, '.config', '.smtk'), 'k');
  const r = run(h);
  assert.deepEqual(statuses(r), [['EXPOSED', 'com.apple.sysmond.plist'], ['EXPOSED', '.smt'], ['EXPOSED', '.smtk']]);
  assert.match(r.rows[0].reason, /label com\.apple\.sysmond, runs \/bin\/sh \/Users\/x\/\.config\/\.smt/);
  const d = fresh('drop'); mkdirSync(join(d, 'Library', 'LaunchAgents'), { recursive: true }); chmodSync(join(d, 'Library', 'LaunchAgents'), 0);
  try { assert.deepEqual(statuses(run(d)), [['UNKNOWN', 'com.apple.sysmond.plist']]); } finally { chmodSync(join(d, 'Library', 'LaunchAgents'), 0o755); }
  // an ordinary LaunchAgent beside it is nothing
  const o = fresh('drop'); put(join(o, 'Library', 'LaunchAgents', 'com.example.agent.plist'), '<plist/>');
  assert.deepEqual(run(o).rows, []);
});

test('I5 the tunnel key in the temp folders: by fingerprint EXPOSED, by name alone REVIEW; a temp folder that can\'t be listed is UNKNOWN', () => {
  const blob = newBlob();
  assert.deepEqual(opensshPublicBlob(privKey(blob)), blob, 'the control: the reader gets the public blob back out of the key file');
  const ours = { ...R, tmpKey: { ...R.tmpKey, fingerprint: keyFingerprint(blob) } };
  const t = fresh('t'); put(join(t, '.stk_0123456789'), privKey(blob));
  assert.deepEqual(statuses(run(fresh('h'), ours, [t])), [['EXPOSED', '.stk_0123456789']]);
  // the published tunnel fingerprint is not this key's: REVIEW, with the key it holds
  const r = run(fresh('h'), R, [t]);
  assert.deepEqual(statuses(r), [['REVIEW', '.stk_0123456789']]);
  assert.match(r.rows[0].reason, new RegExp(keyFingerprint(blob).replace(/[+/]/g, '\\$&')));
  const j = fresh('t'); put(join(j, '.stk_abcdef0123'), 'not a key');
  assert.deepEqual(statuses(run(fresh('h'), R, [j])), [['REVIEW', '.stk_abcdef0123']]);
  const n = fresh('t'); put(join(n, '.stk_xyz'), 'x'); put(join(n, '.stk_01234567890'), 'x');
  assert.deepEqual(run(fresh('h'), R, [n]).rows, []);
  const shut = fresh('t'); chmodSync(shut, 0);
  try { assert.deepEqual(statuses(run(fresh('h'), R, [shut])), [['UNKNOWN', 'temp folder']]); } finally { chmodSync(shut, 0o755); }
});

test('I6 a cached package is matched by the vendor\'s VSIX hashes', () => {
  const h = fresh('vsix');
  const p = put(join(h, 'Library', 'Application Support', 'Cursor', 'CachedExtensionVSIXs', 'anthropic.claude-code-2.1.312-darwin-arm64'), STANDIN);
  assert.deepEqual(run(h).rows, [], 'the control: not one of the published packages');
  assert.deepEqual(statuses(run(h, { ...R, vsixSha256: [sha(STANDIN)] })), [['EXPOSED', 'cached package']]);
  assert.ok(run(h).searched.includes(p), 'a package read is in the receipt');
});

test('I7 the command: EXPOSED is exit 1 with the remediation, REVIEW exit 0, a place it couldn\'t read exit 2, and a clean home one receipted SAFE', () => {
  const h = fresh('cli'); put(join(h, '.ssh', 'authorized_keys'), `${ATTACKER}\n`);
  const t = cli(h);
  assert.equal(t.status, 1, t.stdout + t.stderr);
  assert.match(t.stdout, /^EXPOSED +authorized_keys +~\/\.ssh\/authorized_keys$/m);
  assert.match(t.stdout, /fix: The payload ran on this machine\. Uninstalling the extension is not enough/);
  assert.match(t.stdout, /not covered: The Linux @reboot crontab line/);
  const j = JSON.parse(cli(h, ['--json']).stdout);
  assert.deepEqual(j.results.map((x) => [x.kind, x.status, x.what]), [['ioc', 'EXPOSED', 'authorized_keys']]);
  assert.equal(j.results[0].fix, R.fix);
  const rv = fresh('cli'); ext(rv, '.cursor', 'anthropic.claude-code-2.1.312-darwin-arm64');
  const r = cli(rv, ['--json']);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.deepEqual(JSON.parse(r.stdout).results.map((x) => [x.status, x.fix]), [['REVIEW', R.reviewFix]]);
  const un = fresh('cli'); chmodSync(put(join(un, '.ssh', 'authorized_keys'), 'x\n'), 0);
  assert.equal(cli(un).status, 2);
  const clean = fresh('cli'); ext(clean, '.vscode', 'anthropic.claude-code-2.1.320-darwin-arm64'); put(join(clean, '.ssh', 'authorized_keys'), `${pubLine(newBlob(), 'me')}\n`);
  const s = cli(clean, ['--json']);
  assert.equal(s.status, 0, s.stdout + s.stderr);
  const rows = JSON.parse(s.stdout).results;
  assert.deepEqual(rows.map((x) => x.status), ['SAFE']);
  assert.ok(rows[0].searched.includes(join(clean, '.ssh', 'authorized_keys')) && rows[0].searched.includes(join(clean, '.vscode', 'extensions', 'anthropic.claude-code-2.1.320-darwin-arm64', 'extension.js')), JSON.stringify(rows[0].searched));
});

test('I8 read-only by construction: lib/iocs.mjs runs nothing and opens nothing for writing', () => {
  const src = readFileSync(join(ROOT, 'lib', 'iocs.mjs'), 'utf8');
  assert.doesNotMatch(src, /run\.mjs|child_process|\bspawn|execFile|execSync|runSync/);
  assert.doesNotMatch(src, /from 'node:fs'/);
});
