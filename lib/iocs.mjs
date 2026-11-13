// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Indicators of compromise a vendor published for a backdoor, checked by reading files only (0.1.18,
// claude-code-extension-2026-10: the tampered Claude Code extension builds 2.1.312 and 2.1.313 one marketplace served on
// 29 Oct 2026). Nothing found is run, no key is used, no ssh program is started (a key's fingerprint is computed here,
// from its bytes, as ssh-keygen would), and no process list is read. Each indicator is the vendor's, matched exactly:
//   - editor extension folders, by the published SHA-256 of their extension.js and the two strings the vendor says it holds;
//   - cached extension packages (VSIX), by the vendor's four SHA-256s;
//   - the attacker's public key in authorized_keys, by its key blob and its fingerprint, never by its comment, which
//     anyone can change; the comment alone is a REVIEW line;
//   - the files the payload drops (the LaunchAgent, the two scripts), by their path;
//   - the tunnel's private key in the temp folders, by its name and, where it parses as an OpenSSH key, its fingerprint.
// A place that can't be looked at is UNKNOWN, never a quiet all-clear.
import { createHash } from 'node:crypto';
import { join, basename } from 'node:path';
import { readCapped, listDir, pathState } from './files.mjs';

const MAX_JS = 64 * 1024 * 1024;       // the malicious extension.js is 3,692,922 bytes; a bundle of 64 MB is not one
const MAX_VSIX = 512 * 1024 * 1024;    // an extension package
const MAX_SMALL = 1024 * 1024;         // authorized_keys, a plist, a key file
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** An SSH public key blob's fingerprint as OpenSSH prints it: SHA256:<base64 of the SHA-256, no padding>. */
export const keyFingerprint = (blob) => `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;

/** The public key blob inside an OpenSSH private key file ("openssh-key-v1"), or null when the text isn't one. Only the
 *  public half is read: the format keeps it unencrypted ahead of the private section, which is never touched. */
export function opensshPublicBlob(text) {
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(String(text ?? ''));
  if (!m) return null;
  const buf = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
  const MAGIC = 'openssh-key-v1\0';
  if (buf.subarray(0, MAGIC.length).toString('latin1') !== MAGIC) return null;
  let o = MAGIC.length;
  const field = () => { if (o + 4 > buf.length) throw new Error('short'); const n = buf.readUInt32BE(o); o += 4; if (o + n > buf.length) throw new Error('short'); const s = buf.subarray(o, o + n); o += n; return s; };
  try {
    field(); field(); field();                      // cipher, kdf, kdf options
    if (o + 4 > buf.length || buf.readUInt32BE(o) < 1) return null;
    o += 4;
    const blob = field();
    return blob.length ? blob : null;
  } catch { return null; }
}

/** The base64 key blobs on a line of authorized_keys, wherever they stand: options before them, another key run into the
 *  same line (the payload appends its key with no line break before it, so it can share a line with a real one). */
const BLOB = /(?:^|[\s,"])(AAAA[A-Za-z0-9+/]{20,}={0,2})(?=\s|$)/g;

/**
 * The extension folders of every editor that keeps them as ~/.<editor>/extensions (VS Code, Cursor, Windsurf, VSCodium,
 * Insiders, and any other: the vendor's own clean-up script looks in ~/.[!.]*\/extensions), whose name matches `nameRe`
 * (case-insensitive). → { folders: [{ path, version }], listed: [folders opened], denied: [folders that couldn't be] }.
 * `version`: the first capture of nameRe, or ''.
 */
export function extensionFolders(home, nameRe, editors = []) {
  const rx = new RegExp(nameRe, 'i');
  const out = { folders: [], listed: [], denied: [] };
  const top = listDir(home);
  if (top.denied) { out.denied.push(home); return out; }
  if (top.entries) out.listed.push(home);
  for (const e of top.entries ?? []) {
    if (!e.name.startsWith('.') || e.name === '.' || e.name === '..') continue;
    if (!(e.isDirectory() || e.isSymbolicLink())) continue;
    const ext = join(home, e.name, 'extensions');
    const st = pathState(ext);
    if (st === 'gone' || st === 'file' || st === 'other') continue;
    // A dot-folder that can't be entered (macOS keeps ~/.Trash to itself) may hold no extensions folder at all: only an
    // editor's own folder is a place one is known to be, and only there is not looking a gap (UNKNOWN). Any other is
    // left, as it is in the vendor's own script, which can't look there either.
    if (st === 'denied') { if (editors.includes(e.name)) out.denied.push(ext); continue; }
    const l = listDir(ext);
    if (l.denied) { out.denied.push(ext); continue; }
    out.listed.push(ext);
    for (const x of l.entries ?? []) {
      const m = rx.exec(x.name);
      if (m && (x.isDirectory() || x.isSymbolicLink())) out.folders.push({ path: join(ext, x.name), version: m[1] ?? '' });
    }
  }
  return out;
}

const said = (p, home) => (home && p.startsWith(`${home}/`) ? `~${p.slice(home.length)}` : p);

/**
 * The indicators of one incident → { rows: [{ status, what, path, reason }], searched: [places read] }.
 * rule: the incident's `iocs` (lib/incidents/claude-code-extension-2026-10.json). home: the home folder to read;
 * tmpDirs: the temp folders (lib/binaries.mjs tempDirs()).
 */
export function checkIocs(rule, { home, tmpDirs = [] }) {
  const rows = [], searched = [];
  const add = (status, what, path, reason) => rows.push({ status, what, path, reason });
  const unknown = (what, path, why) => add('UNKNOWN', what, path, why);

  // 1. extension folders: the tampered extension.js, by hash and by the vendor's two strings
  const ex = rule.extensions;
  if (ex) {
    const f = extensionFolders(home, ex.nameRe, ex.editors);
    searched.push(...f.listed);
    for (const d of f.denied) unknown('extensions folder', d, 'could not be opened, so the extensions in it were not checked');
    for (const { path, version } of f.folders) {
      const js = join(path, ex.file);
      const st = pathState(js);
      const bad = ex.badVersions.includes(version);
      if (st === 'gone') {
        // nothing of that name: the payload lives in that file, and there is none here to carry it
        if (bad) add('REVIEW', `extension ${version}`, path, `a version the incident names, with no ${ex.file} in it, so the published file could not be compared`);
        continue;
      }
      const buf = st === 'file' ? readCapped(js, MAX_JS) : null;
      if (!buf) { unknown(`extension ${version}`, js, `found, but ${ex.file} could not be read (or is larger than 64 MB), so it was not compared`); continue; }
      searched.push(js);
      const h = sha256(buf);
      if (ex.sha256.includes(h)) { add('EXPOSED', `extension ${version}`, js, `this is the tampered ${ex.file} the vendor published (SHA-256 ${h})`); continue; }
      const text = buf.toString('latin1');
      const marks = ex.markers.filter((m) => text.includes(m));
      if (marks.length === ex.markers.length) { add('EXPOSED', `extension ${version}`, js, `this ${ex.file} holds both strings the vendor says the tampered one holds (${ex.markers.join(', ')}), though not byte for byte the published file (SHA-256 ${h})`); continue; }
      if (marks.length) { add('REVIEW', `extension ${version}`, js, `this ${ex.file} holds ${marks.join(', ')}, one of the strings the tampered one holds, and not the other; it is not the published file (SHA-256 ${h})`); continue; }
      if (bad) add('REVIEW', `extension ${version}`, js, `version ${version} was served tampered; this copy's ${ex.file} is not the published file and holds neither of its strings (SHA-256 ${h}), so it is probably a clean build from another source`);
    }
  }

  // 2. cached extension packages, by the vendor's VSIX hashes
  for (const c of rule.vsixCaches ?? []) {
    const dir = c.replace(/^~(?=\/)/, home);
    const st = pathState(dir);
    if (st === 'gone' || st === 'file' || st === 'other') continue;
    const l = st === 'dir' ? listDir(dir) : { denied: true };
    if (l.denied) { unknown('extension cache', dir, 'could not be opened, so the cached packages in it were not checked'); continue; }
    searched.push(dir);
    for (const e of l.entries ?? []) {
      if (!new RegExp(rule.vsixName, 'i').test(e.name)) continue;
      const p = join(dir, e.name);
      const buf = readCapped(p, MAX_VSIX);
      if (!buf) { unknown('cached package', p, 'found, but it could not be read, so it was not compared'); continue; }
      searched.push(p);
      const h = sha256(buf);
      if (rule.vsixSha256.includes(h)) add('EXPOSED', 'cached package', p, `this is one of the tampered packages the vendor published (SHA-256 ${h})`);
    }
  }

  // 3. the attacker's key in authorized_keys: by blob, and by the fingerprint of every blob on every line
  const k = rule.sshKey;
  if (k) {
    const ssh = join(home, '.ssh');
    // listed, not only looked at: a ~/.ssh that is there but can't be opened is one row, not a guess per file name
    const sst = pathState(ssh) === 'dir' && listDir(ssh).denied ? 'denied' : pathState(ssh);
    if (sst === 'denied') unknown('~/.ssh', ssh, 'could not be opened, so authorized_keys was not read');
    else if (sst !== 'dir') searched.push({ saw: `no ${said(ssh, home)} folder` });
    else {
      let any = false;
      for (const name of k.files) {
        const p = join(ssh, name);
        const st = pathState(p);
        if (st === 'gone') continue;
        const buf = st === 'file' ? readCapped(p, MAX_SMALL) : null;
        if (!buf) { unknown(name, p, 'is there but could not be read (or is larger than 1 MB), so the attacker\'s key was not looked for in it'); continue; }
        any = true; searched.push(p);
        const text = buf.toString('utf8');
        const blobs = [...text.matchAll(BLOB)].map((m) => m[1]);
        const hit = text.includes(k.blob) || blobs.some((b) => keyFingerprint(Buffer.from(b, 'base64')) === k.fingerprint);
        if (hit) { add('EXPOSED', name, p, `holds the attacker's public key (${k.fingerprint}), whatever its comment says`); continue; }
        if (text.includes(k.comment)) add('REVIEW', name, p, `a key here is labelled "${k.comment}", the label of the attacker's key, but its key is not the attacker's: check where it came from`);
      }
      if (!any) searched.push(ssh);
    }
  }

  // 4. the files the payload drops, by path: any of them there is the payload having run
  for (const f of rule.files ?? []) {
    const p = f.path.replace(/^~(?=\/)/, home);
    const st = pathState(p);
    if (st === 'gone') { searched.push({ saw: `no ${said(p, home)}` }); continue; }
    if (st === 'denied') { unknown(basename(p), p, 'could not be looked at (a folder on the way could not be opened), so whether the payload dropped it is not known'); continue; }
    let detail = '';
    if (f.readLabel && st === 'file') {
      const text = readCapped(p, MAX_SMALL)?.toString('utf8') ?? '';
      const label = (/<key>Label<\/key>\s*<string>([^<]{1,200})<\/string>/.exec(text) ?? [])[1];
      const args = [...(/<key>ProgramArguments<\/key>\s*<array>([\s\S]{0,2000}?)<\/array>/.exec(text)?.[1] ?? '').matchAll(/<string>([^<]{1,300})<\/string>/g)].map((m) => m[1]);
      if (label || args.length) detail = ` (label ${label ?? 'not read'}${args.length ? `, runs ${args.join(' ')}` : ''})`;
    }
    add('EXPOSED', basename(p), p, `${f.why}${detail}`);
  }

  // 5. the tunnel's private key in the temp folders
  const t = rule.tmpKey;
  if (t) {
    const rx = new RegExp(t.nameRe);
    for (const d of tmpDirs) {
      const l = listDir(d);
      if (l.gone) continue;
      if (l.denied) { unknown('temp folder', d, 'could not be listed, so the tunnel key was not looked for there'); continue; }
      searched.push(d);
      for (const e of l.entries ?? []) {
        if (!rx.test(e.name)) continue;
        const p = join(d, e.name);
        const blob = opensshPublicBlob(readCapped(p, MAX_SMALL)?.toString('utf8'));
        const fp = blob ? keyFingerprint(blob) : '';
        if (fp === t.fingerprint) add('EXPOSED', e.name, p, `this is the attacker's tunnel key (${fp}): the payload ran here`);
        else add('REVIEW', e.name, p, blob ? `named like the payload's tunnel key, but it holds another key (${fp})` : 'named like the payload\'s tunnel key, and not readable as an OpenSSH key, so it could not be compared');
      }
    }
  }
  return { rows, searched };
}
