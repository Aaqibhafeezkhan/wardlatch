#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The coverage check (docs/COVERAGE-PROTOCOL.md). Offline: it reads the committed snapshot of the sources
// (test/support/fixtures/coverage-snapshot.json, written by scripts/coverage/refresh.mjs), the incident files in
// lib/incidents/ and the declined list (scripts/coverage/declined.json). Every item in a class Wardlatch covers must be
// NAMED (its CVE number is in an incident file) or DECLINED (an entry with a one-line reason and a review date).
// Anything in neither is a GAP, and the check fails.
//
//   node scripts/coverage/check.mjs [--snapshot file] [--declined file] [--today YYYY-MM-DD] [--json]
//
// "No gaps" is printed only from a complete read: every source the protocol names is in the snapshot, each read
// whole (its own counts agree), and the snapshot is not older than MAX_AGE_DAYS. Otherwise the result is INCOMPLETE,
// which fails too, and says which source was missing or short. A declined entry past its review date fails, so a
// decline is a decision with a date, not a place to leave things.
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const SNAPSHOT = join(ROOT, 'test', 'support', 'fixtures', 'coverage-snapshot.json');
export const DECLINED = join(ROOT, 'scripts', 'coverage', 'declined.json');
export const INCIDENTS = join(ROOT, 'lib', 'incidents');
export const SOURCES = ['apple-macos', 'cisa-kev', 'cert-vu'];
export const MAX_AGE_DAYS = 31;
/** Where a declined item's flawed code runs: a server or appliance, the machine a person uses (an app, agent, desktop or
 *  the OS itself), both, or not yet known. */
export const RUNS_ON = ['server', 'client', 'both', 'unknown'];

/**
 * The identity-equivalence class (docs/PATTERN-IDENTITY-EQUIVALENCE.md): two spellings of one name (case, Unicode form,
 * a fold), a path that resolves elsewhere (a link, a path handling issue), or names compared looser or stricter than the
 * system that uses them (X.509 name constraints). One regex for Apple's lines and CERT/CC's notes.
 */
export const EQUIVALENCE = /unicode normali[sz]ation|normali[sz]ation (?:collision|mismatch)|case[- ]?(?:in)?sensitiv|case[- ]fold|path equivalence|\bAPFS\b|HFS\+|homoglyph|confusable|alternat(?:e|ive) (?:unicode )?spellings?|equivalent (?:paths?|names?|spellings?)|\bCWE-(?:41|176|178)\b|name[- ]constraint|path handling|symlink|symbolic link|canonicali[sz]/i;

/**
 * The classes Wardlatch covers, matched on Apple's own "Impact:" line. An Apple entry in any of them is in scope. The
 * owner's list (16 Nov 2026): permission, TCC and privacy bypass; trust and certificates; code signing and Gatekeeper;
 * sandbox escape; plus privilege escalation to root or the kernel, and anything Apple says may have been exploited.
 */
export const CLASSES = {
  privacy: /sensitive user (data|information)|user-sensitive data|protected user data|Privacy preferences|without (the user's )?permission|before user authorization|location information|information about a user's contacts|fingerprint the user|access user data|microphone|camera/i,
  sandbox: /sandbox/i,
  'code-signing': /Gatekeeper|code[- ]?sign|signature/i,
  trust: /certificate|\btrust|\bTLS\b|impersonat|spoof/i,
  privilege: /root privileges|elevated privileges|kernel privileges|modify protected parts of the file system|escalate/i,
  exploited: /Apple is aware of a report/i,
  // 16 Nov 2026 (docs/PATTERN-IDENTITY-EQUIVALENCE.md): a check compared one notion of a name, a path or an identity,
  // and the system resolved another. Matched on Apple's Impact and Description lines, and on CERT/CC's notes.
  equivalence: EQUIVALENCE,
};

/**
 * Two classes that both read the Description line, kept distinct (release/0.1.19-candidate, 16 Nov 2026):
 *  - `equivalence`: NAME OR PATH FOLDING. One name, two spellings (case, Unicode form), a path that resolves
 *    elsewhere, names compared looser or stricter than the system that uses them. `EQUIVALENCE` above, plus, on Apple's
 *    lines, any "normalization" (fix/no-stale-safe first caught that word under identity; it is folding, so it lives
 *    here now, and nothing it matched before is lost).
 *  - `identity`: AN IMPERSONATED OR FORGED CALLER OR AUTHORITY (fix/no-stale-safe, 16 Nov 2026). Either line says one
 *    party is taken for another (impersonate, spoof, forged), or the Description is Apple's "logic issue / improved
 *    checks" and either line is about permission, TCC, privacy or an authorization.
 * One CVE may be in both; an item is one CVE, so the report's totals count it once (items() keys by CVE).
 */
export const APPLE_FOLDING = /normali[sz]/i;
export const IDENTITY = {
  words: /impersonat|spoof|forged|forger/i,
  logic: /logic issue|improved checks/i,
  authority: /permission|\bTCC\b|privacy|sensitive user|protected user data|user data|authori[sz]|entitlement/i,
};
const identityOf = (impact, description) => {
  const both = `${impact}\n${description}`;
  return IDENTITY.words.test(both) || (IDENTITY.logic.test(description) && IDENTITY.authority.test(both));
};
const equivalenceOf = (impact, description) => {
  const both = `${impact}\n${description}`;
  return EQUIVALENCE.test(both) || APPLE_FOLDING.test(both);
};
/** The classes an Apple entry is in: from its Impact line, and for `equivalence` and `identity` its Description too. */
export const classesOf = (impact, description = '') => {
  const i = String(impact ?? ''), d = String(description ?? '');
  const out = new Set(Object.keys(CLASSES).filter((k) => k !== 'equivalence' && CLASSES[k].test(i)));
  if (equivalenceOf(i, d)) out.add('equivalence');
  if (identityOf(i, d)) out.add('identity');
  return [...out].sort();
};

/**
 * The items each source holds, one per CVE (or, for an Apple entry printed without a CVE number, one per release,
 * component and place: `apple:<release>:<component>:<n>`). Apple items carry the releases they are fixed in; every KEV
 * row is in scope (class `exploited`): CISA says it is exploited, so it is either named, or declined with a reason.
 */
export function items(snapshot) {
  const out = new Map();
  for (const r of snapshot.apple ?? []) {
    (r.entries ?? []).forEach((e, n) => {
      const keys = e.cves.length ? e.cves : [`apple:${r.name}:${e.component}:${n}`];
      for (const key of keys) {
        const it = out.get(key) ?? { key, source: 'apple-macos', component: e.component, impact: e.impact, classes: new Set(), releases: [] };
        for (const c of classesOf(e.impact, e.description)) it.classes.add(c);
        it.releases.push(r.name);
        out.set(key, it);
      }
    });
  }
  for (const k of snapshot.kev ?? []) {
    const it = out.get(k.cve);
    if (it) { it.classes.add('exploited'); it.kev = k; continue; }
    out.set(k.cve, { key: k.cve, source: 'cisa-kev', component: `${k.vendorProject} ${k.product}`, impact: k.name, classes: new Set(['exploited']), releases: [], kev: k });
  }
  // CERT/CC's notes in the equivalence class: every CVE number a note prints anywhere (its list, its text, its
  // vulnerability rows, its vendors' statements and addenda, its references) is one item. A note with no CVE at all is
  // one item keyed by its VU number, so it too is named or declined (a decline is the only way: incidents name CVEs).
  for (const n of snapshot.cert ?? []) {
    for (const key of n.cves.length ? n.cves : [n.id]) {
      const it = out.get(key);
      if (it) { it.classes.add('equivalence'); it.cert = n.id; continue; }
      out.set(key, { key, source: 'cert-vu', component: n.id, impact: n.name, classes: new Set(['equivalence']), releases: [], cert: n.id });
    }
  }
  return [...out.values()].map((i) => ({ ...i, classes: [...i.classes].sort() }));
}

/** Which sources the snapshot read whole: [] when all, else the reasons. */
export function incomplete(snapshot, today) {
  const why = [];
  const src = new Map((snapshot.sources ?? []).map((s) => [s.id, s]));
  for (const id of SOURCES) if (!src.has(id)) why.push(`source ${id} is not in the snapshot`);
  const a = src.get('apple-macos');
  if (a) {
    if ((snapshot.apple ?? []).length !== a.macosReleasesInWindow) why.push(`apple-macos: ${(snapshot.apple ?? []).length} releases read, the index listed ${a.macosReleasesInWindow} in the window`);
    if (!a.indexOldest || a.indexOldest > snapshot.since) why.push(`apple-macos: the index read reaches back to ${a.indexOldest}, not to the window's start ${snapshot.since}`);
    for (const r of snapshot.apple ?? []) if (!r.noCves && !(r.entries ?? []).length) why.push(`apple-macos: ${r.name} has a page and no entries read`);
    // the identity class reads the Description line: a snapshot without it (written before 16 Nov 2026) would match
    // nothing there and look clean, so it is not a complete read
    const bare = (snapshot.apple ?? []).flatMap((r) => (r.entries ?? []).filter((e) => typeof e.description !== 'string' || !e.description.trim()).map(() => r.name));
    if (bare.length) why.push(`apple-macos: ${bare.length} entries carry no Description line (first in ${bare[0]}), which the identity class reads: run scripts/coverage/refresh.mjs`);
  }
  const k = src.get('cisa-kev');
  if (k) {
    if (!(k.count > 0) || k.count !== k.read) why.push(`cisa-kev: the feed said ${k.count} rows and ${k.read} were read`);
    if ((snapshot.kev ?? []).length !== k.inWindow) why.push(`cisa-kev: ${(snapshot.kev ?? []).length} rows kept, ${k.inWindow} were in the window`);
  }
  const c = src.get('cert-vu');
  if (c) {
    if (!Array.isArray(c.months) || c.months.length !== c.monthsInWindow || !(c.monthsInWindow > 0)) why.push(`cert-vu: ${c.months?.length ?? 0} monthly listings read, the window has ${c.monthsInWindow}`);
    if (!(c.notesRead >= (snapshot.cert ?? []).length)) why.push(`cert-vu: ${c.notesRead} notes read, fewer than the ${(snapshot.cert ?? []).length} kept`);
    if ((snapshot.cert ?? []).length !== c.inClass) why.push(`cert-vu: ${(snapshot.cert ?? []).length} notes kept, ${c.inClass} were in the class`);
    for (const n of snapshot.cert ?? []) if (!n.vulsRead || !n.vendorsRead) why.push(`cert-vu: ${n.id}'s vulnerability rows or vendors were not read`);
  }
  const age = (Date.parse(`${today}T00:00:00Z`) - Date.parse(snapshot.read)) / 86400000;
  if (!Number.isFinite(age)) why.push(`the snapshot's read time "${snapshot.read}" or today "${today}" is not a date`);
  else if (age > MAX_AGE_DAYS) why.push(`the snapshot was read ${Math.floor(age)} days ago (${snapshot.read}); the protocol allows ${MAX_AGE_DAYS}: run scripts/coverage/refresh.mjs`);
  return why;
}

/** Every CVE number named in an incident file: Map cve → [incident ids]. */
export function namedCves(dir = INCIDENTS) {
  const named = new Map();
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.json')).sort()) {
    for (const c of new Set(readFileSync(join(dir, f), 'utf8').match(/CVE-\d{4}-\d{4,}/g) ?? [])) named.set(c, [...(named.get(c) ?? []), f.replace(/\.json$/, '')]);
  }
  return named;
}

/**
 * The check. `declined`: { entries: [{ key, reason, runsOn, reviewBy, candidate? }] }. → { complete, why, inScope, named,
 * declined, gaps, expired, badDeclines, unusedDeclines, ok }. ok only when complete, with no gap, no expired or
 * malformed decline.
 */
export function check({ snapshot, named, declined, today }) {
  const why = incomplete(snapshot, today);
  const all = items(snapshot);
  const inScope = all.filter((i) => i.classes.length);
  const dec = new Map();
  const badDeclines = [];
  for (const d of declined?.entries ?? []) {
    if (!d || typeof d.key !== 'string' || !d.key) { badDeclines.push({ entry: d, why: 'no key' }); continue; }
    if (typeof d.reason !== 'string' || d.reason.trim().length < 12 || d.reason.length > 240 || /\n/.test(d.reason)) badDeclines.push({ entry: d, why: 'the reason must be one line of 12 to 240 characters' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(d.reviewBy ?? ''))) badDeclines.push({ entry: d, why: 'no reviewBy date (YYYY-MM-DD)' });
    // where the flawed code runs (fix/no-stale-safe, 16 Nov 2026): PR #37 declined ScreenConnect's client flaw as a
    // "self-hosted server", and nothing asked. Every skip now says it, so a client-side flaw can't hide behind a server word
    if (!RUNS_ON.includes(d.runsOn)) badDeclines.push({ entry: d, why: `no runsOn (one of ${RUNS_ON.join(', ')}): where the flawed code runs` });
    if (dec.has(d.key)) badDeclines.push({ entry: d, why: 'declined twice' });
    dec.set(d.key, d);
  }
  const res = { named: [], declined: [], gaps: [] };
  for (const i of inScope) {
    const cve = /^CVE-/.test(i.key) ? i.key : '';
    if (cve && named.has(cve)) res.named.push({ ...i, incidents: named.get(cve) });
    else if (dec.has(i.key)) res.declined.push({ ...i, decline: dec.get(i.key) });
    else res.gaps.push(i);
  }
  const expired = res.declined.filter((i) => i.decline.reviewBy < today);
  // a decline for an item the snapshot holds but that is also named: the incident wins, and the decline is stale
  const inScopeKeys = new Set(inScope.map((i) => i.key));
  const unusedDeclines = [...dec.values()].filter((d) => !inScopeKeys.has(d.key) || (named.has(d.key)));
  const complete = !why.length;
  return { complete, why, sources: snapshot.sources ?? [], since: snapshot.since, read: snapshot.read, total: all.length, inScope: inScope.length, ...res, expired, badDeclines, unusedDeclines, ok: complete && !res.gaps.length && !expired.length && !badDeclines.length };
}

export function report(r) {
  const out = [];
  out.push(`sources read (snapshot of ${r.read}, window from ${r.since}):`);
  const said = (s) => (s.id === 'apple-macos' ? `(index rows ${s.indexRows}, back to ${s.indexOldest}; ${s.macosReleasesInWindow} macOS releases in the window)`
    : s.id === 'cert-vu' ? `(${s.months?.length} monthly listings, ${s.months?.[0]} to ${s.months?.at(-1)}; ${s.notesRead} notes read, ${s.inClass} in the equivalence class)`
      : `(catalog ${s.catalogVersion}, ${s.read} of ${s.count} rows read; ${s.inWindow} added in the window)`);
  for (const s of r.sources) out.push(`  ${s.id}: ${s.url} ${said(s)}`);
  out.push(`items: ${r.total}; in a covered class: ${r.inScope}; named in an incident: ${r.named.length}; declined: ${r.declined.length}; gaps: ${r.gaps.length}`);
  if (!r.complete) { out.push('INCOMPLETE: no verdict on gaps can be given from this read:'); for (const w of r.why) out.push(`  ${w}`); }
  for (const g of r.gaps) out.push(`GAP ${g.key} [${g.classes.join(',')}] ${g.component}: ${g.impact}${g.releases.length ? ` (${g.releases.join('; ')})` : ''}`);
  for (const e of r.expired) out.push(`EXPIRED ${e.key}: declined until ${e.decline.reviewBy} (${e.decline.reason})`);
  for (const b of r.badDeclines) out.push(`BAD DECLINE ${b.entry?.key ?? '?'}: ${b.why}`);
  for (const u of r.unusedDeclines) out.push(`note: declined entry ${u.key} matches nothing in scope, or is now named: remove it`);
  const cand = r.declined.filter((d) => d.decline.candidate);
  if (cand.length) out.push(`declined as candidates for a future incident: ${cand.length} (${cand.map((d) => d.key).join(', ')})`);
  out.push(r.ok ? `NO GAPS, from a complete read of: ${r.sources.map((s) => s.id).join(', ')}` : 'FAIL');
  return out.join('\n');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const a = process.argv.slice(2);
  const opt = (k, d) => { const i = a.indexOf(k); return i < 0 ? d : a[i + 1]; };
  const snapshot = JSON.parse(readFileSync(opt('--snapshot', SNAPSHOT), 'utf8'));
  const declined = JSON.parse(readFileSync(opt('--declined', DECLINED), 'utf8'));
  const today = opt('--today', new Date().toISOString().slice(0, 10));
  const r = check({ snapshot, named: namedCves(), declined, today });
  if (a.includes('--json')) console.log(JSON.stringify({ ...r, named: r.named.map((i) => i.key), declined: r.declined.map((i) => i.key) }, null, 1));
  else console.log(report(r));
  // exitCode, not process.exit(): on macOS a pipe is written asynchronously, and exit() cut a long report short on
  // Node 18 and 20 (CI saw 51 of 428 GAP lines). Setting the code lets Node flush stdout before it exits.
  process.exitCode = r.ok ? 0 : 1;
}
