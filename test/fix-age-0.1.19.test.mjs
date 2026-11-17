// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The machine-speed moves (release/0.1.19-candidate), 1: fix age. Every EXPOSED line says how long its incident's fix
// has been public, "fix public for N days (since YYYY-MM-DD)", from the incident's `fixPublished` date and the same
// "today" as every other date check (lib/clock.mjs effectiveNow); --json carries it as fixAgeDays. An incident whose
// fix date is not known says "fix date unknown", with why, and never a date someone made up.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync, cpSync, utimesSync } from 'node:fs';
import { join } from 'node:path';
import { scratch, mutatedLib, realLib, cli, ROOT, HERE } from './never-false-safe/support.mjs';

const T = scratch('fixage');
after(() => T.done());
const { fixAge } = await realLib('clock.mjs');
const INC = readdirSync(join(ROOT, 'lib', 'incidents')).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', f), 'utf8')));
const NOW = Date.parse('2026-11-17T12:00:00Z');
const today = { now: NOW, from: 'the system clock' };

test('F1 every incident says when its fix was published, with the source, or that the date is unknown and why', () => {
  assert.ok(INC.length >= 30);
  for (const i of INC) {
    const f = i.fixPublished;
    assert.ok(f && typeof f === 'object', `${i.id}: fixPublished`);
    if (f.date === null) { assert.ok(typeof f.why === 'string' && f.why.length >= 20, `${i.id}: why the date is unknown`); assert.equal(f.source, undefined, i.id); continue; }
    assert.match(f.date, /^\d{4}-\d{2}-\d{2}$/, i.id);
    assert.ok(typeof f.source === 'string' && f.source.length >= 20, `${i.id}: the source of the date`);
    assert.ok(f.date <= '2026-11-17', `${i.id}: a fix date after this release was written`);
    // the date is said in the incident's own words, or the source says where it comes from
    assert.ok(i.summary.length > 0);
  }
  // the controls: both kinds are present
  assert.ok(INC.some((i) => i.fixPublished.date) && INC.some((i) => i.fixPublished.date === null));
});

test('F2 fixAge: days since the date, by the effective today; one day singular; unknown, unreadable or future dates are "fix date unknown"', () => {
  assert.deepEqual(fixAge({ date: '2026-06-04', source: 's' }, today), { days: 166, since: '2026-06-04', text: 'fix public for 166 days (since 2026-06-04)' });
  assert.equal(fixAge({ date: '2026-11-16', source: 's' }, today).text, 'fix public for 1 day (since 2026-11-16)');
  assert.equal(fixAge({ date: '2026-11-17', source: 's' }, today).text, 'fix public for 0 days (since 2026-11-17)');
  assert.deepEqual(fixAge({ date: null, why: 'a malicious release, not a flaw with a fixed version' }, today), { days: null, since: null, text: 'fix date unknown: a malicious release, not a flaw with a fixed version' });
  assert.equal(fixAge(undefined, today).text, 'fix date unknown');
  assert.equal(fixAge({ date: '17 Nov 2026', source: 's' }, today).days, null);
  assert.match(fixAge({ date: '2026-12-01', source: 's' }, today).text, /^fix date unknown \(the advisory's date, 2026-12-01, is after today/);
  assert.equal(fixAge({ date: '2026-06-04' }, { now: NaN }).days, null);
});

/** The command on a project whose uv.lock pins Starlette 0.46.2, with the clock at NOW (test/never-false-safe/clock.cjs). */
function run(bin) {
  const home = T.fresh('home'), proj = T.fresh('proj');
  T.put(join(proj, 'uv.lock'), 'version = 1\n\n[[package]]\nname = "starlette"\nversion = "0.46.2"\n');
  const plist = T.put(join(T.fresh('sv'), 'SystemVersion.plist'), '<plist/>\n'); utimesSync(plist, new Date('2026-10-01'), new Date('2026-10-01'));
  const env = { WL_NFS_NOW: String(NOW), WL_NFS_PLIST: plist };
  const preload = [join(ROOT, 'test', 'support', 'hide-machine-places.cjs'), join(HERE, 'clock.cjs')];
  return { text: cli(['--incident', 'starlette-2026-06', '--paths', proj], { home, env, preload, json: false, bin }).text, json: cli(['--incident', 'starlette-2026-06', '--paths', proj], { home, env, preload, bin }) };
}

test('F3 the command: the EXPOSED line is followed by the fix age, and --json carries fixAgeDays and the incident\'s fixPublished', () => {
  const { text, json } = run();
  assert.match(text, /EXPOSED +starlette 0\.46\.2 .*uv\.lock\n +fix public for 166 days \(since 2026-06-04\)\n/);
  const row = json.rows.find((r) => r.status === 'EXPOSED');
  assert.equal(row.fixAgeDays, 166); assert.equal(row.fixAge, 'fix public for 166 days (since 2026-06-04)');
  assert.deepEqual(json.json.incidents[0].fixPublished, INC.find((i) => i.id === 'starlette-2026-06').fixPublished);
  // a row that is not EXPOSED carries no fix age
  assert.ok(json.rows.filter((r) => r.status !== 'EXPOSED').every((r) => !('fixAgeDays' in r)));
});

test('F3m mutation proof: a fix date made up for an unknown one, a future date counted, or the line dropped, each fails', async () => {
  let get = await mutatedLib(T.dir, 'clock.mjs', 'const since = fixPublished?.date ?? null;', "const since = fixPublished?.date ?? '2026-01-01';");
  assert.notEqual((await get('clock.mjs')).fixAge({ date: null, why: 'a compromise, not a fixed release' }, today).days, null, 'mutant survived: an invented date');
  get = await mutatedLib(T.dir, 'clock.mjs', '!Number.isFinite(days) || days < 0', '!Number.isFinite(days)');
  assert.notEqual((await get('clock.mjs')).fixAge({ date: '2026-12-01', source: 's' }, today).days, null, 'mutant survived: a future date counted');
  // the command, with the incident loop no longer setting the fix age: the EXPOSED line has none
  const copy = T.fresh('bin');
  for (const d of ['bin', 'lib']) cpSync(join(ROOT, d), join(copy, d), { recursive: true });
  cpSync(join(ROOT, 'package.json'), join(copy, 'package.json'));
  const p = join(copy, 'bin', 'wardlatch.mjs'), src = readFileSync(p, 'utf8'), line = '  fixAgeNow = fixAge(inc.fixPublished, TODAY);\n';
  assert.ok(src.includes(line));
  writeFileSync(p, src.replace(line, ''));
  assert.doesNotMatch(run(p).text, /fix public for/, 'mutant survived: the line dropped');
});
