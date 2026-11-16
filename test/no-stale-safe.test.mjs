// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// fix/no-stale-safe (the pattern review of 16 Nov 2026): a SAFE that means "at the newest release Wardlatch knows" must
// not outlive the list it rests on. macos-2026-11's list of Apple releases was read on 13 Nov 2026; Apple had release
// candidates of Tahoe 26.7.4 and Sequoia 15.8.4 out, and when they ship, a Mac on 26.7.3 is behind. Once the list is
// more than STALE_AFTER_DAYS (21) old, a Mac at its newest release is REVIEW, and "today" is the later of the clock and
// the newest system update file, so a clock set back can't keep it SAFE. Each rule has a planted mutation, applied to a
// copy of lib/, that must turn the verdict table red.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, cpSync, realpathSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { macosUpdateRow } from '../lib/macos.mjs';
import { STALE_AFTER_DAYS, CLOCK_FILES, effectiveNow, listAgeDays, staleList } from '../lib/clock.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'macos-2026-11.json'), 'utf8'));
const DAY = 86400000;
const LISTED = Date.parse(`${INC.latestListed}T00:00:00Z`);
const day = (n) => LISTED + n * DAY + 12 * 3600000;       // noon UTC, n days after the list was read
const clockAt = (n, { file } = {}) => effectiveNow({ clock: day(n), files: file === undefined ? [] : ['/fake/SystemVersion.plist'], mtime: () => (file === undefined ? NaN : day(file)) });
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-stale-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));

test('S0 one named constant, 21 days; the list date is recorded in the incident; the clock reads system update files on both platforms', () => {
  assert.equal(STALE_AFTER_DAYS, 21);
  assert.equal(INC.latestListed, '2026-11-13');
  assert.ok(CLOCK_FILES.darwin.includes('/System/Library/CoreServices/SystemVersion.plist'));
  assert.ok(CLOCK_FILES.linux.length >= 3);
  assert.equal(listAgeDays('2026-11-13', day(20)), 20);
  assert.ok(Number.isNaN(listAgeDays('13 Nov 2026', day(1))) && Number.isNaN(listAgeDays(undefined, day(1))));
});

// the three cases the review asked for, plus the clock set before the list: [what, today, version, want]
const TABLE = [
  ['20 days', () => clockAt(20), '26.7.3', 'SAFE'],
  ['21 days (the limit itself)', () => clockAt(21), '26.7.3', 'SAFE'],
  ['22 days', () => clockAt(22), '26.7.3', 'REVIEW'],
  ['clock set back to 3 days, a system file changed at 22', () => clockAt(3, { file: 22 }), '26.7.3', 'REVIEW'],
  ['clock set before the list was read', () => clockAt(-5), '26.7.3', 'REVIEW'],
  ['a newer major than every line, at 22 days', () => clockAt(22), '28.0', 'REVIEW'],
];
const verdicts = (row, nowOf = (f) => f()) => TABLE.every(([, f, v, want]) => row(INC, v, 'darwin', '25H100', { today: nowOf(f) }).status === want);

test('S1 age 20 and 21 days: SAFE; 22: REVIEW, saying how old the list is and to check Software Update', () => {
  for (const [what, f, v, want] of TABLE) assert.equal(macosUpdateRow(INC, v, 'darwin', '25H100', { today: f() }).status, want, what);
  const r = macosUpdateRow(INC, '26.7.3', 'darwin', '25H100', { today: clockAt(22) });
  assert.match(r.reason, /at or past 26\.7\.3, Apple's latest security release for macOS Tahoe 26 \(9 Nov 2026\); but Wardlatch's list of Apple releases is 22 days old \(read 2026-11-13; today's date from the system clock\), and a newer release may have come out since; check Software Update$/);
  assert.equal(r.fix, INC.fixStale); assert.match(r.fix, /Software Update/);
  assert.equal(r.stale, true); assert.equal(r.searched, undefined, 'a REVIEW carries no SAFE receipt');
});

test('S2 a clock set back can\'t keep it SAFE: a system file changed later than the clock is today', () => {
  const t = clockAt(3, { file: 22 });
  assert.equal(t.now, day(22)); assert.equal(t.from, 'the modification time of /fake/SystemVersion.plist');
  const r = macosUpdateRow(INC, '26.7.3', 'darwin', '25H100', { today: t });
  assert.equal(r.status, 'REVIEW'); assert.match(r.reason, /22 days old .*today's date from the modification time of \/fake\/SystemVersion\.plist/);
  // the control: the same set-back clock with no later file reads SAFE, so it is the file that made the difference
  assert.equal(macosUpdateRow(INC, '26.7.3', 'darwin', '25H100', { today: clockAt(3) }).status, 'SAFE');
  // an older file never moves today back
  assert.equal(clockAt(22, { file: 3 }).now, day(22));
  // with real files: a file changed later than the clock wins; one that isn't there is left out
  const f = join(dir, 'SystemVersion.plist'); writeFileSync(f, 'x'); utimesSync(f, day(30) / 1000, day(30) / 1000);
  const real = effectiveNow({ clock: day(1), files: [join(dir, 'missing'), f] });
  assert.equal(Math.round(real.now / 1000), Math.round(day(30) / 1000)); assert.equal(real.from, `the modification time of ${f}`);
  assert.equal(effectiveNow({ clock: day(1), files: [join(dir, 'missing')] }).from, 'the system clock');
});

test('S3 fails closed: no list date, or a clock before it, is REVIEW; EXPOSED and the other REVIEWs are unchanged by age', () => {
  const { latestListed, ...noDate } = INC;
  const r = macosUpdateRow(noDate, '26.7.3', 'darwin', '25H100', { today: clockAt(1) });
  assert.equal(r.status, 'REVIEW'); assert.match(r.reason, /\(not recorded\) could not be placed against today/);
  assert.match(macosUpdateRow(INC, '26.7.3', 'darwin', '25H100', { today: clockAt(-5) }).reason, /is before 2026-11-13, the day Wardlatch's list of Apple releases was read/);
  for (const n of [1, 400]) {
    assert.equal(macosUpdateRow(INC, '26.7.0', 'darwin', '25H100', { today: clockAt(n) }).status, 'EXPOSED', `${n} days`);
    assert.equal(macosUpdateRow(INC, '26.7.1', 'darwin', '25H100', { today: clockAt(n) }).status, 'REVIEW', `${n} days`);
    assert.doesNotMatch(macosUpdateRow(INC, '26.7.1', 'darwin', '25H100', { today: clockAt(n) }).reason, /days old/);
    assert.equal(macosUpdateRow(INC, '14.8.9', 'darwin', '23J100', { today: clockAt(n) }).status, 'REVIEW');
  }
  // the staleness reason itself, from the helper
  assert.equal(staleList('2026-11-13', clockAt(21), { what: 'x', check: 'y' }), null);
  assert.equal(staleList('2026-11-13', clockAt(22), { what: 'x', check: 'y' }).days, 22);
});

// S4: the planted mutations. Each is a change a careless edit could make, applied as text to a copy of lib/; each must
// make the verdict table above fail, and the copy without a change must pass it (so the copy itself is sound).
const MUTANTS = [
  ['the limit moved two days late (22 reads SAFE)', 'clock.mjs', 'if (days > maxDays) return', 'if (days > maxDays + 2) return'],
  ['the limit moved two days early (20 reads REVIEW)', 'clock.mjs', 'if (days > maxDays) return', 'if (days >= maxDays - 1) return'],
  ['the system files ignored (a clock set back keeps it SAFE)', 'clock.mjs', 'if (Number.isFinite(t) && t > best.now)', 'if (false && t > best.now)'],
  ['a clock before the list allowed', 'clock.mjs', 'if (days < 0) return', 'if (days < -9999) return'],
  ['the staleness rule not applied to the SAFE', 'macos.mjs', 'if (stale) return', 'if (false) return'],
];
const mutantRow = async (name, file, from, to) => {
  const copy = join(dir, `lib-${name.replace(/\W+/g, '-').slice(0, 40)}`);
  cpSync(join(ROOT, 'lib'), copy, { recursive: true });
  if (file) {
    const src = readFileSync(join(copy, file), 'utf8');
    assert.equal(src.split(from).length, 2, `${name}: the text to mutate is in ${file} exactly once`);
    writeFileSync(join(copy, file), src.replace(from, to));
  }
  const m = await import(pathToFileURL(join(copy, 'macos.mjs')).href);
  // the system-file case goes through the copy's own effectiveNow, so a mutation of it is what is measured
  const c = await import(pathToFileURL(join(copy, 'clock.mjs')).href);
  return { row: m.macosUpdateRow, nowOf: (f) => { const t = f(); return t.from === 'the system clock' ? t : c.effectiveNow({ clock: t.clock, files: ['/fake/SystemVersion.plist'], mtime: () => t.now }); } };
};
test('S4 mutation proof: each planted mistake fails the verdict table; the true code, and an unchanged copy, pass it', async () => {
  assert.ok(verdicts(macosUpdateRow), 'the true code passes');
  const same = await mutantRow('unchanged');
  assert.ok(verdicts(same.row, same.nowOf), 'an unchanged copy passes');
  for (const [name, file, from, to] of MUTANTS) {
    const m = await mutantRow(name, file, from, to);
    assert.equal(verdicts(m.row, m.nowOf), false, `mutant survived: ${name}`);
  }
});
