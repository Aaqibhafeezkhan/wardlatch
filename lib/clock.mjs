// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// How old a list built into Wardlatch is, for a check whose SAFE means "at the newest release we know of". Such a SAFE
// is only as true as the list is current: when Apple ships macOS Tahoe 26.7.4, a Mac on 26.7.3 is behind, and a list
// that still ends at 26.7.3 would call it SAFE until Wardlatch is republished (the pattern review of 16 Nov 2026).
// So once the list is older than STALE_AFTER_DAYS, such a version is REVIEW, never SAFE, and the line says why.
//
// "Now" is the later of the system clock and the newest modification time of a few files the system itself rewrites
// when it is updated, so a clock set back does not make an old list look new. Nothing is run and nothing is sent:
// each file is stat()ed, never opened. A file that can't be read is left out; it can only make "now" later, never earlier.
import { mtimeMs } from './files.mjs';

/** Days a built-in "latest known" list stays trusted for a SAFE. One constant, for every such check (lib/macos.mjs). */
export const STALE_AFTER_DAYS = 21;
const DAY_MS = 86400000;

/** Files whose modification time is a lower bound on today, by platform. Each is rewritten by the system's own updates. */
export const CLOCK_FILES = {
  darwin: [
    '/System/Library/CoreServices/SystemVersion.plist',                                      // every macOS update
    '/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist',         // XProtect's background updates
    '/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist',
    '/private/var/db/receipts',                                                               // a folder: every installed package
  ],
  linux: ['/etc/os-release', '/var/lib/dpkg/status', '/var/lib/rpm', '/var/lib/pacman/local', '/var/lib/apk/db/installed'],
};

/**
 * Today, as the later of the clock and the files' modification times. → { now, from, clock }: `from` names which one
 * won ("the system clock", or "the modification time of <file>"), so a line that rests on it can say so.
 */
export function effectiveNow({ clock = Date.now(), files = CLOCK_FILES[process.platform] ?? [], mtime = mtimeMs } = {}) {
  let best = { now: clock, from: 'the system clock' };
  for (const f of files) {
    const t = mtime(f);
    if (Number.isFinite(t) && t > best.now) best = { now: t, from: `the modification time of ${f}` };
  }
  return { ...best, clock };
}

/** Whole days from `listedOn` (YYYY-MM-DD, UTC) to `now` (ms); NaN when either can't be placed. */
export function listAgeDays(listedOn, now) {
  const at = /^\d{4}-\d{2}-\d{2}$/.test(String(listedOn ?? '')) ? Date.parse(`${listedOn}T00:00:00Z`) : NaN;
  return Number.isFinite(at) && Number.isFinite(now) ? Math.floor((now - at) / DAY_MS) : NaN;
}

/**
 * null when the list read on `listedOn` is at most `maxDays` old as of `today` ({ now, from } from effectiveNow); otherwise
 * { days, reason }. Fails closed: a list date that can't be placed, or a "today" before it (the clock is behind), is stale.
 * `what` names the list ("list of Apple releases"); `check` is the advice that ends the reason.
 */
export function staleList(listedOn, today, { what, check, maxDays = STALE_AFTER_DAYS }) {
  const days = listAgeDays(listedOn, today?.now);
  if (!Number.isFinite(days)) return { days: NaN, reason: `when Wardlatch's ${what} was read (${listedOn || 'not recorded'}) could not be placed against today, so it is not known to be current; ${check}` };
  if (days < 0) return { days, reason: `this machine's date (from ${today.from}) is before ${listedOn}, the day Wardlatch's ${what} was read, so how old that list is can't be known; ${check}` };
  if (days > maxDays) return { days, reason: `Wardlatch's ${what} is ${days} days old (read ${listedOn}; today's date from ${today.from}), and a newer release may have come out since; ${check}` };
  return null;
}
