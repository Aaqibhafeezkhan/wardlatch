// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Reading Apple's security pages as data, for the coverage check (docs/COVERAGE-PROTOCOL.md). Pure functions over the
// HTML text: no network, no files. scripts/coverage/refresh-apple.mjs fetches the pages and calls these; the test
// (test/coverage-protocol.test.mjs) calls them on the committed snapshot and on planted pages.
//
// Every reader here is held to a completeness gate, not only to a positive control: a page whose CVE numbers are not
// all placed in an entry is an error, never a shorter list (a parser that read one entry of 30 would otherwise pass).

// One pass, one table: each entity is decoded exactly once, so "&amp;lt;" becomes the text "&lt;", never "<" (CodeQL
// js/double-escaping). The output is plain text for matching CVE ids; it is never rendered as HTML.
const ENTITIES = { '&nbsp;': ' ', '&#160;': ' ', '&amp;': '&', '&quot;': '"', '&#39;': "'", '&rsquo;': "'", '&#8217;': "'", '&lt;': '<', '&gt;': '>' };
const decode = (s) => String(s).replace(/&(?:nbsp|#160|amp|quot|#39|rsquo|#8217|lt|gt);/g, (e) => ENTITIES[e]);
// Remove until nothing changes, so a fragment rebuilt by one removal ("<scr<script>ipt>") is removed too, and match
// end tags with optional spaces ("</script >") (CodeQL js/incomplete-multi-character-sanitization, js/bad-tag-filter).
const stripAll = (s, re) => { let prev; do { prev = s; s = s.replace(re, ''); } while (s !== prev); return s; };
/** The visible text of an HTML fragment: scripts and styles dropped, block ends as line breaks, spaces collapsed. */
export function htmlText(html) {
  let s = stripAll(String(html ?? ''), /<script\b[\s\S]*?<\/script\s*>/gi);
  s = stripAll(s, /<style\b[\s\S]*?<\/style\s*>/gi);
  s = s.replace(/<(br|\/p|\/h\d|\/li|\/tr|\/td|\/div)\b[^>]*>/gi, '\n');
  s = stripAll(s, /<[^<>]*>/g).replace(/[<>]/g, ' ');
  return decode(s).split('\n').map((l) => l.replace(/\s+/g, ' ').trim()).filter(Boolean).join('\n');
}

export const CVE_RE = /CVE-\d{4}-\d{4,}/g;
const MONTHS = { Jan: 1, Feb: 2, Mar: 3, Apr: 4, May: 5, Jun: 6, Jul: 7, Aug: 8, Sep: 9, Oct: 10, Nov: 11, Dec: 12 };
/** "17 Aug 2026" → "2026-08-17", or '' when it is not that shape. */
export function isoDate(s) {
  const m = /^(\d{1,2}) ([A-Z][a-z]{2}) (\d{4})$/.exec(String(s ?? '').trim());
  if (!m || !MONTHS[m[2]]) return '';
  return `${m[3]}-${String(MONTHS[m[2]]).padStart(2, '0')}-${m[1].padStart(2, '0')}`;
}

/**
 * The rows of Apple's security releases index (support.apple.com/en-us/100100): [{ name, url, availableFor, date,
 * noCves }]. `url` is '' for a row Apple gives no page ("This update has no published CVE entries", noCves true).
 * Throws when the table can't be read whole: a row without three cells or without a date in Apple's form.
 */
export function parseIndex(html) {
  const rows = [];
  const trs = String(html ?? '').split(/<tr\b[^>]*>/i).slice(1);
  for (const tr of trs) {
    const cells = tr.split(/<td\b[^>]*>/i).slice(1);
    if (!cells.length) continue;                                   // a header row (<th>)
    if (cells.length < 3) throw new Error(`index row with ${cells.length} cells: ${htmlText(tr).slice(0, 80)}`);
    const a = /<a\b[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/i.exec(cells[0]);
    const first = htmlText(cells[0]).split('\n');
    const name = a ? htmlText(a[2]) : first[0];
    const date = isoDate(htmlText(cells[2]).split('\n')[0]);
    if (!name || !date) throw new Error(`index row not read whole: ${htmlText(tr).slice(0, 120)}`);
    const noCves = /no published CVE entries/i.test(htmlText(cells[0]));
    if (!a && !noCves) throw new Error(`index row ${name} has neither a page nor Apple's "no published CVE entries"`);
    rows.push({ name, url: a ? a[1] : '', availableFor: htmlText(cells[1]).replace(/\n/g, ' '), date, noCves });
  }
  if (!rows.length) throw new Error('no rows read from the index');
  return rows;
}

/** A macOS release row ("macOS Tahoe 26.6.2", "macOS Golden Gate 27"): { line, version } or null. */
export function macosRelease(name) {
  const m = /^macOS ([A-Z][A-Za-z]+(?: [A-Z][A-Za-z]+)?) (\d+(?:\.\d+){0,2})$/.exec(String(name ?? '').trim());
  return m ? { line: m[1], version: m[2] } : null;
}

/**
 * One release's security notes page → { title, released, entries: [{ component, impact, description, cves }],
 * cves }. An entry is Apple's block: a component line, "Available for:", "Impact:", "Description:", then one or more
 * "CVE-…" lines. Completeness gate: every CVE number in the page's text from its title to "Additional recognition"
 * (or its end) must be in an entry, and every entry must have an Impact and a CVE; otherwise this throws.
 */
export function parseNotes(html) {
  const text = htmlText(html);
  const lines = text.split('\n');
  const start = lines.findIndex((l) => /^About the security content of /.test(l) && !/ - Apple Support$/.test(l));
  if (start < 0) throw new Error('no "About the security content of" heading');
  const title = lines[start].replace(/^About the security content of /, '');
  let end = lines.findIndex((l, i) => i > start && /^Additional recognition$/.test(l));
  const stop = lines.findIndex((l, i) => i > start && /^(Helpful\?|Information about products not manufactured by Apple)/.test(l));
  if (end < 0) end = stop < 0 ? lines.length : stop;
  const body = lines.slice(start, end);
  const released = (body.find((l) => /^Released /.test(l)) ?? '').replace(/^Released /, '');
  const entries = [];
  for (let i = 0; i < body.length; i++) {
    if (!/^Available for: /.test(body[i])) continue;
    const component = body[i - 1] ?? '';
    const impact = /^Impact: /.test(body[i + 1] ?? '') ? body[i + 1].replace(/^Impact: /, '') : '';
    const description = /^Description: /.test(body[i + 2] ?? '') ? body[i + 2].replace(/^Description: /, '') : '';
    const cves = [];
    for (let j = i + 3; j < body.length && !/^Available for: /.test(body[j + 1] ?? '') && !/^Available for: /.test(body[j]); j++) {
      const m = /^(CVE-\d{4}-\d{4,})/.exec(body[j]);
      if (m) cves.push(m[1]);
    }
    if (!component || !impact) throw new Error(`${title}: entry "${component}" not read whole (impact missing)`);
    // Apple prints some entries with no CVE number (macOS Sequoia 15.8's first three Shortcuts entries): kept, with
    // cves [], and the coverage check names them by release, component and place, never drops them
    entries.push({ component, impact, description, cves });
  }
  const placed = new Set(entries.flatMap((e) => e.cves));
  const named = new Set(body.join('\n').match(CVE_RE) ?? []);
  const loose = [...named].filter((c) => !placed.has(c));
  if (loose.length) throw new Error(`${title}: ${loose.length} CVE number(s) on the page in no entry read: ${loose.slice(0, 5).join(', ')}`);
  return { title, released, entries, cves: [...placed].sort() };
}
