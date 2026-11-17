#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The daily coverage sweep's last step (.github/workflows/coverage-sweep.yml; docs/COVERAGE-PROTOCOL.md): one GitHub
// issue per unnamed item the coverage check found, opened or updated with `gh`, labelled coverage-gap.
//
//   node scripts/coverage/check.mjs --snapshot s.json --json > check.json
//   node scripts/coverage/gap-issues.mjs check.json [--repo owner/name]
//
// One issue per item, found again by its title's start, "Coverage gap: <key> (", in any state: an open one is updated,
// a closed one is reopened (the item is still neither named nor declined, so closing it did not settle it). It only
// opens, edits, labels and reopens issues: it never commits, pushes or opens a pull request. A human writes the
// incident or the decline. A check that was not a complete read files nothing and exits 1.
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { FIRST, classFirst } from './check.mjs';

export const LABEL = 'coverage-gap';
export { FIRST, classFirst };
/** "Coverage gap: <key> (<classes>)", the identity and equivalence classes named first. */
export const titleOf = (g) => `Coverage gap: ${g.key} (${[...g.classes].sort((a, b) => (FIRST.includes(b) - FIRST.includes(a)) || a.localeCompare(b)).join(', ')})`;
export const prefixOf = (key) => `Coverage gap: ${key} (`;

/** The issue text for one gap: what the source says, where, and what a maintainer does next. */
export function bodyOf(g, { read, since } = {}) {
  return [
    `The daily coverage sweep (snapshot read ${read ?? '?'}, window from ${since ?? '?'}) found an item in a class Wardlatch covers that no incident names and no decline covers.`,
    '',
    `- Item: ${g.key}`,
    `- Classes: ${g.classes.join(', ')}`,
    `- Source: ${g.source}${g.kev ? ` (CISA KEV, added ${g.kev.dateAdded})` : ''}`,
    `- Component: ${g.component}`,
    `- Impact: ${g.impact}`,
    ...(g.releases?.length ? [`- Fixed in: ${g.releases.join('; ')}`] : []),
    ...(g.cert ? [`- CERT/CC: ${g.cert}`] : []),
    '',
    'Next: write an incident that names it, or add a one-line decline with a review date to scripts/coverage/declined.json (docs/COVERAGE-PROTOCOL.md). This issue is reopened by the sweep while the item stays a gap.',
  ].join('\n');
}

/**
 * The actions for a check result against the issues that exist (`existing`: [{ number, title, state }]).
 * → [{ do: 'create' | 'edit' | 'reopen', number?, title, body }]: one per gap, class first.
 */
export function plan(result, existing) {
  if (!result?.complete) throw new Error(`the coverage check was not a complete read (${(result?.why ?? ['no result']).join('; ')}): no issues filed`);
  return classFirst(result.gaps ?? []).map((g) => {
    const title = titleOf(g), body = bodyOf(g, result);
    const has = existing.find((i) => typeof i.title === 'string' && i.title.startsWith(prefixOf(g.key)));
    if (!has) return { do: 'create', title, body };
    return { do: String(has.state).toUpperCase() === 'CLOSED' ? 'reopen' : 'edit', number: has.number, title, body };
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const a = process.argv.slice(2);
  const file = a[0], repo = a.includes('--repo') ? a[a.indexOf('--repo') + 1] : process.env.GITHUB_REPOSITORY;
  if (!file || !repo) { console.error('usage: node scripts/coverage/gap-issues.mjs <check.json> [--repo owner/name]'); process.exit(2); }
  const gh = (...args) => execFileSync('gh', [...args, '-R', repo], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  const result = JSON.parse(readFileSync(file, 'utf8'));
  let actions;
  try {
    actions = plan(result, result.gaps?.length ? JSON.parse(gh('issue', 'list', '--label', LABEL, '--state', 'all', '--limit', '1000', '--json', 'number,title,state')) : []);
  } catch (e) { console.error(e.message); process.exit(1); }
  if (actions.length) gh('label', 'create', LABEL, '--color', 'B60205', '--description', 'An in-class fix no incident names and no decline covers', '--force');
  for (const x of actions) {
    if (x.do === 'create') gh('issue', 'create', '--title', x.title, '--body', x.body, '--label', LABEL);
    else {
      if (x.do === 'reopen') gh('issue', 'reopen', String(x.number));
      gh('issue', 'edit', String(x.number), '--title', x.title, '--body', x.body, '--add-label', LABEL);
    }
    console.log(`${x.do} ${x.number ?? ''} ${x.title}`.replace(/ {2}/, ' '));
  }
  console.log(`${actions.length} gap issue(s) filed or updated; ${result.ok ? 'the check passed' : 'the check failed'}`);
  process.exitCode = result.ok ? 0 : 1;
}
