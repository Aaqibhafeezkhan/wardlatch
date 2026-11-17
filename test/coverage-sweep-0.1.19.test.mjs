// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The machine-speed moves (release/0.1.19-candidate), 2 and 4: the daily coverage sweep in CI, and class-first gaps.
// .github/workflows/coverage-sweep.yml runs the refresh and the check every day (and by hand, with no inputs) and files
// one issue per gap with gh. Its token may read the repository and write issues, and nothing else. It must never
// commit, push or open a pull request; the answers to OSPS-BR-01 depend on the no-inputs rule. The file is read as
// text, each rule shown to fail on a planted mutant; scripts/coverage/gap-issues.mjs is run on a stand-in gh.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, chmodSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { plan, titleOf, LABEL } from '../scripts/coverage/gap-issues.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WF = readFileSync(join(ROOT, '.github', 'workflows', 'coverage-sweep.yml'), 'utf8');
const dir = mkdtempSync(join(tmpdir(), 'wardlatch-sweep-'));
after(() => rmSync(dir, { recursive: true, force: true }));

/** → the problems with the sweep workflow's text (none for the real one). */
function problems(text) {
  const p = [];
  const need = (ok, what) => { if (!ok) p.push(what); };
  const on = (/^on:\n((?: {2}.*\n|\n)+?)(?=^\S)/m.exec(text) ?? [])[1] ?? '';
  need(/^ {2}schedule:\n {4}- cron: '[^']+'/m.test(on), 'a daily schedule');
  need(/^ {2}workflow_dispatch:\s*$/m.test(on) && !/^ {4}inputs:/m.test(on) && !/workflow_dispatch:\s*\{/.test(on), 'workflow_dispatch with no inputs');
  need(!/\$\{\{\s*(?:github\.event\.inputs|inputs)\./.test(text), 'no input is read anywhere');
  need(/^permissions:\n {2}contents: read\n\n?jobs:/m.test(text), 'the workflow\'s default token reads contents only');
  const jobs = text.slice(text.indexOf('\njobs:\n')).split(/\n(?= {2}[a-z][\w-]*:\n)/).slice(1);
  need(jobs.length === 1, `one job (${jobs.length})`);
  const perms = (/^ {4}permissions:\n((?: {6}.*\n)+)/m.exec(jobs[0] ?? '') ?? [])[1] ?? '';
  need(JSON.stringify(perms.split('\n').filter(Boolean).map((l) => l.replace(/#.*/, '').trim()).sort()) === JSON.stringify(['contents: read', 'issues: write']), `the job's permissions are contents: read and issues: write only (${perms.trim()})`);
  for (const m of text.matchAll(/^\s*(?:- )?uses:\s*(\S+)(.*)$/gm)) need(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/.test(m[1]) && /#\s*v\d/.test(m[2]), `not pinned by commit: ${m[1]}`);
  need(/actions\/checkout@[0-9a-f]{40}.*\n\s+with: \{ persist-credentials: false \}/.test(text), 'checkout keeps no credentials');
  need(!/\bgit\s+(?:push|commit|tag|config)\b|\bgh\s+pr\b|pull-requests|contents:\s*write|\bgh\s+api\b.*-X\s*(?:PUT|POST|PATCH|DELETE)|create-pull-request|git-auto-commit/i.test(text), 'no commit, push, tag or pull request');
  need(/node scripts\/coverage\/refresh\.mjs --out "\$RUNNER_TEMP\//.test(text), 'the snapshot is written to the runner\'s temp folder, not the repository');
  need(/node scripts\/coverage\/check\.mjs --snapshot "\$RUNNER_TEMP\/coverage-snapshot\.json" --json/.test(text), 'the check reads that snapshot');
  need(/node scripts\/coverage\/gap-issues\.mjs "\$RUNNER_TEMP\/coverage-check\.json" --repo "\$GITHUB_REPOSITORY"/.test(text) && /GH_TOKEN: \$\{\{ github\.token \}\}/.test(text), 'the issues are filed with the job\'s own token');
  need(!/\$\{\{\s*secrets\./.test(text), 'no secret');
  return p;
}

test('W1 the sweep workflow: daily and by hand with no inputs; contents: read and issues: write only; never a commit, push or PR', () => {
  assert.deepEqual(problems(WF), []);
});

test('W1m mutation proof: each planted change to the workflow is caught', () => {
  const mutants = {
    'an input': ['  workflow_dispatch:\n', '  workflow_dispatch:\n    inputs:\n      months: { default: "6" }\n'],
    'no schedule': ["  schedule:\n    - cron: '17 6 * * *'     # every day, 06:17 UTC\n", ''],
    'pull-requests: write': ['      issues: write          # open, edit and reopen the gap issues\n', '      issues: write          # open, edit and reopen the gap issues\n      pull-requests: write\n'],
    'contents: write': ['      contents: read         # check out', '      contents: write        # check out'],
    'no issues: write': ['      issues: write          # open', '      issues: read           # open'],
    'credentials kept': ['with: { persist-credentials: false }', 'with: { persist-credentials: true }'],
    'a push': ['      - name: Open or update one issue per gap\n', '      - name: Save the snapshot\n        run: git add -A && git commit -m snap && git push\n      - name: Open or update one issue per gap\n'],
    'a tag instead of a pin': ['actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1', 'actions/setup-node@v7'],
    'the snapshot written into the repository': ['refresh.mjs --out "$RUNNER_TEMP/coverage-snapshot.json"', 'refresh.mjs'],
    'a personal token': ['GH_TOKEN: ${{ github.token }}', 'GH_TOKEN: ${{ secrets.SWEEP_TOKEN }}'],
    'a second job': ['\n      - name: Read the sources', '\n  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n      - name: Read the sources'],
  };
  for (const [what, [from, to]] of Object.entries(mutants)) {
    assert.ok(WF.includes(from), `the mutant's text is in the workflow: ${what}`);
    assert.notDeepEqual(problems(WF.replace(from, to)), [], `mutant survived: ${what}`);
  }
});

const gap = (key, classes, extra = {}) => ({ key, classes, source: 'apple-macos', component: 'C', impact: 'I', releases: ['macOS X'], ...extra });
const RESULT = { complete: true, ok: false, read: '2026-11-17T06:17:00Z', since: '2026-05-17', gaps: [gap('CVE-2026-1', ['privacy']), gap('CVE-2026-2', ['equivalence', 'sandbox']), gap('CVE-2026-3', ['identity', 'privacy']), gap('CVE-2026-4', ['exploited'], { source: 'cisa-kev', kev: { dateAdded: '2026-11-16' } })] };

test('W2 gap issues: one per item, titled "Coverage gap: <CVE> (<classes>)", identity and equivalence first; found again by title, reopened if closed', () => {
  assert.equal(titleOf(gap('CVE-2026-2', ['sandbox', 'equivalence'])), 'Coverage gap: CVE-2026-2 (equivalence, sandbox)');
  const a = plan(RESULT, [{ number: 7, title: 'Coverage gap: CVE-2026-1 (privacy)', state: 'OPEN' }, { number: 9, title: 'Coverage gap: CVE-2026-2 (sandbox)', state: 'CLOSED' }, { number: 11, title: 'Coverage gap: CVE-2026-10 (privacy)', state: 'OPEN' }]);
  assert.deepEqual(a.map((x) => [x.do, x.number, x.title]), [
    ['create', undefined, 'Coverage gap: CVE-2026-3 (identity, privacy)'],
    ['reopen', 9, 'Coverage gap: CVE-2026-2 (equivalence, sandbox)'],
    ['edit', 7, 'Coverage gap: CVE-2026-1 (privacy)'],
    ['create', undefined, 'Coverage gap: CVE-2026-4 (exploited)'],
  ]);
  assert.match(a[3].body, /CISA KEV, added 2026-11-16/);
  // an incomplete read files nothing
  assert.throws(() => plan({ ...RESULT, complete: false, why: ['cisa-kev: short'] }, []), /not a complete read \(cisa-kev: short\)/);
  assert.deepEqual(plan({ ...RESULT, gaps: [] }, []), []);
});

test('W3 the script on a stand-in gh: lists the label\'s issues, then creates, reopens and edits; exits 1 while the check fails', () => {
  const bin = join(dir, 'bin'), log = join(dir, 'gh.log'), file = join(dir, 'check.json');
  spawnSync('mkdir', ['-p', bin]);
  writeFileSync(join(bin, 'gh'), `#!/bin/sh\nprintf '%s' "$*" | tr '\\n' ' ' >> "${log}"; echo >> "${log}"\nif [ "$1 $2" = "issue list" ]; then echo '[{"number":9,"title":"Coverage gap: CVE-2026-2 (sandbox)","state":"CLOSED"}]'; fi\n`);
  chmodSync(join(bin, 'gh'), 0o755);
  writeFileSync(file, JSON.stringify(RESULT));
  const r = spawnSync(process.execPath, [join(ROOT, 'scripts', 'coverage', 'gap-issues.mjs'), file, '--repo', 'o/r'], { encoding: 'utf8', env: { PATH: `${bin}:/usr/bin:/bin` } });
  assert.equal(r.status, 1, r.stderr);
  const calls = readFileSync(log, 'utf8').trim().split('\n');
  assert.match(calls[0], new RegExp(`^issue list --label ${LABEL} --state all --limit 1000 --json number,title,state -R o/r$`));
  assert.match(calls[1], /^label create coverage-gap /);
  assert.ok(calls.some((c) => /^issue create --title Coverage gap: CVE-2026-3 \(identity, privacy\) /.test(c)), calls.join('\n'));
  assert.ok(calls.some((c) => c === 'issue reopen 9 -R o/r'), calls.join('\n'));
  assert.equal(calls.filter((c) => /^issue create /.test(c)).length, 3);
  assert.ok(calls.every((c) => /^(issue (list|create|edit|reopen)|label create) /.test(c)), 'nothing but issues and the label');
  // an incomplete read: gh is never asked to write
  writeFileSync(log, ''); writeFileSync(file, JSON.stringify({ ...RESULT, complete: false, why: ['x'] }));
  assert.equal(spawnSync(process.execPath, [join(ROOT, 'scripts', 'coverage', 'gap-issues.mjs'), file, '--repo', 'o/r'], { encoding: 'utf8', env: { PATH: `${bin}:/usr/bin:/bin` } }).status, 1);
  assert.doesNotMatch(readFileSync(log, 'utf8'), /create|edit|reopen/);
});
