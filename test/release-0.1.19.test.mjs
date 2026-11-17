// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.19's release extras, held in place: .github/workflows/release.yml publishes to npm through trusted publishing
// (GitHub's OIDC token, no npm token) only after the release job's approval, tests, attestation and checks, and only
// the exact package it attested; it attests the npm package's SBOM with actions/attest-sbom and attaches both; every
// action is pinned by commit. Workflows cannot run here, so the file is read as text (Wardlatch has no YAML parser and
// no dependencies), and each rule below is shown to fail on a planted mutant of the file.
import './support/no-real-home.cjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bindSbom } from '../scripts/sbom.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (f) => readFileSync(join(ROOT, f), 'utf8');
const WF = read('.github/workflows/release.yml');
const dir = mkdtempSync(join(tmpdir(), 'wardlatch-rel0119-'));
after(() => rmSync(dir, { recursive: true, force: true }));

/** The top-level jobs of a workflow's text: { name: its block }. */
const jobsOf = (text) => {
  const body = text.slice(text.indexOf('\njobs:\n') + 7);
  const out = {}; let name = null;
  for (const line of body.split('\n')) {
    const m = /^ {2}([A-Za-z][\w-]*):\s*$/.exec(line);
    if (m) { name = m[1]; out[name] = ''; continue; }
    if (name) out[name] += `${line}\n`;
  }
  return out;
};
/** A job's steps, in order: [{ name, text }]. */
const stepsOf = (job) => job.split(/\n(?= {6}- )/).slice(1).map((t) => ({ name: (/name: (.+)/.exec(t) ?? /uses: (\S+)/.exec(t) ?? [])[1] ?? '', text: t }));
const at = (steps, re) => steps.findIndex((s) => re.test(s.text));

/** → the problems with a release workflow's text (none for the real one). */
function problems(text) {
  const p = [];
  const need = (ok, what) => { if (!ok) p.push(what); };
  // every action pinned by a full commit, with the version beside it
  for (const m of text.matchAll(/^\s*(?:- )?uses:\s*(\S+)(.*)$/gm)) need(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/.test(m[1]) && /#\s*v\d/.test(m[2]), `not pinned by commit: ${m[1]}`);
  // no npm token, anywhere: trusted publishing only
  need(!/\$\{\{\s*secrets\./.test(text), 'a secret is referenced');
  need(!/registry-url|always-auth|_authToken\s*=|(?:NODE_AUTH_TOKEN|NPM_TOKEN)(?:\s*:\s|=)/.test(text), 'an npm token is configured');
  need((text.match(/npm publish/g) ?? []).length === 1, 'npm publish appears other than once');
  const jobs = jobsOf(text);
  const rel = jobs.release ?? '', npm = jobs.npm ?? '';
  need(rel && npm, 'the release and npm jobs');
  need(/^ {4}environment: release\b/m.test(rel), 'the release job waits for the release environment');
  // the npm job: after the release job, in the release environment, with only these permissions
  need(/^ {4}needs: release\s*$/m.test(npm), 'the npm job needs the release job');
  need(/^ {4}environment: release\s*$/m.test(npm), 'the npm job is in the release environment (npm\'s trusted publisher names it)');
  const perms = (/^ {4}permissions:\n((?: {6}.*\n)+)/m.exec(npm) ?? [])[1] ?? '';
  need(JSON.stringify(perms.split('\n').filter(Boolean).map((l) => l.replace(/#.*/, '').trim()).sort()) === JSON.stringify(['contents: read', 'id-token: write']), `the npm job's permissions are contents: read and id-token: write only (${perms.trim()})`);
  need(/^ {6}run: \{ shell: bash \}/m.test(npm) && /^ {6}run: \{ shell: bash \}/m.test(rel), 'both jobs run bash with pipefail');
  need(!/actions\/checkout/.test(npm), 'the npm job publishes the release\'s file, not a checkout');
  const ns = stepsOf(npm);
  const setup = at(ns, /actions\/setup-node@/), guard = at(ns, /trusted publishing \(11\.5\.1 or later\)/), dl = at(ns, /gh release download/);
  const check = at(ns, /sha256sum -c -[\s\S]*gh attestation verify/), pub = at(ns, /npm publish/);
  need(/node-version: '2[4-9]'/.test(ns[setup]?.text ?? ''), 'Node 24 or later, whose npm can do trusted publishing');
  need(setup >= 0 && guard > setup && dl > guard && check > dl && pub > check, `the npm job's order: setup, npm and token guard, download, digest and attestation check, publish (${[setup, guard, dl, check, pub]})`);
  need(/NODE_AUTH_TOKEN:-\}\$\{NPM_TOKEN:-\}.*exit 1/.test(ns[guard]?.text ?? '') && /ACTIONS_ID_TOKEN_REQUEST_URL/.test(ns[guard]?.text ?? ''), 'the guard refuses a token and requires the OIDC token');
  need(/SHA: \$\{\{ needs\.release\.outputs\.tgz-sha256 \}\}/.test(ns[check]?.text ?? '') && /--signer-workflow "\$GITHUB_REPOSITORY\/\.github\/workflows\/release\.yml" --source-ref "\$GITHUB_REF" --deny-self-hosted-runners/.test(ns[check]?.text ?? ''), 'the check uses the release job\'s digest and verifies the attestation for this tag');
  need(/grep -qx "\$SHA {2}wardlatch-\$VERSION\.tgz" SHA256SUMS/.test(ns[check]?.text ?? ''), 'the release\'s SHA256SUMS names the same digest');
  need(/echo "\$SHA {2}wardlatch-\$VERSION\.tgz" \| sha256sum -c -\n\s+npm publish "\.\/wardlatch-\$VERSION\.tgz" --provenance --access public\n/.test(ns[pub]?.text ?? ''), 'the publish step checks the digest again and publishes that file with --provenance --access public');
  // the release job: its digest out, both attestations checked before anything is published, the SBOM attached
  need(/tgz-sha256: \$\{\{ steps\.built\.outputs\.tgz-sha256 \}\}/.test(rel) && /echo "tgz-sha256=\$\(sha256sum "wardlatch-\$VERSION\.tgz" \| cut -d' ' -f1\)" >> "\$GITHUB_OUTPUT"/.test(rel), 'the release job outputs the package\'s digest');
  const rs = stepsOf(rel);
  const att = at(rs, /attest-build-provenance@/), attCheck = at(rs, /Check the attestation before publishing/);
  const sbom = at(rs, /node scripts\/sbom\.mjs "wardlatch-\$VERSION\.tgz" "wardlatch-\$VERSION\.spdx\.json"/), sAtt = at(rs, /actions\/attest-sbom@/);
  const sCheck = at(rs, /--predicate-type https:\/\/spdx\.dev\/Document\/v2\.3/), create = at(rs, /gh release create/);
  need(att >= 0 && attCheck > att && sbom > attCheck && sAtt > sbom && sCheck > sAtt && create > sCheck, `the release job's order: attest, check, SBOM, attest the SBOM, check it, release (${[att, attCheck, sbom, sAtt, sCheck, create]})`);
  need(/subject-path: wardlatch-\$\{\{ env\.VERSION \}\}\.tgz\n\s+sbom-path: wardlatch-\$\{\{ env\.VERSION \}\}\.spdx\.json/.test(rs[sAtt]?.text ?? ''), 'the SBOM is attested for the npm package');
  need(/npm sbom --sbom-format spdx/.test(rs[sbom]?.text ?? ''), 'npm sbom is the base where npm has it');
  need(/"wardlatch-\$VERSION\.spdx\.json" "wardlatch-\$VERSION\.spdx\.json\.sigstore\.json"/.test(rs[create]?.text ?? ''), 'the release carries the SBOM and its bundle');
  need(/sha256sum "wardlatch-\$GITHUB_REF_NAME\.tar\.gz" "wardlatch-\$VERSION\.tgz" \| tee SHA256SUMS/.test(rel), 'SHA256SUMS names the two release files only (scripts/reproduce-release.sh)');
  return p;
}

test('release.yml: npm trusted publishing of the attested package, the SBOM attested and attached, every action pinned', () => {
  assert.deepEqual(problems(WF), []);
});

test('release.yml mutation proof: each planted change to the workflow is caught', () => {
  const mutants = {
    'an npm token': ['run: npm publish', 'run: npm publish'], // replaced below
    'the publish job not waiting for the release job': ['    needs: release\n', ''],
    'the publish job outside the release environment': ['  npm:\n    needs: release\n    runs-on: ubuntu-latest\n    environment: release\n', '  npm:\n    needs: release\n    runs-on: ubuntu-latest\n'],
    'contents: write on the npm job': ['      contents: read         # download', '      contents: write        # download'],
    'no id-token on the npm job': ['      id-token: write        # the OIDC token npm', '      actions: read          # the OIDC token npm'],
    'no provenance': ['--provenance --access public', '--access public'],
    'the digest check dropped before publishing': ['          echo "$SHA  wardlatch-$VERSION.tgz" | sha256sum -c -\n          npm publish', '          npm publish'],
    'the attestation check dropped': ['--source-ref "$GITHUB_REF" --deny-self-hosted-runners', '--deny-self-hosted-runners'],
    'publishing a fresh pack': ['npm publish "./wardlatch-$VERSION.tgz"', 'npm publish'],
    'Node 22 (npm 10)': ["with: { node-version: '24' }", "with: { node-version: '22' }"],
    'the token guard dropped': ['if [ -n "${NODE_AUTH_TOKEN:-}${NPM_TOKEN:-}" ]; then echo "::error::an npm token is set; this job publishes only through trusted publishing"; exit 1; fi', 'true'],
    'attest-sbom by tag': ['actions/attest-sbom@c604332985a26aa8cf1bdc465b92731239ec6b9e', 'actions/attest-sbom@v4'],
    'the SBOM check dropped': ['--predicate-type https://spdx.dev/Document/v2.3', ''],
    'the SBOM not attached': ['"wardlatch-$VERSION.spdx.json" "wardlatch-$VERSION.spdx.json.sigstore.json"', ''],
    'the SBOM attested for the source archive': ['subject-path: wardlatch-${{ env.VERSION }}.tgz\n          sbom-path', 'subject-path: wardlatch-${{ github.ref_name }}.tar.gz\n          sbom-path'],
    'SHA256SUMS naming the SBOM too': ['"wardlatch-$VERSION.tgz" | tee SHA256SUMS', '"wardlatch-$VERSION.tgz" "wardlatch-$VERSION.spdx.json" | tee SHA256SUMS'],
    'no pipefail on the npm job': ['    defaults:\n      run: { shell: bash }\n    steps:\n      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1  # v7.1.0\n        with: { node-version: \'24\' }', '    steps:\n      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1  # v7.1.0\n        with: { node-version: \'24\' }'],
  };
  mutants['an npm token'] = ['        working-directory: pkg\n        run: |\n          echo "$SHA  wardlatch-$VERSION.tgz" | sha256sum -c -\n          npm publish', '        working-directory: pkg\n        run: |\n          echo "$SHA  wardlatch-$VERSION.tgz" | sha256sum -c -\n          NODE_AUTH_TOKEN=${{ secrets.NPM_TOKEN }} npm publish'];
  for (const [what, [from, to]] of Object.entries(mutants)) {
    assert.ok(WF.includes(from), `the mutant's text is in release.yml: ${what}`);
    assert.notDeepEqual(problems(WF.replace(from, to)), [], `mutant survived: ${what}`);
  }
});

test('docs/RELEASING.md names the one-time trusted-publisher setup and keeps the manual publish as a 2FA fallback', () => {
  const doc = read('docs/RELEASING.md');
  assert.match(doc, /Trusted publish(?:ing|er)/);
  for (const s of ['deimos-hq', 'wardlatch', 'release.yml', '`release`']) assert.ok(doc.includes(s), s);
  assert.match(doc, /npm publish \.\/wardlatch-X\.Y\.Z\.tgz/);
  assert.match(doc, /2FA|two-factor/);
  assert.doesNotMatch(doc, /The workflow never publishes to npm/);
});

// ---------------------------------------------------------------- scripts/sbom.mjs

const PKG = JSON.parse(read('package.json'));
const SHA = 'a'.repeat(64);
// npm 11's `npm sbom --sbom-format spdx --sbom-type library` for this package (its shape, measured 16 Nov 2026)
const npmOut = (v = PKG.version, extra = []) => ({
  spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT', name: `wardlatch@${v}`,
  documentNamespace: `http://spdx.org/spdxdocs/wardlatch-${v}-x`, creationInfo: { created: '2026-11-17T00:00:00.000Z', creators: ['Tool: npm/cli-11.20.0'] },
  documentDescribes: [`SPDXRef-Package-wardlatch-${v}`],
  packages: [{ name: 'wardlatch', SPDXID: `SPDXRef-Package-wardlatch-${v}`, versionInfo: v, packageFileName: '', downloadLocation: 'NOASSERTION', filesAnalyzed: false, licenseDeclared: 'Apache-2.0' }, ...extra],
  relationships: [],
});

test('sbom: npm\'s SPDX, or a minimal one, bound to the package file\'s name, SHA-256 and npm URL; exactly one package', () => {
  const tgzName = `wardlatch-${PKG.version}.tgz`;
  for (const npmSbom of [npmOut(), null]) {
    const d = bindSbom({ pkg: PKG, tgzName, sha256: SHA, npmSbom, now: new Date('2026-11-16T00:00:00Z') });
    assert.equal(d.spdxVersion, 'SPDX-2.3');
    assert.deepEqual(d.documentDescribes, [`SPDXRef-Package-wardlatch-${PKG.version}`]);
    assert.equal(d.packages.length, 1);
    assert.deepEqual([d.packages[0].packageFileName, d.packages[0].checksums, d.packages[0].downloadLocation, d.packages[0].licenseDeclared],
      [tgzName, [{ algorithm: 'SHA256', checksumValue: SHA }], `https://registry.npmjs.org/wardlatch/-/${tgzName}`, 'Apache-2.0']);
  }
  // refused: a dependency, another version, a file named for another version, a missing digest, a declared dependency
  const refuse = (args, re) => assert.throws(() => bindSbom({ pkg: PKG, tgzName, sha256: SHA, npmSbom: npmOut(), ...args }), re);
  refuse({ npmSbom: npmOut(PKG.version, [{ name: 'left-pad', SPDXID: 'SPDXRef-Package-left-pad-1.3.0', versionInfo: '1.3.0' }]) }, /lists 2 packages/);
  refuse({ npmSbom: npmOut('0.0.1') }, /not wardlatch@/);
  refuse({ tgzName: 'wardlatch-0.0.1.tgz' }, /not wardlatch-/);
  refuse({ sha256: '' }, /no SHA-256/);
  refuse({ pkg: { ...PKG, dependencies: { 'left-pad': '1.3.0' } } }, /declares dependencies/);
});

test('sbom: the script run on a package file writes its SBOM with the file\'s real digest, and refuses a wrong name', () => {
  const tgz = join(dir, `wardlatch-${PKG.version}.tgz`), out = join(dir, 'out.spdx.json');
  writeFileSync(tgz, 'not really a tarball, but bytes with a digest');
  const sha = createHash('sha256').update(readFileSync(tgz)).digest('hex');
  const run = (args) => spawnSync(process.execPath, [join(ROOT, 'scripts', 'sbom.mjs'), ...args], { encoding: 'utf8' });
  const r = run([tgz, out]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(readFileSync(out, 'utf8')).packages[0].checksums[0].checksumValue, sha);
  const npm = join(dir, 'npm.json'); writeFileSync(npm, JSON.stringify(npmOut()));
  assert.equal(run([tgz, out, npm]).status, 0);
  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')).creationInfo.creators, ['Tool: npm/cli-11.20.0']);
  const wrong = join(dir, 'wardlatch-0.0.1.tgz'); writeFileSync(wrong, 'x');
  const w = run([wrong, join(dir, 'never.json')]);
  assert.equal(w.status, 1);
  assert.match(w.stderr, /not wardlatch-/);
  assert.equal(run([]).status, 2);
});
