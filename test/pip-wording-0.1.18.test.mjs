// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// 0.1.18: pip's own CA list (pip/_vendor/certifi/cacert.pem). 0.1.16 and 0.1.17 said, in the README and on the REVIEW
// line, that pip 24.2 and later use it "only with --use-deprecated=legacy-certs". An independent review (13 Nov 2026)
// found that wrong, and pip's own code on this Mac agrees: index_command.py (pip 26.1.2 and 26.2.1) loads
// certifi.where() into its truststore context, and truststore adds those certificates as extra anchors with
// SecTrustSetAnchorCertificatesOnly false, so the list is trusted by default beside the system's trust. This test fails
// if the old wording comes back anywhere a reader is told it, or if the line calls the list harmless. The verdict stays
// REVIEW: whether it should be EXPOSED is the owner's open question.
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipListRows } from '../lib/probe.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const INC = JSON.parse(readFileSync(join(ROOT, 'lib', 'incidents', 'emudhra-2026-10.json'), 'utf8'));
const HELD = readFileSync(join(ROOT, 'test', 'support', 'fixtures', 'macos-27.2-cert.pem'), 'utf8');
let dir;
before(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), 'wardlatch-pipword-'))); });
after(() => rmSync(dir, { recursive: true, force: true }));
const pip = (py, v) => { const d = join(dir, `${py}-${v}`, 'lib', py, 'site-packages'); mkdirSync(join(d, 'pip', '_vendor', 'certifi'), { recursive: true }); if (v) writeFileSync(join(d, 'pip', '__init__.py'), `__version__ = "${v}"\n`); writeFileSync(join(d, 'pip', '_vendor', 'certifi', 'cacert.pem'), HELD); return d; };
// the old claim, in any of the forms 0.1.16 and 0.1.17 printed or published it
const OLD = [/only with[^.]{0,20}--use-deprecated=legacy-certs/i, /only when run with --use-deprecated=legacy-certs/i, /don't use that flag/i, /it takes a flag to be used/i, /use it only with/i];
const SOFT = [/low[- ]risk/i, /harmless/i, /nothing to worry/i];

test('P1 the REVIEW line says the list is trusted by default beside the system\'s trust, for every pip it can name, and never the old claim', () => {
  const [newer, old39, unknown] = pipListRows(INC, [pip('python3.12', '26.2.1'), pip('python3.9', '21.2.4'), pip('pythonX', '')]);
  assert.match(newer.reason, /pip 26\.2 on Python 3\.12 trusts this list by default, together with the system's trust/);
  assert.match(newer.reason, /a withdrawn root in it is trusted by every pip download unless the system blocks the certificate itself/);
  assert.match(newer.reason, /on a macOS without Apple's block, or on Linux, this was not measured/);
  // the built-in Python 3.9 with pip 21.2 uses its own list for every download
  assert.match(old39.reason, /pip 21\.2 on Python 3\.9 uses this list for every download/);
  assert.match(unknown.reason, /pip 24\.2 and later on Python 3\.10 or later trust it by default together with the system's trust/);
  for (const r of [newer, old39, unknown]) {
    assert.equal(r.status, 'REVIEW', 'the verdict is unchanged until the owner decides');
    for (const rx of [...OLD, ...SOFT]) assert.doesNotMatch(r.reason, rx, `${rx} in: ${r.reason}`);
  }
});

test('P2 the README, the code\'s comments and the docs no longer say it', () => {
  for (const f of ['README.md', 'lib/probe.mjs', 'bin/wardlatch.mjs', 'ASSURANCE_CASE.md', 'docs/ARCHITECTURE.md']) {
    const text = readFileSync(join(ROOT, f), 'utf8').replace(/0\.1\.16 and 0\.1\.17 said[^.]*\./g, '');
    for (const rx of OLD) assert.doesNotMatch(text, rx, `${f}: ${rx}`);
  }
  assert.match(readFileSync(join(ROOT, 'README.md'), 'utf8'), /pip 24\.2 and later on Python 3\.10 or later trust it by default, together with the system's trust/);
});
