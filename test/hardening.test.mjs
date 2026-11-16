// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The command needs no write access: it runs, and gives the same answer, under Node's permission model with reading
// and child processes allowed and nothing else (no file writes, no worker threads, no native add-ons, no WASI). This is
// the README's "changes nothing" checked from outside the code rather than by reading it (test/conventions.test.mjs
// reads it). What the permission model does not cover, said plainly: the programs Wardlatch starts (git, curl, the
// runtimes it checks) are not Node and are not restricted by it, and in the Node versions this runs on it does not
// restrict network connections. A person can run Wardlatch this way themselves (docs/SECURITY-REVIEW.md).
import './support/no-real-home.cjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'wardlatch.mjs');
const HIDE_PHP = ['--require', join(ROOT, 'test', 'support', 'hide-php-places.cjs')];
// Stable as --permission from Node 22.13 and 23.5; Node 20 has only --experimental-permission, Node 18 neither.
const HAS = process.allowedNodeEnvironmentFlags.has('--permission');
const SKIP = HAS ? false : `this Node (${process.version}) has no --permission flag`;
const LOCKED = ['--permission', '--allow-fs-read=*', '--allow-child-process'];
let dir, home;

const ownEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_[A-Z_]+|GOENV|GOTOOLCHAIN)$/.test(k)));
const node = (nodeArgs, args, env = {}) => {
  const r = spawnSync(process.execPath, [...nodeArgs, ...args], { encoding: 'utf8', env: { ...ownEnv(), HOME: home, ...env }, maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

before(() => { dir = mkdtempSync(join(tmpdir(), 'wardlatch-perm-')); home = mkdtempSync(join(tmpdir(), 'wardlatch-perm-home-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); });

test('control: under the same flags, a write from Node is refused (so the model is on and the flags mean what they say)', { skip: SKIP }, () => {
  const target = join(dir, 'written');
  const code = `require('node:fs').writeFileSync(${JSON.stringify(target)}, 'x')`;
  const locked = node(LOCKED, ['-e', code]);
  assert.notEqual(locked.code, 0);
  assert.match(locked.err, /ERR_ACCESS_DENIED/);
  assert.equal(existsSync(target), false);
  const open = node([], ['-e', code]);
  assert.equal(open.code, 0, open.err);
  assert.equal(existsSync(target), true);
});

test('every incident except the network trust check gives the same answer with no write permission', { skip: SKIP }, () => {
  // a vulnerable php on a private PATH, so the run has an EXPOSED line, not only SAFE ones
  const bin = join(dir, 'bin'); mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'php'), '#!/bin/sh\necho "PHP 8.4.26 (cli)"\n', { mode: 0o755 });
  const ids = readdirSync(join(ROOT, 'lib', 'incidents')).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5))
    .filter((id) => id !== 'emudhra-2026-10');                       // its probes need the advisory's public test hosts
  assert.ok(ids.length >= 15, `only ${ids.length} incidents`);
  const args = [BIN, ...ids.flatMap((id) => ['--incident', id]), '--no-containers', '--json', '--paths', dir];
  const env = { PATH: `${bin}:/usr/bin:/bin` };
  const plain = node(HIDE_PHP, args, env);
  const locked = node([...LOCKED, ...HIDE_PHP], args, env);
  assert.doesNotMatch(locked.err, /ERR_ACCESS_DENIED/, locked.err);
  assert.equal(plain.code, 1, plain.err);
  assert.equal(locked.code, plain.code, locked.err);
  const a = JSON.parse(plain.out), b = JSON.parse(locked.out);
  assert.deepEqual(a.incidents.map((i) => i.id).sort(), ids.slice().sort());
  assert.deepEqual(b.incidents.map((i) => i.id), a.incidents.map((i) => i.id));
  assert.deepEqual(b.results, a.results);
  assert.ok(a.results.some((r) => r.status === 'EXPOSED' && r.incident === 'php-2026-10'), 'the planted php is EXPOSED');
});
