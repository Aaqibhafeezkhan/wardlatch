// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Preloaded by the tests that run the PHP check: hides the folders it searches off PATH (/usr/sbin, /usr/local, /opt), and
// the machine's own PHP programs in the system folders the tests put on PATH (/usr/bin, /bin, /sbin: an Ubuntu runner
// ships /usr/bin/php, and with usrmerge /bin/php is the same file), so a machine with PHP installed (a CI runner, a
// developer's Mac) can't change what a test sees. Up to this, a GitHub ubuntu-latest runner's /usr/bin/php (EXPOSED)
// made A4m's mutant exit 1 although the mutant had dropped ~/bin/php: the proof failed for the machine's reason, not
// the mutant's (16 Nov 2026). Nothing else changes: every other program in those folders is seen as it is.
'use strict';
const fs = require('node:fs');
const { basename, dirname } = require('node:path');
const HIDDEN_DIR = /^\/(?:usr\/sbin|usr\/local|opt)(?:\/|$)/;
// the same names lib/incidents/php-2026-10.json's binaryNames matches, in the folders a test's PATH names
const SYSTEM = new Set(['/usr/bin', '/bin', '/sbin']);
const PHP = /^php(?:-fpm|-cgi)?(?:\d+(?:\.\d+)?)?$/i;
const hidden = (p) => { const s = String(p); return HIDDEN_DIR.test(s) || (SYSTEM.has(dirname(s)) && PHP.test(basename(s))); };
const gone = () => Object.assign(new Error('hidden by the test'), { code: 'ENOENT' });
const exists = fs.existsSync;
fs.existsSync = (p) => !hidden(p) && exists(p);
for (const k of ['statSync', 'lstatSync', 'realpathSync', 'readdirSync', 'openSync']) {
  const o = fs[k];
  fs[k] = (p, ...a) => {
    if (hidden(p)) throw gone();
    const r = o(p, ...a);
    // a system folder's listing leaves its PHP programs out, as if they were not installed
    if (k === 'readdirSync' && SYSTEM.has(String(p).replace(/\/+$/, '')) && Array.isArray(r)) {
      return r.filter((e) => !PHP.test(typeof e === 'string' ? e : Buffer.isBuffer(e) ? e.toString() : e.name));
    }
    return r;
  };
  // realpathSync.native (the OS's realpath, which lib/files.mjs realPathAsWritten uses) hides the same folders
  if (o.native) fs[k].native = (p, ...a) => { if (hidden(p)) throw gone(); return o.native(p, ...a); };
}
require('node:module').syncBuiltinESMExports();
