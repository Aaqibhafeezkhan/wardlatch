// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Preloaded (node --require) by test/never-false-safe/hostile.test.mjs into the command it runs: the clock reads
// WL_NFS_NOW (milliseconds since 1970) for every Date.now() and new Date(), and SystemVersion.plist is read from
// WL_NFS_PLIST (a file the test wrote, with the modification time the test gave it), for stat() and open() alike.
// Nothing else changes. Only a test loads it.
'use strict';
const fs = require('node:fs');
const NOW = process.env.WL_NFS_NOW ? Number(process.env.WL_NFS_NOW) : null;
if (NOW !== null) {
  const Real = Date;
  class Fixed extends Real { constructor(...a) { if (a.length) super(...a); else super(NOW); } static now() { return NOW; } }
  globalThis.Date = Fixed;
}
const PLIST = '/System/Library/CoreServices/SystemVersion.plist', TO = process.env.WL_NFS_PLIST;
if (TO) {
  const m = (p) => (String(p) === PLIST ? TO : p);
  for (const k of ['existsSync', 'statSync', 'lstatSync', 'openSync', 'readFileSync', 'accessSync']) {
    const o = fs[k];
    fs[k] = function (p, ...rest) { return o.call(this, m(p), ...rest); };
  }
  require('node:module').syncBuiltinESMExports();
}
