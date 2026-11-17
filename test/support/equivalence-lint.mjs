// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The equivalence lint (docs/PATTERN-IDENTITY-EQUIVALENCE.md): every place Wardlatch's shipped code compares a name it
// listed from the disk, or a path's prefix, as exact text. On a Mac's disk many spellings open one file (case, ß and
// ss, ligatures, NFC and NFD), so an exact comparison there is a decision about identity, and each one must be
// classified by a person: made to ask the disk (lib/files.mjs sameNameOnDisk, segmentTester), or kept with the reason
// it can't make Wardlatch say SAFE wrongly or read the wrong file. test/equivalence-2026-11.test.mjs fails on a
// comparison that is in neither list, and on a listed one that is no longer in the code.

/** The shapes looked for: a listed name or a path compared as exact text. */
export const SHAPES = [
  { id: 'name-eq', rx: /\b(?:e|x|a|y)\.name\s*[!=]==|[!=]==\s*(?:e|x|a|y)\.name\b/ },
  { id: 'name-in-list', rx: /\.(?:includes|has)\(\s*(?:e|x|a|y)\.name\s*\)/ },
  { id: 'name-own-key', rx: /Object\.hasOwn\([^,]+,\s*(?:e|x|a|y)\.name\s*\)/ },
  { id: 'name-affix', rx: /\b(?:e|x|a|y)\.name\.(?:startsWith|endsWith)\(/ },
  { id: 'name-regex', rx: /\.test\(\s*(?:e|x|a|y)\.name\s*\)/ },
  { id: 'basename-eq', rx: /basename\([^()]*(?:\([^()]*\))?[^()]*\)\s*[!=]==|[!=]==\s*basename\(/ },
  { id: 'names-has', rx: /\bnames\.has\(/ },
  { id: 'path-prefix', rx: /\.startsWith\(`\$\{[^}]+\}\/`\)|\.startsWith\(\w+ \+ sep\)|\.startsWith\(dir/ },
];

/** Findings in one file's text → [{ file, line, shape, text }]. Comment lines are skipped. */
export function lintText(file, text) {
  const out = [];
  text.split('\n').forEach((raw, i) => {
    const t = raw.trim();
    if (!t || t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return;
    for (const s of SHAPES) if (s.rx.test(raw)) out.push({ file, line: i + 1, shape: s.id, text: t });
  });
  return out;
}

/**
 * The classified places: [file, a piece of the line's text that is unique enough to find it, verdict, reason].
 * verdict 'fixed': the comparison now asks the disk or folds as the disk does (the line names the helper).
 * verdict 'harmless': exact on purpose, with the reason.
 */
export const CLASSIFIED = [
  ['lib/lockfiles.mjs', "const name = typeof e.name === 'string' ? e.name", 'harmless', 'e is a package entry inside a lockfile (its JSON "name" field), not a file on disk'],
  ['lib/macos.mjs', 'v.held.includes(x.name)', 'harmless', 'certificate names read from a trust store, not files on disk'],
  ['lib/owners.mjs', 'names.has(70)', 'harmless', 'a map of user ids, not file names'],
  ['lib/brotli.mjs', 'PACKAGE_DIRS.has(e.name)', 'harmless', 'a skip list: a folder named in another spelling is walked, never skipped'],
  ['lib/brotli.mjs', "s.startsWith(`${k}/`)", 'harmless', 'dyld\'s own tokens (@loader_path, @executable_path) in a load command, which dyld matches exactly too'],
  ['lib/lockfiles.mjs', 'NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)', 'harmless', 'a skip list: a folder named Node_Modules or library in another spelling is WALKED, not skipped, so an exact match can only search more'],
  ['lib/installs.mjs', 'NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)', 'harmless', 'a skip list: another spelling is walked, never skipped (as in lib/lockfiles.mjs)'],
  ['lib/installs.mjs', "e.name.endsWith('.dist-info')) add(d)", 'harmless', 'installers write the .dist-info suffix in lower case (PEP 376/627); a folder with another suffix is still walked, and its packages are read by venvPackages'],
  ['lib/installs.mjs', 'e.name.includes', 'harmless', 'tests for U+FFFD in a name that is not UTF-8: a byte test, not an identity'],
  ['lib/installs.mjs', 'names.has(ioc.name)', 'harmless', 'the dropped file\'s name is the one the malicious release writes, and Python runs a .pth by listing the folder (site.py), not by a name it asks for: a renamed copy is a variant, which nameAlone and the hash rule handle, not another spelling of one file'],
  ['lib/installs.mjs', 'if (names.has(name)) out.push', 'harmless', 'distInfo names the release\'s own install record as its wheel writes it; distVersions, which judges versions, matches in any case'],
  ['lib/discover.mjs', 'NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)', 'harmless', 'a skip list: another spelling is walked, never skipped'],
  ['lib/workflows.mjs', 'NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)', 'harmless', 'a skip list: another spelling is walked, never skipped'],
  ['lib/wordpress.mjs', 'NOT_WALKED.includes(e.name) || isSystemFolder(e.name, d)', 'harmless', 'a skip list: another spelling is walked, never skipped'],
  ['lib/wordpress.mjs', 'names.some((n) => e.name === n || isCopyName(e.name, n))', 'harmless', 'the same test also asks the disk by each listed plugin\'s name (pathState(join(d, n))) and by its main file under any folder name, so a plugin folder in another spelling is found that way'],
  ['lib/wordpress.mjs', "basename(app) === 'app'", 'harmless', 'Bedrock\'s app folder is matched to decide a site\'s layout; a folder in another spelling still holds a listed plugin, which holdsListed finds by asking the disk'],
  ['lib/wordpress.mjs', "basename(d) === 'plugins' && (isRoot", 'harmless', 'a plugins folder in another spelling is not taken as wp-content/plugins, but holdsListed still finds every listed plugin in it by asking the disk, and reads it'],
  ['lib/wordpress.mjs', "|| (basename(dirname(d)) === 'app'", 'harmless', 'the same layout guess for Bedrock, with holdsListed behind it'],
  ['lib/wordpress.mjs', "const sitesOwn = (p) => sites.has(dirname(dirname(p))) && basename(p) === 'plugins'", 'harmless', 'decides whether a plugins folder is a site\'s own or a leftover; either way it is read'],
  ['lib/wordpress.mjs', "&& (basename(dirname(p)) === 'wp-content'", 'harmless', 'part of the same own-or-leftover test; either way the folder is read'],
  ['lib/wordpress.mjs', 'PHP_FILE.test(e.name)', 'harmless', 'PHP_FILE is case-insensitive (/\\.php$/i)'],
  ['lib/wordpress.mjs', 'CODE.test(e.name) || !INERT.test(e.name)', 'harmless', 'a name that is neither code nor inert is read as code: another spelling can only be read, never skipped'],
  ['lib/wordpress.mjs', "e.isFile() && /\\.php$/i.test(e.name)", 'harmless', 'case-insensitive, and index.php / hello.php are WordPress\'s own placeholders, which WordPress itself writes in lower case'],
  ['lib/iocs.mjs', "if (!e.name.startsWith('.') || e.name === '.' || e.name === '..') continue;", 'harmless', 'a dot is a dot in every spelling; . and .. are not names a disk folds'],
  ['lib/iocs.mjs', 'if (editors.includes(e.name)) out.denied.push(ext)', 'harmless', 'only decides whether a folder that can\'t be entered is reported UNKNOWN; every dot-folder is still searched for extensions'],
  ['lib/iocs.mjs', 'new RegExp(rule.vsixName, \'i\').test(e.name)', 'harmless', 'the pattern is compiled with the i flag, so case cannot hide a name'],
  ['lib/iocs.mjs', 'if (!rx.test(e.name)) continue;', 'harmless', 'the tunnel key\'s pattern is compiled with i (review N5)'],
  ['lib/iocs.mjs', "(rule.extensions?.badVersions ?? []).some((v) => new RegExp", 'harmless', 'a version number in a cached package\'s name: digits and dots, which no disk folds'],
  ['lib/claudecode.mjs', 'if (!VERSION.test(e.name) || p === active) continue;', 'harmless', 'Claude Code names its version folders with digits and dots'],
  ['lib/binaries.mjs', "a.name !== 'zz'", 'harmless', 'a sentinel in the code\'s own list, not a name read from the disk'],
  ['lib/binaries.mjs', 'if (rx.test(e.name)) out.push(joinAsWritten(d, e.name))', 'harmless', 'a malware\'s trace in a temp folder has the name the malware gives it; the patterns that need it are compiled with i'],
  ['lib/files.mjs', "(e.isDirectory() || (e.isSymbolicLink() && mayBeFolder(join(d, e.name))) || e.name === '.git')", 'harmless', 'holdsMore: whether a folder holds more than was walked; a .GIT in another spelling counts as a folder anyway'],
  ['lib/files.mjs', '(l.entries ?? []).some((e) => !notEntered.includes(e.name)', 'harmless', 'the same skip list as the walkers: another spelling counts as more to walk'],
  ['lib/discover.mjs', '/^\\.?(venv|env|virtualenv)$/i.test(e.name)', 'harmless', 'the pattern is compiled with the i flag, so case cannot hide a name'],
  ['lib/brotli.mjs', "e.name.endsWith('.dist-info'), isEgg = e.name.endsWith('.egg-info')", 'harmless', 'installers write these suffixes in lower case; the decoder itself is found by the files in the package, which the loader opens by path'],
  ['lib/brotli.mjs', "e.name.endsWith('.libs') ? [[sub, isDecoderFileName]]", 'harmless', 'auditwheel and delocate name these folders; a package folder that is not one is still read for its binding'],
  ['lib/brotli.mjs', 'BINDING_DIRS.includes(e.name)', 'harmless', 'the folders a binding is installed in, as pip writes them; a rename breaks Python\'s import (exact on a Mac too: importlib compares the listed name)'],
  ['lib/brotli.mjs', "if (!e.name.endsWith('.egg')) continue;", 'harmless', 'setuptools writes .egg in lower case'],
  ['lib/brotli.mjs', "/^brotli/i.test(e.name)", 'harmless', 'the pattern is compiled with the i flag, so case cannot hide a name'],
  ['lib/brotli.mjs', "(l.entries ?? []).filter((e) => e.name.endsWith('.conf'))", 'harmless', 'ld.so.conf.d entries: the loader itself matches *.conf exactly (glibc glob), so this agrees with it'],
  ['lib/brotli.mjs', "const isNode = basename(file) === 'node';", 'harmless', 'only picks the advice text for a row already found'],
  ['lib/brotli.mjs', "mine.find(([k]) => k === basename(real))", 'harmless', 'a version manager\'s shim kind, from the name the manager itself gave the file it wrote'],
  ['lib/brotli.mjs', "if (onPath && basename(dirname(onPath)) === layout.folder)", 'harmless', 'adds a home when the shim sits in the manager\'s own folder; the manager\'s configured homes are read either way'],
  ['lib/brotli.mjs', 'const within = (p) => p.startsWith(dir.endsWith(sep) ? dir : dir + sep);', 'harmless', 'both sides are built from the same folder string the walk listed, not from two spellings'],
  ['lib/brotli.mjs', "const fix = r.via && !r.via.startsWith(dir + sep)", 'harmless', 'only chooses which fix text a row shows'],
  ['lib/reach.mjs', "if (real !== realHome && !real.startsWith(`${realHome}/`)) return unknown('link-outside');", 'harmless', 'both sides come from realpath(3), which returns the name as stored on disk (MEASURED 16 Nov 2026: realpathSync.native of STRASSE/cafe\\u0301 gave Straße/café), and a miss here is UNKNOWN, never SAFE and never a read'],
  ['lib/iocs.mjs', 'const said = (p, home) => (home && p.startsWith(`${home}/`)', 'harmless', 'only shortens a path for printing'],
  ['bin/wardlatch.mjs', "const trash = kept.some((p) => basename(p) === '.Trash');", 'harmless', 'only adds "or empty the Trash" to advice'],
  ['bin/wardlatch.mjs', 'inc.rules.filter((x) => basename(p) === x.plugin', 'harmless', 'the same line also asks the disk for the plugin\'s main file (pathState(join(p, x.mainFile)))'],
];

/** The lint over files → { unclassified: findings, stale: classified entries that match nothing }. */
export function lint(files) {
  const found = files.flatMap(([f, text]) => lintText(f, text));
  const used = new Set();
  const unclassified = found.filter((x) => {
    const i = CLASSIFIED.findIndex(([f, piece]) => f === x.file && x.text.includes(piece));
    if (i < 0) return true;
    used.add(i);
    return false;
  });
  const stale = CLASSIFIED.filter((_, i) => !used.has(i));
  return { found, unclassified, stale };
}
