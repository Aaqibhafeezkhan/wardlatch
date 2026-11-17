#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// The SBOM of one release's npm package, as SPDX 2.3 JSON, bound to that exact file: the release workflow
// (.github/workflows/release.yml) runs it on the package it packed and attested, then attests the SBOM with
// actions/attest-sbom and attaches both to the GitHub release.
//
//   npm sbom --sbom-format spdx --sbom-type library > npm-sbom.json     # if this npm has `npm sbom`
//   node scripts/sbom.mjs wardlatch-X.Y.Z.tgz wardlatch-X.Y.Z.spdx.json [npm-sbom.json]
//
// npm's SBOM (when given and readable) is the base; without one, a minimal SPDX document is written. Either way the
// package entry gets the tarball's file name, its SHA-256 and npm's download URL, so the SBOM names the bytes it
// describes. Wardlatch has no dependencies, and the SBOM must say so: a document with any other package in it, or one
// whose package is not this name and version, is refused (exit 1) and nothing is written. Nothing here is run from
// the package; it is only read.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DEPS = ['dependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies'];

/** → the SPDX document for `pkg` (package.json's contents) packed as `tgzName` with SHA-256 `sha256`. `npmSbom`: npm's
 *  own SPDX output, parsed, or null. Throws when the result would not describe exactly this package and nothing else. */
export function bindSbom({ pkg, tgzName, sha256, npmSbom = null, now = new Date() }) {
  const { name, version } = pkg;
  if (!name || !version) throw new Error('package.json has no name or version');
  if (tgzName !== `${name}-${version}.tgz`) throw new Error(`the package file is ${tgzName}, not ${name}-${version}.tgz`);
  if (!/^[0-9a-f]{64}$/.test(sha256 ?? '')) throw new Error('no SHA-256 for the package file');
  for (const k of DEPS) if (pkg[k] && Object.keys(pkg[k]).length) throw new Error(`package.json declares ${k}: Wardlatch has none`);
  const id = `SPDXRef-Package-${name}-${version}`;
  const doc = npmSbom?.spdxVersion === 'SPDX-2.3' ? structuredClone(npmSbom) : {
    spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT', name: `${name}@${version}`,
    documentNamespace: `https://spdx.org/spdxdocs/${name}-${version}-${sha256}`,
    creationInfo: { created: now.toISOString(), creators: ['Tool: wardlatch-scripts/sbom.mjs'] },
    documentDescribes: [id],
    packages: [{ name, SPDXID: id, versionInfo: version, primaryPackagePurpose: 'LIBRARY', filesAnalyzed: false, licenseDeclared: pkg.license ?? 'NOASSERTION', externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: `pkg:npm/${name}@${version}` }] }],
    relationships: [{ spdxElementId: 'SPDXRef-DOCUMENT', relatedSpdxElement: id, relationshipType: 'DESCRIBES' }],
  };
  const pkgs = doc.packages ?? [];
  if (pkgs.length !== 1) throw new Error(`the SBOM lists ${pkgs.length} packages; Wardlatch has no dependencies, so it must list exactly itself`);
  const [p] = pkgs;
  if (p.name !== name || p.versionInfo !== version || p.SPDXID !== id) throw new Error(`the SBOM's package is ${p.name}@${p.versionInfo}, not ${name}@${version}`);
  if (JSON.stringify(doc.documentDescribes) !== JSON.stringify([id])) throw new Error('the SBOM does not describe the package');
  Object.assign(p, {
    packageFileName: tgzName,
    checksums: [{ algorithm: 'SHA256', checksumValue: sha256 }],
    downloadLocation: `https://registry.npmjs.org/${name}/-/${tgzName}`,
  });
  return doc;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const [tgz, out, npmOut] = process.argv.slice(2);
  if (!tgz || !out || process.argv.length > 5) { console.error('usage: node scripts/sbom.mjs <package.tgz> <out.spdx.json> [npm-sbom.json]'); process.exit(2); }
  try {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    let npmSbom = null;
    if (npmOut) { try { npmSbom = JSON.parse(readFileSync(npmOut, 'utf8')); } catch { console.error(`${npmOut}: not readable SPDX JSON; writing the minimal SBOM`); } }
    const sha256 = createHash('sha256').update(readFileSync(tgz)).digest('hex');
    writeFileSync(out, `${JSON.stringify(bindSbom({ pkg, tgzName: basename(tgz), sha256, npmSbom }), null, 2)}\n`);
    console.log(`${out}: SPDX 2.3, ${pkg.name}@${pkg.version}, ${basename(tgz)} sha256 ${sha256}`);
  } catch (e) { console.error(`sbom: ${e.message}`); process.exit(1); }
}
