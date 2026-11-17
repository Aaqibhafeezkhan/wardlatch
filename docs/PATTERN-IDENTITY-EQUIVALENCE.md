# The identity-equivalence pattern

Written 16 Nov 2026, the day CERT/CC published [VU#604762](https://kb.cert.org/vuls/id/604762). The owner had sensed a
pattern across several macOS findings and could not name it. This page names it, tests the working thesis against the
evidence, and records how it was turned into checks that run on their own: a coverage class, a lint, and helpers that
ask the disk.

## The thesis, and the verdict

**Working thesis.** A check compares one notion of identity (exact bytes, a service ID a program claims, a list the tool
keeps), while macOS acts on a different, looser one (folded file names, the OS's own service identity, the system trust
store). An attacker lives in the gap between what the check compared and what the OS actually used.

**Verdict: confirmed, with two refinements.** Every public piece below fits it. The evidence adds two things:

1. **The gap runs both ways.** Most cases are a check that is *stricter* than the system: it compares bytes while the
   disk folds, so a deny rule misses a file. A check that is *looser* than the system fails the same way: a fold table
   wider than the disk calls two files one (Wardlatch's 1 Nov 2026 site-packages fix, `lib/files.mjs` `namedAs`, had to
   refuse NFKC for that reason). The fault is a mismatch, not a direction.
2. **Time is one more axis of identity.** node-tar's CVE-2026-23950 is a lock keyed on one spelling while another
   spelling of the same file is written in parallel. The check and the use agree on the name and disagree on the moment.

In one sentence: **a decision is made about the identity the checker computed, and the action happens to the identity
the system resolves; wherever the two can differ, the decision does not cover the action.**

## What a Mac's disk does with names (MEASURED, 16 Nov 2026)

On this Mac (macOS 27.2.1), with a probe that creates a file under one spelling and stats another (scratch script, run
on the start-up disk and on three disk images made with `hdiutil`). "Same" means the same device and inode.

| Spelling pair | APFS (default, case-insensitive) | APFS case-sensitive | HFS+ | HFS+ case-sensitive |
|---|---|---|---|---|
| `secret` / `SECRET` | same | different | same | different |
| `straße` / `strasse`, `groß` / `groẞ` | same | different | different | different |
| `café` NFC / NFD | same | **same** | same | same |
| `ﬁle` / `file`, `oﬀ` / `off` (ligatures) | same | different | different | different |
| `Kelvin sign` K / `K`, `ſ` / `s`, final sigma | same | different | different | different |
| `zw` / `z` U+200D `w` | different | different | **same** | different |
| `ı` / `i`, `İ` / `i`, fullwidth `Ａ` / `A`, `²` / `2` | different | different | different | different |
| trailing dot, trailing space | different | different | different | different |

So the default APFS volume applies **full Unicode case folding** (ß to ss, ligatures, Kelvin, long s) **and canonical
normalization** (NFC = NFD), not compatibility normalization (NFKC) and not Turkish folding. HFS+ applies simple case
folding and NFD, and ignores some format characters. **A case-sensitive APFS volume is not safe** from this class: it
still treats NFC and NFD as one name, which is the variant setuptools, go-slug and libarchive were found with. Also
measured: Node's `fs.realpathSync` keeps the spelling it was given, while `fs.realpathSync.native` (realpath(3)) returns
the name as stored, so two realpaths of one file can differ as text.

CERT/CC's note says "ß versus ss" and "Unicode normalization" interchangeably. They are two mechanisms: ß/ss is case
folding (only the case-insensitive volume does it), NFC/NFD is normalization (every Mac volume format above does it).

## The pieces, mapped

| Piece | What the check compared | What the system used | Source |
|---|---|---|---|
| VU#604762: Deno CVE-2026-49401 | the requested path and the `--deny-*` path, as bytes | APFS's folded, normalized name | [GHSA-8xpq-cjcf-3wh9](https://github.com/denoland/deno/security/advisories/GHSA-8xpq-cjcf-3wh9) |
| VU#604762: setuptools CVE-2026-59890 | MANIFEST.in globs against on-disk names, no normalization | NFD and NFC as one file | [GHSA-h35f-9h28-mq5c](https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c) |
| VU#604762: go-slug CVE-2026-14978 (Terraform) | `.terraformignore` patterns, no normalization | the same | [IBM bulletin](https://www.ibm.com/support/pages/node/7284170) |
| VU#604762: libarchive CVE-2026-45110 | exclusion patterns, byte for byte | the same; no fix released (PR #3359) | [VU#604762](https://kb.cert.org/vuls/id/604762) |
| node-tar CVE-2026-23950 | a lock per normalized-and-lowercased path | `ß` and `ss` as one file, written in parallel | [GHSA-r6q2-hw4h-h46w](https://github.com/isaacs/node-tar/security/advisories/GHSA-r6q2-hw4h-h46w) |
| VU#293714: app-builder CVE-2026-13723 | extraction paths, no canonical form | `ß` and `ss` as one file, plus a link | [VU#293714](https://kb.cert.org/vuls/id/293714) |
| VU#948176 / VU#573195: X.509 name constraints (GnuTLS CVE-2026-3833, pyca CVE-2026-34073; records .14 and .15 for macOS's trust framework) | a DNS name case-sensitively, an IPv4 address in one form, a URI's host by one parse | case-insensitive DNS, IPv4-mapped IPv6, another parse of the authority | [VU#948176](https://kb.cert.org/vuls/id/948176) |
| eMudhra's compromised intermediates (`emudhra-2026-10`) | the roots in the file a tool reads (`/etc/ssl/cert.pem` for LibreSSL's curl and git; certifi; a runtime's own list) | Apple's own trust evaluation, which blocks the intermediates: "does this Mac trust it" has a different answer per store asked | this repository's incident and its measurements |
| CVE-2026-65339, macOS Audio (`apple-audio-2026-08`) | by public reports, a permission check that took a program's claimed service identity | the OS's own identity of that service | **Apple's notes say only "A logic issue was addressed with improved checks"**; the identity reading is from reports, not Apple, and is UNVERIFIED here |
| Wardlatch itself, 1 Nov 2026 (`lib/files.mjs` `namedAs`) | `site-packages` as an exact name | any spelling APFS opens as it | test/reread-r4 and the comment in `lib/files.mjs` |
| Wardlatch itself, 16 Nov 2026 (this change) | lockfile names, `*` path segments, a PATH program asked for by pattern | the file npm, the version-file reader and the shell actually open | below |

## What changed in Wardlatch (16 Nov 2026)

**Incidents** (each named in the coverage check): `deno-2026-06` (CVE-2026-49401), `terraform-2026-08`
(CVE-2026-14978, judged by the go-slug version in Terraform's own module list), `setuptools-2026-07` (CVE-2026-59890).
All three are a Mac's only: below the fix on a Mac is EXPOSED; on Linux Deno and Terraform rows are SAFE with the
vendor's reason, and setuptools adds no row. An unread version is UNKNOWN everywhere.

**Audit of Wardlatch's own comparisons.** Every place the shipped code compares a listed name or a path prefix as text
was found by the lint and classified. Fixed, each with a test and a planted mutation that the test catches
(`test/equivalence-2026-11.test.mjs` A3 to A6):

- `lib/lockfiles.mjs`: a lockfile was found only under its exact name. npm opens `package-lock.json`, which on APFS is a
  file listed as `Package-Lock.json`: that project's pins were never read and the run said SAFE. Now `lockNameOf` asks
  the disk (`sameNameOnDisk`), so Linux, where the two are two files, is unchanged.
- `lib/installs.mjs` `expand` and `lib/binaries.mjs` `dirsMatching`: a `*` segment was a case-sensitive regex. An
  `Xcode*.app` renamed `xcode.app` held a git that read as not there. On a Mac a segment now also matches by
  `wideFold`; on Linux it is exact. It can only add a place read.
- `lib/binaries.mjs` `copiesMatching`: a program on PATH was found only by a lower-case pattern. `php` on a Mac runs a
  file listed as `PHP`. The exact name is now also asked for, as the shell asks; on a disk that keeps case this adds
  nothing.

Harmless, with reasons (the full list, one line each, is `CLASSIFIED` in `test/support/equivalence-lint.mjs`): skip
lists (`NOT_WALKED`, `isSystemFolder`, `PACKAGE_DIRS`) only ever walk *more* when a name is spelled otherwise; regexes
already compiled with `i`; names that the program reading them also matches exactly (Python's import of a binding
folder, the loader's `*.conf`, `.pth` files run by listing); WordPress's layout guesses, behind which `holdsListed` asks
the disk by each plugin's name; `lib/reach.mjs`'s home-folder prefix, whose two sides both come from realpath(3) and
whose miss is UNKNOWN; and strings that are not file names (lockfile JSON fields, certificate names, user ids).
`fix/fix-macos.sh` has no allow or deny list of names: it acts on the one path it is given and writes only files it
creates beside it with `mktemp`.

## How the pattern is now held by machine

1. **A coverage class**, `equivalence` (`scripts/coverage/check.mjs` `EQUIVALENCE`), with a third source, CERT/CC's
   notes, read whole by month through the VINCE API (`scripts/coverage/refresh.mjs`). An Apple entry is in the class by
   its Impact or Description line (path handling, links, case, Unicode, name constraints); a CERT/CC note by its title
   and text, and then every CVE number it prints anywhere, its vendors' addenda included, is an item. A future CVE of
   this shape must be named or declined, or `npm test` fails. First read (16 Nov 2026, 85 notes from May to November): 8
   notes in the class, 20 items, 3 named, 17 declined with reasons and a review date; and 2 Apple entries newly in
   scope by their Description, declined as D5.
2. **A lint**, `test/support/equivalence-lint.mjs`, run by `test/equivalence-2026-11.test.mjs` L1: a new exact
   comparison of a listed name or a path prefix in `lib/` or `bin/` fails the suite until someone classifies it. A
   classification that no longer matches the code fails too.
3. **Helpers that ask the disk** (`lib/files.mjs`): `sameNameOnDisk(dir, name, wanted)` (a sieve, then device and inode)
   for a name a program opens; `segmentTester(part)` for a `*` pattern; `wideFold` as the sieve, tested never to be
   narrower than the measured APFS table. The rule they encode: **compare names the way the program that uses them
   resolves them, and when that program is the kernel, ask the disk.**

To classify a new lint finding: say which program uses the name and how it resolves it. If that program would open a
file Wardlatch's comparison misses, use a helper; if Wardlatch's miss can only make it look at more, or the user of the
name compares exactly too, add a `harmless` line with that reason.

## Where the same shape may still be hiding (hypotheses, UNVERIFIED)

None of these has been tested. Each is a place a tool Wardlatch already checks makes an identity decision that a Mac
may resolve differently.

1. **UNVERIFIED. Node.js's permission model** (`--allow-fs-read`, `--allow-fs-write`). Node.js is listed in VU#604762
   with status Unknown, and its rules compare paths. If they compare without folding, a rule written for one spelling
   misses another on APFS, as Deno's did. Wardlatch reads Node runtimes for other incidents.
2. **UNVERIFIED. Coding agents' permission rules**, such as Claude Code's `permissions.deny` entries like
   `Read(./.env)`: if matched as text, `.ENV` or an NFD spelling would be the same file on APFS and not the same rule.
   Wardlatch has Claude Code incidents and reads its installs.
3. **UNVERIFIED. Python's `tarfile` data filter and pip's extraction** (PEP 706): the filter checks members and link
   targets by path text; a member named with `ss` and a link named with `ß` could be one file on APFS, the shape of
   node-tar's and app-builder's bugs. Wardlatch reads Python installs for Brotli, LiteLLM and GPUStack.
4. **UNVERIFIED. Docker's `.dockerignore` and Docker Desktop's file sharing** (Docker is in VU#604762, Unknown): the
   build context is filtered on the Mac's folded disk and used by a case-sensitive Linux inside the VM. Wardlatch
   lists local images and containers.
5. **UNVERIFIED. Git's own path checks on macOS** (`core.ignorecase`, `core.precomposeunicode`): git has fixed this
   shape before (`.Git` in 2014; case-insensitive symlinks in 2021). Whether the six fixes of 10 Nov 2026 include
   another is not stated in the notes `git-2026-11` read.

## Owner decisions this leaves open

See `docs/COVERAGE-PROTOCOL.md` D5 to D8.
