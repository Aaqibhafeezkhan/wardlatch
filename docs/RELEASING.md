# Releasing

Releases are cut by the maintainer or the successor, the two owners of the `wardlatch` package on npm
([GOVERNANCE.md](../GOVERNANCE.md)). There is no build: a release is the source in `bin/` and `lib/`, packed by npm.

## How to cut one

```bash
# 0. Coverage (docs/COVERAGE-PROTOCOL.md): refresh the sources, re-copy the incidents' KEV rows, and the check must
#    say NO GAPS. Each new gap becomes an incident or a decline with a reason before the release goes ahead.
node scripts/coverage/refresh.mjs
curl -sSo kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
node scripts/kev-snapshot.mjs kev.json && rm kev.json
node scripts/coverage/check.mjs

# 1. The changelog: move "Unreleased" under "## [X.Y.Z] - YYYY-MM-DD" and update the links at the bottom.
# 2. The version. It must match the tag exactly; the release workflow refuses otherwise.
npm version X.Y.Z --no-git-tag-version
git commit -s -am "X.Y.Z: <what changed, in one line>"
git push origin main                      # wait for CI to go green

# 3. A signed, annotated tag on that commit. tag.gpgsign is set, so git signs it with the
#    maintainer's SSH signing key, and GitHub shows it as Verified.
git tag -s vX.Y.Z -m "wardlatch X.Y.Z"
git push origin vX.Y.Z
```

The tag push runs `.github/workflows/release.yml`: the full test suite, a check that the tag matches
`package.json`, then it builds the source archive (`git archive`) and the npm package (`npm pack`), attests both with
Sigstore, and publishes a GitHub release with the changelog section as its notes. **If any step fails, no release
appears.** The workflow never publishes to npm.

```bash
# 4. Publish to npm the exact package the workflow attested, so what is on npm can be verified.
gh release download vX.Y.Z -p 'wardlatch-X.Y.Z.tgz' -R deimos-hq/wardlatch
gh attestation verify wardlatch-X.Y.Z.tgz --repo deimos-hq/wardlatch \
  --signer-workflow deimos-hq/wardlatch/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z \
  --deny-self-hosted-runners
npm publish ./wardlatch-X.Y.Z.tgz
```

```bash
# 5. If the release fixes a draft security advisory, publish it once the package is on npm: the changelog and the
#    release notes link to it, and it links back to them. Then request its CVE, and update any published advisory
#    whose workaround or impact the new one changes.
gh api -X PATCH repos/deimos-hq/wardlatch/security-advisories/GHSA-xxxx-xxxx-xxxx -f state=published
gh api -X POST repos/deimos-hq/wardlatch/security-advisories/GHSA-xxxx-xxxx-xxxx/cve
```

If `fix/fix-macos.sh` changed in the release, the download on www.deimoscore.com, the SHA-256 printed on the page and
the site's changelog record change at the same time, and the hash pinned in `.github/workflows/ci.yml` with them.

### Tags for the releases before the workflow

0.1.0 to 0.1.2 were published before any tag existed. These are the commits npm recorded as each one's `gitHead`
(a pack of each matches the published package's file count and size):

```bash
git tag -s v0.1.0 4d4f2955b2a5ac39f36797ac6b8f5cfc1209034d -m "wardlatch 0.1.0 (npm, 21 Oct 2026 05:14 UTC)"
git tag -s v0.1.1 49ea20cd599c817efa4d4c9ec37cfdaca8d5b48e -m "wardlatch 0.1.1 (npm, 21 Oct 2026 05:57 UTC)"
git tag -s v0.1.2 bcf739c318dd60397a76360ac68e04138fd532bd -m "wardlatch 0.1.2 (npm, 21 Oct 2026 07:53 UTC)"
git push origin v0.1.0 v0.1.1 v0.1.2
```

Pushing them starts no release: those commits contain no workflow files. They mark where each release came from; they
do not sign the packages already on npm.

## Verifying a release

For a release cut through the workflow, the package on npm and the source archive each carry a Sigstore attestation
bound to the GitHub workflow run and commit that built them, recorded in a public transparency log. There is no key to
import.

```bash
npm pack wardlatch@X.Y.Z                 # downloads wardlatch-X.Y.Z.tgz from npm without installing it
gh attestation verify wardlatch-X.Y.Z.tgz --repo deimos-hq/wardlatch \
  --signer-workflow deimos-hq/wardlatch/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z \
  --deny-self-hosted-runners
```

Without GitHub's attestation store, use the bundle attached to the release:

```bash
gh attestation verify wardlatch-X.Y.Z.tgz --bundle wardlatch-X.Y.Z.tgz.sigstore.json --repo deimos-hq/wardlatch \
  --signer-workflow deimos-hq/wardlatch/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z \
  --deny-self-hosted-runners
sha256sum -c SHA256SUMS                  # the files are byte for byte what was published
```

That `SHA256SUMS` is the release asset, downloaded beside the release files, and it covers them — including the
source tarball GitHub builds from the tag. The `SHA256SUMS` committed in the repository is a different file: it
covers the packed tarballs committed here, so that `shasum -a 256 -c SHA256SUMS` is checkable in a clone with
nothing downloaded. Repack and regenerate it when a release adds a tarball to the repository:

```bash
shasum -a 256 wardlatch-*.tgz            # append the new line; never type a digest
```

**0.1.3 and 0.1.4 verify under the repository's earlier name.** The repository moved from
`thearchitect0x-glitch/wardlatch` to `deimos-hq/wardlatch` on 21 October 2026, after those two releases. Their
attestations name the repository they were built in, and that cannot change, so verify them with the earlier name and the
bundle attached to the release:

```bash
gh attestation verify wardlatch-0.1.4.tgz --bundle wardlatch-0.1.4.tgz.sigstore.json --repo thearchitect0x-glitch/wardlatch
```

The tag is signed with the maintainer's SSH signing key, which GitHub lists for the account:

```bash
gh api users/thearchitect0x-glitch/ssh_signing_keys --jq '.[].key' | sed 's/^/thearchitect0x-glitch /' > allowed_signers
git -c gpg.ssh.allowedSignersFile=allowed_signers verify-tag vX.Y.Z
```

An attestation answers "which workflow, at which commit, built this file". It does not answer whether that commit was
any good; the tests, CodeQL and review are what address that.

## Reproducing a release

The attestation says which workflow built a file. A rebuild says the file is what its tag's source makes, without
trusting that workflow: anyone with git and npm can rebuild both release files from the signed tag and get the same
bytes.

```bash
git clone https://github.com/deimos-hq/wardlatch.git && cd wardlatch
scripts/reproduce-release.sh vX.Y.Z                    # rebuilds, fetches the release's SHA256SUMS with gh, compares
scripts/reproduce-release.sh vX.Y.Z ~/SHA256SUMS       # or compares with a SHA256SUMS you downloaded yourself
```

It does what `release.yml` does, from the tag: `git archive --format=tar.gz --prefix=wardlatch-vX.Y.Z/` for the source
archive and `npm pack` (with `--ignore-scripts`; the package has no scripts) for the npm package, then
`sha256sum -c` against the release's `SHA256SUMS`, which must name exactly those two files. It exits 0 only when both
match.

What the bytes depend on, measured on 15 Nov 2026:

- **File permission bits: yes.** `npm pack` records each file's mode. A tree unpacked under `umask 077` packs to a
  different file. Build from files that are 644 and 755, as git checks them out under `umask 022`; the script sets that
  umask.
- **Modification times: no.** `npm pack` writes a fixed time for every entry; touching every file changes nothing.
- **The machine and the npm version: not for the releases so far.** v0.1.17 and v0.1.18, rebuilt on macOS with npm
  11.20.0 and git 2.54.0, match the release workflow's files (Ubuntu, Node 22's npm) byte for byte: SHA-256
  `7f5237a5…18f3` and `6e00a19a…2efc` for the npm packages, `ebda47f6…f654` and `975717e1…7049` for the source
  archives. The 0.1.17 package also matches npm's recorded `integrity` and `shasum`. A different npm or git could in
  principle pack differently; the script would then say "NOT reproduced", and that is a finding, not a pass.

CI checks both halves on every push and pull request (the `reproducible` job in `.github/workflows/ci.yml`): that
the current commit packs to the same bytes from two different trees, with a control that a changed tree packs
differently, and that the newest published release rebuilds from its tag with this script.
