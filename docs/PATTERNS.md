# Patterns behind false SAFEs

Wardlatch's one law is never a false SAFE. Most false SAFEs it has found came from a few shapes, not from one-off
mistakes. Each section here names one shape, says what was found, and names the check that runs on its own to keep it
out. [PATTERN-IDENTITY-EQUIVALENCE.md](PATTERN-IDENTITY-EQUIVALENCE.md) covers P1, the identity-equivalence class, in
full. This page adds P4's fix, and two patterns first named in the research sweep of 16 and 17 Nov 2026: P8 and P9.

Patterns P1 to P7 were named in the maintainer's notes of 16 Nov 2026. Briefly: P1 identity-equivalence; P2 the fix
lives somewhere other than where people patch (a vendored or bundled copy); P3 quiet fixes with no KEV row and a late
CVE; P4 sweeps that miss things because of how they sample; P5 the audit is itself a trigger; P6 silent state change and
truth that decays with time; P7 one instance fixed, not the class.

## P4, fixed for Apple's pages (release/0.1.19-candidate)

**Found.** The coverage read (`scripts/coverage/refresh.mjs`) took macOS's rows from Apple's security releases index,
and no other row. Xcode 27.2's two fixes (CVE-2026-112605, CVE-2026-112602, 29 Oct 2026) were therefore in neither an
incident nor the declined list. The check said NO GAPS from a read that never opened Xcode's page.

**The check.** The refresh now reads every index row in the window whose "Available for" column names macOS (macOS,
Safari, Xcode, other Mac apps). It records every other row as skipped, with its column. `scripts/coverage/check.mjs` is
INCOMPLETE when a skipped row names macOS, when the read and skipped rows don't add up to the window, or when the
snapshot predates the change. `test/coverage-protocol.test.mjs` C4 plants each of those. C4p names the Mac products the
read must carry, and C4pm puts the old macOS-only filter back and requires the check to fail on Xcode 27.2. The first
read after the change found two more gaps, Xcode 27's sandbox escapes (CVE-2026-86948, CVE-2026-86949), now named
in `xcode-2026-10`.

## P8. Self-erasing compromise: clean now is not "never ran"

**Found.** A CI secret stealer seen from 10 Nov 2026 (reported by two independent research teams; no advisory
identifier yet) pushes a commit, lets it run, and reverts it within seconds. Then it deletes the run and its logs. The
working tree and the current workflow files are clean afterwards. A check that reads only current state says SAFE about
a repository whose secrets were taken. What is left is history: a reflog line, a branch ref, a packed-refs entry, an
installed script under `node_modules`.

**The rule.** An incident whose source says the attacker reverted, deleted logs or cleaned up must say which history
store it reads (reflog, packed-refs, refs, installed artefacts). When that store is absent or expired (a fresh clone has
no reflog), the history half of the answer is UNKNOWN, never SAFE: "nothing in the tree" is a statement about now.
Wardlatch never runs git to read them; it reads the files.

**State.** Named here, for the next incident of this kind. No 0.1.19 incident depends on history, so no check enforces
it yet. The first such incident must carry the history store in its schema, and a test that a missing store reads
UNKNOWN.

## P9. The fixed version is not the fixed state

**Found.** In four sources the fix is something the user must turn on, or clean up, after the update:

- the MCP Python SDK's CVE-2026-116684: the patched versions add `validate_token_resource`, off unless set ("Upgrading
  alone changes nothing", GHSA-w4fh-qvv9-3v23);
- FastMCP's GHSA-vqqp-x5qm-5qp4: 4.1.2 adds an `issuer` parameter, and leaving it out is still allowed ("Upgrading alone
  is insufficient");
- Docker Desktop's CVE-2026-114409: 4.94.0 and 4.95.0 stopped writing tokens to the known logging paths, but "logs
  containing credentials can remain after upgrading";
- ImageMagick (CERT/CC VU#580079): safe only with a strict policy file (not yet an incident).

A version comparison alone reads each of these SAFE at or past the fix.

**The checks.**

- `fixNeedsConfig: { from, reason }` on a package's rule (lib/lockfiles.mjs `judgePinned`, used for lockfile pins and,
  through `ranges`, for site-packages). A version at or past `from` is REVIEW with the reason, which names the setting.
  It is never SAFE, because Wardlatch does not read the code that would set it. `mcp-python-2026-10` uses it for the
  SDK and for both FastMCP packages. CVE-2026-116685, fixed by the version alone, keeps its EXPOSED-below-the-fix rule
  in the same ranges.
- `residueWhenFixed` on a version file (lib/installs.mjs `residue`). At or past the fix, the folder the earlier versions
  wrote to is listed by name and date, never by contents. A file older than the fix's release, or older than this copy
  of the app (its version file's ctime), makes the row REVIEW and names the folder. A folder that can't be listed is
  UNKNOWN. `docker-desktop-2026-10` uses it for `~/Library/Containers/com.docker.docker/Data/log`.
- `test/sweep-0.1.19.test.mjs` M1m and D1m plant each half's removal, in the code and in the incident file, and
  require the at-the-fix fixture to read SAFE, so the tests can tell the difference.
