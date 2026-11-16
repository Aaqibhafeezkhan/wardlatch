# Security review

A threat model and review of Wardlatch as a whole: what it must guarantee, where its trust boundaries are, what an
attacker can reach, what stands in the way, and what is left. It is the review the OpenSSF Best Practices Gold level
asks for (`security_review`), and it is meant to be redone, not kept.

**Who did it, said plainly.** This review was done by the project: an AI coding assistant (Claude) working on the
project's own branch at the maintainer's request, reading the code and running the measurements below. It is **not an
independent review**. Nobody outside Deimos AI LLC has reviewed Wardlatch's design as a whole. The earlier review rounds
named in [CHANGELOG.md](../CHANGELOG.md) and [ASSURANCE_CASE.md](../ASSURANCE_CASE.md) were the project's own too.
An outside review is still wanted; see "What would make this stronger" at the end.

| | |
|---|---|
| Date | 15 November 2026 |
| Code reviewed | `main` at 1dfd218 (release 0.1.18), and the branch that adds this file |
| Method | Read the design documents and the code at each boundary; ran the suite, coverage and the checks below; measured each claim marked *measured* on macOS (Darwin 27.2, Node 26.12.1) unless it says CI |
| Next review | At the latest when a trust boundary below changes (a new kind of input, a new network peer, anything written), and in any case within a year |

This file does not repeat the assurance case. [ASSURANCE_CASE.md](../ASSURANCE_CASE.md) holds the full argument and the
evidence for each requirement; this is the reviewer's view across it: where an attack would start, and whether the
argument holds there.

## 1. What must hold

The security requirements are R1 to R7 in [ASSURANCE_CASE.md §1](../ASSURANCE_CASE.md#1-what-wardlatch-must-guarantee).
In one line each:

| # | Requirement |
|---|---|
| R1 | Never SAFE without a control that shows the check could have seen the problem; otherwise UNKNOWN, exit 2 |
| R2 | Sends nothing about the user: only TLS connections to the incidents' test hosts and two control sites |
| R3 | The command changes nothing on the machine |
| R4 | Never prints a secret it finds |
| R5 | What it reads cannot forge, hide or rewrite what it prints |
| R6 | No host shell, no dependencies |
| R7 | The Mac fix leaves `/etc/ssl/cert.pem` intact or correctly cleaned, never worse |

The one that matters most for a security tool is R1. A false SAFE is the failure that does harm, because people stop
looking; [SECURITY.md](../SECURITY.md) puts it first in scope.

## 2. Trust boundaries

From the diagram in [ASSURANCE_CASE.md §3](../ASSURANCE_CASE.md#3-trust-boundaries-and-the-argument):

| Boundary | Across it | Trust |
|---|---|---|
| **B1** network | TLS connections from the runtimes being checked (and the reachability handshake) to the advisories' test hosts and the control sites | Untrusted. Only success or failure of each connection is read; responses are discarded |
| **B2** the disk | Files, folder names, git repositories, Python environments, lockfiles, WordPress sites, programs read as bytes | Partly attacker-controlled by definition (a cloned repository, a compromised site) |
| **B3** containers | `docker`/`podman exec` into running containers, with the image's own `curl`, `python3` or `wget` | Attacker-controlled images |
| **B4** the package | npm delivering Wardlatch itself | Supply chain |
| **B5** the output | Text or JSON read by a person, a CI job, or an AI agent acting on "Next step" | Must not be forgeable from B2 or B3 |
| **B6** the Mac fix | `fix/fix-macos.sh`, as root, on `/etc/ssl/cert.pem` | Runs only when a person runs it on purpose |

Trusted, by stated assumption: the user's account, the programs on the user's `PATH`, Node itself, the operating system,
and npm. [ASSURANCE_CASE.md §4](../ASSURANCE_CASE.md#4-what-is-not-defended) explains each.

## 3. Attack surface, mitigations, and what was checked

### Malicious file and folder names (B2, B3 → B5)

**Attack.** A folder or file named with terminal escapes, a line separator (U+2028), bidi overrides (U+202E),
zero-width or tag characters, so that a printed line reads differently to a person or to an AI agent, or a fake
`SAFE` line appears.

**Mitigation.** One escaper, `lib/escape.mjs`, for every printed name, path, version and value; by Unicode category
(Cc, Cf, Cs, Co, Cn, Zl, Zp), every Default_Ignorable_Code_Point, the tag block and U+2800, and a backslash that would
start one of its forms. `--json` keeps real values with those characters as JSON escapes. A crash message is escaped as
one string, so a line break in a path cannot start a verdict line (`lib/crash.mjs`).

**Checked.** The suite plants such names and asserts the output (`test/wardlatch.test.mjs`, the red-team and re-read
rounds). `lib/escape.mjs` is at 100% line and branch coverage (CI, Node 22).

**Residual.** Printable text is printed as it is: a name can still *say* anything in visible letters, including a
look-alike slash (U+2215). The escaper makes the hidden visible; it cannot make a planted sentence untrue.

### Hostile file contents (B2)

**Attack.** A file built to hang the run (a FIFO, a device, a huge file), to exhaust memory, to make a parser take a
wrong branch (a version string, a certificate bundle, a lockfile, a git config, a plugin header), or to get executed.

**Mitigation.** One way to read the disk (`lib/files.mjs`): a single read-only, non-blocking descriptor
(`O_RDONLY | O_NONBLOCK`), regular files only, size caps (2 MB plugin files, 512 MB for the key scan, read in pieces
past 8 MB), and what a cap leaves unread is UNKNOWN, not passed over. Depth limits on every walk. Nothing read is ever
executed: no `eval`, no `new Function`, no interpreter from a found environment, no `.pth` file (enforced by
`test/conventions.test.mjs` and the 0.1.9 contract tests). Version strings are judged only by their leading dotted
number; anything else is UNKNOWN (`judgeVersion` in `lib/binaries.mjs`). Certificate bundles are read block by block,
and a block that cannot be read is counted, never skipped, so a bundle with any unreadable block is never called clean
(`lib/macos.mjs`).

**Residual.** The parsers are tested with crafted inputs, not yet with generated ones: there is no fuzz or property
test of the version, name or certificate parsers. A regular expression over a large file could still be slow on an
input nobody has tried; the caps bound how much text any one expression sees.

### Symbolic links (B2)

**Attack.** A link that makes a walk loop, leave the searched folders, or read somewhere it should not; or, for a tool
that wrote files, a classic link-following write.

**Mitigation.** Nothing is written, so there is no link-following write to defend. Walks do not follow a link to a
folder, and every such link is reported (an UNKNOWN row), so a link cannot hide a folder in silence
(`lib/discover.mjs`). The committed-keys scan skips links git records as links (mode 120000).

**Checked, measured.** A file git tracks as a regular file, replaced in the working tree by a link to a file outside the
repository, **is followed**: `pathState` and the read follow it, and what the target holds is reported under the
tracked name (a planted private key outside the repository was reported as a REVIEW line for `notes.txt`). The
mirror case, a committed key whose working copy is replaced by a link to a clean file, reads SAFE; but so does
simply editing the working copy to remove the key, because the scan reads current files, not history (the SAFE line
says so). So a link gives an attacker nothing an edit would not, and it needs write access to the repository on this
machine. Nothing is sent and nothing is written either way. **Judged low**, and recorded here rather than fixed:
opening tracked files with `O_NOFOLLOW` (or comparing `lstat` with the index mode) would close the first case, and is a
behaviour change for the maintainer to decide.

### `PATH` hijack and environment variables (B2 → the programs Wardlatch starts)

**Attack.** A program planted earlier on `PATH` (a fake `git`, `curl` or `node`), or an environment variable that makes
a started program load code or look elsewhere (`GIT_DIR`, `OPENSSL_CONF`, `LD_PRELOAD`, `NODE_OPTIONS --require`,
`SHELLOPTS`).

**Mitigation.** `PATH` is trusted on purpose: Wardlatch checks the programs the user actually runs, and an attacker who
controls `PATH` already runs code as the user (out of scope in [SECURITY.md](../SECURITY.md#what-is-not)). What is
defended is everything else: one way to run a program (`lib/run.mjs`) with an absolute path, an argument list (never a
shell), the folder `/`, a SIGKILL timeout, and an environment built from an allowlist per purpose, not the caller's
environment minus a list. Programs an incident says may themselves be malware are read, never run. Settings that could
add trust but are not passed to a probe produce an UNKNOWN row naming them, so they cannot end in an all-SAFE run.

**Residual.** A virtual environment's own `bin/python` is never run, but a malicious program that is first on `PATH`
is run with `--version` like any other: that is the stated trust assumption.

### Network and test hosts (B1)

**Attack.** An on-path attacker or a hostile test host making a runtime look as if it refuses a compromised root
(a false SAFE), or a probe leaking data.

**Mitigation.** Three controls before any SAFE (reachability, a positive control that forces the compromised roots in
and must connect, and a system control where a root cannot be forced); only a certificate-verification refusal counts
as "does not trust". The probes send a plain `GET /` and add nothing from the machine. Only `lib/probe.mjs` opens
connections (enforced by test). Certificate checking is never turned off except in the one reachability handshake,
which sends nothing. Wardlatch's own TLS uses Node's default minimum, TLS 1.2 (measured: `tls.DEFAULT_MIN_VERSION`
is `TLSv1.2`).

**Residual.** Stated in [ASSURANCE_CASE.md §4](../ASSURANCE_CASE.md#4-what-is-not-defended): an on-path attacker
can still produce a false SAFE for a host once the controls pass, and a probe sees what its tool sees, nothing more.
A curl probe carries what the user's curl start-up file adds to requests, on purpose.

### Containers (B3)

**Attack.** A container image whose `curl` lies, or whose output is built to forge a line.

**Mitigation.** The probe script takes positional arguments (no shell string built from data), a container's tool must
refuse a self-signed site and open a normal one before its answer counts, output is escaped, and a remote
`DOCKER_HOST` is never followed. `--no-containers` skips all of it.

**Residual.** The answer is for the image's own tool, which an image author controls.

### Supply chain (B4)

**Mitigation.** No runtime or development dependencies (enforced by test). Every GitHub Action is pinned by full
commit SHA; workflows get read-only tokens unless a job needs more. Releases are built by a workflow that waits for a
maintainer's approval, attested with Sigstore, and published to npm by hand from the attested file
([docs/RELEASING.md](RELEASING.md)). **Measured:** v0.1.17 and v0.1.18 rebuild from their tags byte for byte, on a
different operating system and npm version from the release workflow (`scripts/reproduce-release.sh`), and CI checks
the newest release this way on every push.

**Residual.** The build depends on file permission bits (measured: a tree unpacked under `umask 077` packs to
different bytes), so a rebuild must start from a normal checkout; the script sets `umask 022`. One maintainer, and no
second reviewer on every change (see the end).

### The Mac fix (B6)

Covered in full by R7 in [ASSURANCE_CASE.md §3](../ASSURANCE_CASE.md#3-trust-boundaries-and-the-argument) and its tests
on copies of a real bundle (`test/fix-macos.check.sh`, `test/support/mojave-shapes.sh`). Not re-derived here. It is
the one file without an in-file licence header, because its published SHA-256 would change; `REUSE.toml` declares it.

## 4. Hardening in place

| Mechanism | Where | Enforced by |
|---|---|---|
| No file-writing, moving or deleting function imported by shipped code; files opened only `O_RDONLY` | `bin/`, `lib/` | `test/conventions.test.mjs` |
| Runs with no write permission at all under Node's permission model | the whole command | `test/hardening.test.mjs` (Node 22.13 and later) |
| One process gateway: absolute path, argument list, `/`, SIGKILL timeout, allowlisted environment | `lib/run.mjs` | `test/contract-0.1.9.test.mjs`, `test/conventions.test.mjs` |
| One disk gateway: read-only, non-blocking, regular files only, size caps, "couldn't look" told from "not there" | `lib/files.mjs` | `test/contract-0.1.9.test.mjs` |
| One way to say SAFE, only with a list of what was looked at | `lib/report.mjs` | `test/contract-0.1.9.test.mjs` |
| One escaper for everything printed | `lib/escape.mjs` | the planted-name tests |
| Network only in `lib/probe.mjs`; certificate checking never off except the reachability handshake | `lib/probe.mjs` | `test/conventions.test.mjs` |
| A crash exits 2 ("could not be tested"), never 1 or 0, and its message is escaped | `lib/crash.mjs` | `test/reread-r2.test.mjs`, `test/reread-r3.test.mjs`, `test/r5-audit.test.mjs` |
| Python probes isolated (`-I`); every child process and connection has a timeout | `lib/probe.mjs`, `lib/run.mjs` | the probe tests |
| Deprecated Node APIs fail CI | CI | `NODE_OPTIONS=--throw-deprecation --pending-deprecation` |

**Node's permission model.** On Node 22.13 or later (or 23.5 and later) a person can run Wardlatch from a clone with
reading and child processes allowed and nothing else:

```bash
node --permission --allow-fs-read='*' --allow-child-process bin/wardlatch.mjs
```

Node then refuses
any file write, worker thread, native add-on or WASI from Wardlatch's own process. *Measured:* the same answers with and
without it for every offline incident (the test), and on this machine for the git, macOS and committed-keys checks.
What it does not do: the programs Wardlatch starts (git, curl, the runtimes being checked) are not Node and are not
restricted, which is why Node prints a warning about `--allow-child-process`; and it does not restrict network
connections. It is an extra wall for the person who wants one, not a replacement for the code-level rules above.
Wardlatch does not turn it on by itself: its engine floor is Node 18.17, which has no permission model.

## 5. Dynamic analysis and assertions

- **The test suite runs the real command**, offline, against stand-ins (a throwaway CA and canary server on
  127.0.0.1, fake programs on a private `PATH`, fake containers, fake homes), on Node 18, 20 and 22, Linux and macOS,
  on every push and pull request, and in the release workflow before anything is built. 1,033 tests at 1dfd218
  (a local run).
- **Coverage is measured on every push** with V8's own coverage (`npm run coverage`), with floors of 90% of lines, 80%
  of branches and 80% of functions. CI at 1dfd218: 99.70% of lines, 93.31% of branches, 98.82% of functions.
- **Every bug fix comes with a test that fails without it** ([CONTRIBUTING.md](../CONTRIBUTING.md#testing-policy)).
- **The permission-model run** above is a dynamic check of R3 from outside the code.
- **Not yet:** a fuzzer or property-based test of the parsers that take untrusted input (version strings, file names,
  certificate text). It is planned as a contributor task.
- **Assertions.** The shipped code checks its own invariants with explicit errors rather than `node:assert` (16 in
  `lib/`: an unknown process purpose, an incident with no keys to look for, a SAFE with nothing looked at, and so on),
  and `lib/crash.mjs` turns any of them into exit 2, "could not be tested", so a broken invariant can never end in
  SAFE. The tests use `node:assert/strict` throughout. That is fewer run-time assertions than "many"; most of the
  invariants are held by the single gateways instead.

## 6. Residual risks, in one place

1. **A false SAFE through an on-path attacker** once the controls pass (B1). Stated in the assurance case.
2. **Programs on `PATH` are trusted** (by design), and a version rule trusts the version a program prints.
3. **No fuzzing of the parsers yet** (section 5).
4. **A working-tree link at a tracked path is followed** by the committed-keys scan (section 3, measured, judged low).
5. **The permission model does not cover child processes or the network** (section 4).
6. **`fix/fix-macos.sh` has no in-file licence header**, to keep its published checksum.
7. **The build depends on file permission bits**; rebuild from a normal checkout.
8. **One maintainer, no second reviewer on every change.** A successor holds full access but most changes are reviewed
   by their author only. This is the largest process risk, and it is why this review cannot be called independent.
9. **Everything in [ASSURANCE_CASE.md §4](../ASSURANCE_CASE.md#4-what-is-not-defended)**, which is the longer list and
   the authority.

## 7. What would make this stronger

- A review by someone outside Deimos AI LLC, of the design and of `lib/run.mjs`, `lib/files.mjs`, `lib/escape.mjs`
  and `lib/probe.mjs` first; findings go through [SECURITY.md](../SECURITY.md).
- Generated-input tests (fuzz or property tests) of the version, name and certificate parsers.
- A second person reviewing most changes before they merge.
- A decision on `O_NOFOLLOW` for tracked files in the committed-keys scan.
