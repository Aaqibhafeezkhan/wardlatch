# Coverage protocol

How Wardlatch makes sure it has not missed an incident it should carry. This is a mechanism, not a promise: the rule
below is a test (`test/coverage-protocol.test.mjs`) and a command (`node scripts/coverage/check.mjs`), and either
fails when an item is neither named nor declined.

## Why this exists

On 16 Nov 2026 the owner saw posts about CVE-2026-65339, an Apple "Audio" flaw ("An app may be able to leak sensitive
user information"), fixed in macOS Tahoe 26.6.2 on 17 Aug 2026 and Sequoia 15.8 on 14 Sep 2026. Wardlatch named it
nowhere, three months after the fix, although `macos-2026-11` had read the very index that lists both releases
(13 Nov 2026). Three things let it through, and they are the pattern behind earlier misses too:

1. **Intake was event-driven.** Incidents came from the owner's screenshots of posts, from the news of the week, and
   from a look at CISA's catalog over the last few weeks ("Other KEV entries since 10 Oct 2026", research of
   13 Nov 2026). No source was ever read whole, item by item, for a window of months. A flaw fixed before the window
   and never in the news was never looked at.
2. **The macOS check filtered by KEV.** `macos-2026-11` names a CVE only when CISA lists it. Every other Apple fix is
   folded into one unnamed REVIEW line ("below the line's latest release"). That is a sound verdict rule, but it
   meant 252 Apple fixes in the owner's classes over six months were in no list anyone could see.
3. **"We checked" was never tied to a complete read.** Each sweep said what it found, not which source it read whole
   and which it did not, so an empty answer looked like a clean one. This is the same failure the project fixed in
   Wardlatch's own output in 0.1.9 ("every safe names what it checked"), and the one the 10 Nov 2026 pattern note
   names: a confident negative from an incomplete scan.

## Sources

Each source is read whole for the window, or the check says INCOMPLETE and fails.

| Source | What is read | Whole means |
|---|---|---|
| `apple-macos` | Apple's security releases index, [support.apple.com/en-us/100100](https://support.apple.com/en-us/100100), and the notes page of every macOS release it lists in the window | the index reaches back past the window's start; every macOS row in the window has its page read (or Apple's own "no published CVE entries"); every CVE number on each page is placed in an entry (`parseNotes` throws otherwise); every entry has its Impact line |
| `cisa-kev` | CISA's [Known Exploited Vulnerabilities feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), every row added in the window | the feed's own `count` equals the rows read; the rows kept equal the rows in the window |

Read and not covered, by name: Apple's iOS, iPadOS, watchOS, tvOS, visionOS, Safari, Xcode and other non-macOS rows in
the same index (Wardlatch runs on the Mac and reads no other Apple device; incidents that also affect them say so in
their output, as `apple-audio-2026-08` does). Not read at all: Linux distributions' security trackers, GitHub's
advisory database, and the vendors behind the other incidents (Google, Microsoft, Git, GitLab, and the rest). Adding
one is adding a source here and to `scripts/coverage/refresh.mjs`, with its own "whole means" rule.

## Classes

An Apple entry is in scope when its Impact line matches one of these (`CLASSES` in `scripts/coverage/check.mjs`); the
owner's list of 16 Nov 2026, plus privilege escalation and anything Apple says may have been exploited:

- `privacy`: permission, TCC and privacy bypass ("sensitive user data", "Privacy preferences", "without permission",
  contacts, location, microphone, camera, fingerprinting);
- `sandbox`: sandbox escape;
- `code-signing`: Gatekeeper and code-signing bypass;
- `trust`: certificates, trust, TLS, impersonation and spoofing;
- `privilege`: root, kernel or elevated privileges, and writing protected parts of the file system;
- `exploited`: Apple's "Apple is aware of a report that this issue may have been exploited".

Every row CISA adds to its catalog in the window is in scope as `exploited`, whatever the product.

## What "covered" means

An item in scope is covered in exactly one of two ways:

- **named**: its CVE number appears in an incident file in `lib/incidents/`, so a check can say EXPOSED for it; or
- **declined**: an entry in `scripts/coverage/declined.json` with its key (the CVE, or for an Apple entry printed
  without a number, `apple:<release>:<component>:<place>`), a one-line reason of 12 to 240 characters, and a
  `reviewBy` date. A decline past its date fails the check: a decline is a decision with a date, not a place to
  leave things. `candidate: true` marks one that should probably become an incident.

Anything in neither is a GAP, and the check fails. Being rolled up in an unnamed REVIEW line is not covered.

## The rule about "no gaps"

**"No gaps found" is only valid from a complete scan that names every source it read.** The check prints each source
with its own counts (index rows and how far back they reach; catalog version and rows read of rows listed) before
any verdict, and prints `NO GAPS, from a complete read of: …` only when every source in the table above was read
whole and the snapshot is at most 31 days old. Otherwise it prints `INCOMPLETE` with the reason and fails, even if it
found no gap. The same holds for a person: a sweep that reports "nothing missing" names its sources and window in the
same sentence, or it is reported as incomplete.

## Cadence

- **Weekly, and before every release:** `node scripts/coverage/refresh.mjs` (the only step that uses the network),
  then `node scripts/coverage/check.mjs`. Every new gap is triaged the same week: an incident, or a decline with a
  reason. `node scripts/kev-snapshot.mjs` re-copies the incidents' KEV rows from the same feed (docs/RELEASING.md, step 0).
- **Every CI run:** `npm test` runs `test/coverage-protocol.test.mjs` on the committed snapshot. It fails on a gap, on
  a decline past its `reviewBy`, and on a snapshot older than 31 days, so a month without a refresh turns CI red on its
  own.
- **The window** is six months back from the refresh (`--months`, 1 to 36). An item that leaves the window leaves
  the check; its incident or decline stays as history.

## Proving the check can fail

The test replays the 16 Nov 2026 miss: with `apple-audio-2026-08` taken out, CVE-2026-65339 must come back as a GAP.
It also removes a decline (a gap), back-dates one (expired), takes a source away or shortens a read (INCOMPLETE), and
feeds the readers planted pages with a stray CVE number or a missing Impact line (each throws). Planted mutations of
the check's own code (the KEV count gate, the completeness term of `ok`, the privacy class, the expiry rule, the
notes reader's stray-CVE gate, entries without a CVE, the age gate, the release count gate, matching by CVE key)
were each caught by this test on 16 Nov 2026.

## Owner decisions open (16 Nov 2026)

- **D1.** Apple's 252 in-class fixes of the last six months that CISA does not list are declined until 30 Nov 2026 as
  "rolled up in `macos-2026-11`'s REVIEW, not named". Name them (each would make a Mac below its fix EXPOSED, which
  changes `macos-2026-11`'s decision that only KEV fixes are EXPOSED), name a chosen subset (privacy and sandbox, say),
  or keep them declined with that reason?
- **D2.** Self-hosted server products in CISA's catalog (Oracle, Atlassian, JFrog, Zimbra and the like) are declined
  as out of scope. Keep that scope?
- **D3.** 32 declines are marked `candidate`: the Linux kernel (7), WordPress core (4), Chrome V8 (3), GitLab (2),
  LiteLLM (2), and developer tools and packages (Nx Console, TanStack, Starlette, Langflow, MLflow, Ray, Strapi,
  Kestra, Gitea, TeamCity, Tomcat). Which become incidents?
- **D4.** The 31-day age gate and the `reviewBy` dates make CI fail on their own after a missed refresh or triage.
  Keep that, or move the gate to the release workflow only?
