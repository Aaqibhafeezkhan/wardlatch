# Running Wardlatch in CI

Wardlatch runs the same way in a CI job as on a laptop: `npx`, no install step, no account, no token. It reads the
runner's files and programs, opens TLS connections to the incidents' public test hosts and two control sites, and
changes nothing. This page says what to pass it in CI and what the exit codes mean. Every flag and code below is
the one in `bin/wardlatch.mjs` and the README's [Reference](../README.md#reference).

## The short version

```bash
cd "$HOME" && npx --yes wardlatch@latest --json --paths "$GITHUB_WORKSPACE" > wardlatch.json
```

| Exit code | Means | In a pipeline |
|---|---|---|
| `0` | Every check that ran is SAFE (REVIEW lines may be printed beside them) | pass |
| `1` | Something is EXPOSED | fail |
| `2` | Nothing is exposed, but something could not be tested (an UNKNOWN line), or an option was wrong | your call: see below |

REVIEW lines never change the exit code. `--reach` always exits `0`, whatever it finds.

## Four things that matter on a runner

1. **Run it from the home folder, not the checkout.** `npx` started inside a project uses that project's own
   `node_modules/.bin/node` if it has one, and applies its `.npmrc`; Wardlatch can't undo either. `cd "$HOME"` first.
2. **Point it at the checkout.** With no `--paths`, Wardlatch searches `~/Development`, `~/code`, `~/src`, `~/projects`,
   `~/Projects`, `~/dev`, `~/work`, `~/Sites`, `/var/www`, `/srv/www` and `/Library/WebServer/Documents`. A runner has
   none of them, so the checks that search folders (lockfiles, Python environments, git repositories, WordPress) look
   at nothing and say so. Pass `--paths "$GITHUB_WORKSPACE"` (or your CI's checkout folder); repeat `--paths` for more.
3. **Fetch the whole history.** The workflow-file check reads every commit. A shallow clone is UNKNOWN, wherever its
   history is cut, so the run exits `2`. `actions/checkout` fetches one commit unless told otherwise: set
   `fetch-depth: 0`, or run `git fetch --unshallow` first.
4. **It needs the network.** The trust check connects to public test hosts, first with a control. If none answers, the
   result is UNKNOWN ("could not be tested"), never SAFE. A runner with no outbound network exits `2`.

Containers: Wardlatch checks running Docker and Podman containers from inside, with the image's own `curl`, `python3`
or `wget`. If you don't want that, add `--no-containers`. A `DOCKER_HOST` that points at a remote engine is not
followed; the run says so in an UNKNOWN line.

## A GitHub Actions workflow

Copy this to `.github/workflows/wardlatch.yml`. It runs on every push and pull request, and once a day, because the
incidents change without your code changing.

```yaml
name: Wardlatch
on:
  push:
  pull_request:
  schedule:
    - cron: '17 6 * * *'
permissions:
  contents: read

jobs:
  wardlatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0              # the workflow-file check needs the whole history
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1  # v7.1.0
        with:
          node-version: '22'          # any Node.js 18.17 or later
      - name: Wardlatch
        run: |
          cd "$HOME"
          set +e
          npx --yes wardlatch@latest --json --paths "$GITHUB_WORKSPACE" > wardlatch.json
          code=$?
          set -e
          jq -r '.results[] | select(.status != "SAFE") | "\(.status)  \(.incident)  \(.what // .bin // .file // .kind)  \(.reason // "")"' wardlatch.json >> "$GITHUB_STEP_SUMMARY"
          echo "wardlatch exit code: $code" >> "$GITHUB_STEP_SUMMARY"
          exit "$code"
```

The two `uses:` lines are pinned to the commits this repository's own CI uses; pin them to whatever your policy says.
`jq` is preinstalled on GitHub's Ubuntu runners.

### Fail only on EXPOSED

To fail the job only when something is exposed, and let "could not be tested" through, replace the last line with:

```bash
          if [ "$code" -eq 1 ]; then exit 1; fi
```

Do this knowingly. An exit code of `2` means some check could not see the answer, and it says why on its line: that
is not the same as safe.

### Pin the version

`wardlatch@latest` picks up new incident checks the day they ship, which is the point of running it daily. If your
policy wants every tool pinned, use `npx --yes wardlatch@0.1.19` and move the pin when a release adds a check you want.
Each release's changes are in [CHANGELOG.md](../CHANGELOG.md), and each release is attested; to verify the package
before you trust it, see [RELEASING.md](RELEASING.md#verifying-a-release).

## Any other CI

The same three rules hold anywhere: start from a folder that is not a Node.js project, pass the checkout with
`--paths`, and give the job the whole git history and outbound HTTPS.

```bash
cd "$HOME"
npx --yes wardlatch@latest --json --paths "$CHECKOUT_DIR" > wardlatch.json   # your CI's checkout folder
status=$?
```

`--json` prints one object, `{ tool, version, incidents, results }`. Each result has `incident`, `status` (`SAFE`,
`EXPOSED`, `UNKNOWN` or `REVIEW`) and `kind`, the fields of that kind, `reason` when it is UNKNOWN, and `fix` when there
is something to do. The README's [Reference](../README.md#reference) lists every kind and field. For example, a
lockfile that pins an affected React Server Components package (Wardlatch 0.1.18, `--incident react-rsc-2026-11`):

```json
{
  "incident": "react-rsc-2026-11",
  "kind": "lockfile",
  "file": "/home/runner/work/app/app/package-lock.json",
  "name": "react-server-dom-webpack",
  "version": "19.2.3",
  "what": "react-server-dom-webpack 19.2.3",
  "status": "EXPOSED",
  "reason": "react-server-dom-webpack 19.2.3 is in the affected range 19.2.0 to before 19.2.9 (React's advisory GHSA-xqc2-xf4c-x3h3, CVE-2026-126187); fixed in 19.2.9",
  "fix": "Update react-server-dom-webpack to the fixed version of its line (19.0.9, 19.1.10, 19.2.9 or 19.3.1) or later, install, then rebuild and redeploy: the lockfile says what an install fetches, not what a server is running."
}
```

That row is real output from a run on a test lockfile; only the `file` path was changed to a runner's.

## What it does not do in CI

- It checks the runner, not your production servers. Run it on the server to check the server.
- It does not install or run anything from the project: lockfiles are read as text, binaries are matched by hash, and
  programs are started only from `/`, with an allowlisted environment.
- It sends no telemetry and no results. The only traffic is the TLS connections above, and what your container engine
  sends if your docker context points at a remote one.
- Downloads from CI count as npm downloads, like any other install.
