# npm-block-packages

> ⚠️ **This is NOT the official npm CLI.**
> This is a community fork of [`npm/cli`](https://github.com/npm/cli) with **one specific addition**: every `npm install` consults an auto-updated blacklist of known-compromised packages and refuses to install matches. For the official, upstream npm CLI go to **https://github.com/npm/cli**.

All standard npm behavior is inherited unchanged from upstream. This document only describes what this fork adds. For everything else — `npm install` semantics, lockfiles, workspaces, scripts, configuration, etc. — refer to the [official npm documentation](https://docs.npmjs.com/).

## What this fork does

Before resolving the dependency tree, `npm install` (and `npm ci`, `npm install-test`, `npm install-ci-test`) consults a list of npm packages that are publicly known to be malicious or compromised. If any of the requested packages — or any of their transitive dependencies — appears on the list, the install is aborted with an `EBLOCKED` error **before any files are written** to `node_modules`.

The list is fetched on demand from a configurable URL, cached locally, and refreshed periodically. The default source aggregates the [OpenSSF `malicious-packages`](https://github.com/ossf/malicious-packages) advisory database for the npm ecosystem (~210k entries, refreshed daily).

## Installation

```bash
npm i -g github:boehand/npm-block-packages
```

This replaces your current `npm` with this fork (same as the upstream `npm i -g npm@latest`). To revert at any time, run `npm i -g npm`.

You need an existing Node.js / npm to run the line above — the fork only changes the `npm` binary, not Node itself.

## New command: `npm blacklist`

```text
npm blacklist list                                       # show the cached list
npm blacklist update                                     # force a refresh
npm blacklist check <pkg>[@<version>] [<pkg>[@<ver>] …]  # check specs without installing
npm blacklist scan [<dir>]                               # scan an existing tree on disk
```

`check` exits with status `1` if any of the supplied specs are on the list, which makes it useful as a CI pre-step.

`scan` recursively walks `<dir>` (defaults to the current directory), reads every `package-lock.json` and the top level of every `node_modules/` directory it finds, and reports any installed package or locked version that appears on the blacklist. This is the retroactive complement to the install gate — the gate stops *future* installs, `scan` surfaces *past* installs that pre-date the gate. Exits with status `1` when any hit is found, both for plain-text and `--json` output.

## New configuration keys

| Key | Default | Effect |
|---|---|---|
| `--blacklist-url` | OSSF aggregated mirror | URL the list is fetched from on install. |
| `--blacklist-ttl` | `21600000` (6 h) | How long the cached list is trusted before refetching. Set to `0` to refresh on every install. |
| `--allow-blocked` | `false` | Bypass the blacklist for a single install. Equivalent to `--force` for the gate only. |

The same keys work as environment variables: `NPM_BLACKLIST_URL`, `NPM_BLACKLIST_TTL`, and `NPM_BLACKLIST_DISABLED=1` (the last fully disables the gate, intended for air-gapped CI).

## What a block looks like

```text
npm error code EBLOCKED
npm error blacklist npm blocked the install because 1 package is on the compromised-packages blacklist:
npm error blacklist
npm error blacklist   - flatmap-stream: Malicious package used to compromise event-stream. (https://github.com/advisories/GHSA-mh6f-8j2x-4483)
npm error blacklist
npm error blacklist Blacklist source: https://github.com/ossf/malicious-packages
npm error blacklist Override at your own risk with --allow-blocked.
```

## How the list stays current

A scheduled GitHub Action in this repo (`.github/workflows/update-blacklist.yml`) shallow-clones [`ossf/malicious-packages`](https://github.com/ossf/malicious-packages) once a day, runs `scripts/build-blacklist.js` to flatten every npm-ecosystem OSV advisory into a single compact JSON document, and force-pushes the result to a dedicated `blocked-list` branch. Clients fetch that branch via `raw.githubusercontent.com`, which serves it gzipped (~1.4 MB on the wire).

If you want to use a different source — your own internal list, a different aggregator, etc. — point `--blacklist-url` at it. The expected format is documented in [`lib/utils/blacklist-default.json`](lib/utils/blacklist-default.json).

## Disclaimer

This fork is provided as-is. It is **not affiliated with npm, Inc., GitHub, or the OpenJS Foundation**. The blacklist itself is best-effort: it depends entirely on the upstream OSSF data and can lag behind newly disclosed compromises. **It is not a replacement for `npm audit`, lockfile review, dependency pinning, or any other security practice.** Always treat installs from any source — including this one — as code you are running.

For the official, supported npm CLI, see **https://github.com/npm/cli**.
