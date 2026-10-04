# actionwarden

[![CI](https://github.com/sriharifortitude/actionwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/actionwarden/actions/workflows/ci.yml)

A security linter for GitHub Actions workflows: script injection, privileged
workflows that check out a pull request's code, unpinned actions, and
over-broad token permissions. Go, one dependency (`yaml.v3`), MIT.

## Why

A workflow runs with the repository's secrets and a token that can often
push, and it runs on text that strangers write: issue titles, branch names,
pull request bodies, commit messages. Two mistakes cause most of the damage:

- putting that text into a `run:` script with `${{ }}`, which is substituted
  *before* the shell runs, so a title can become part of the program;
- using an action by tag. Tags move. In March 2025 the tag of
  `tj-actions/changed-files` was re-pointed to code that printed secrets into
  the logs of every repository that used it (CVE-2025-30066).

GitHub documents both in its security hardening guide. Neither is hard to
check for, and most repositories still have them.

## What it finds

Three workflows in `testdata/vulnerable/`: an issue-triage bot, a pull request
preview deployer, and a release workflow.

<!-- demo:start -->
```
testdata/vulnerable/.github/workflows/pr-preview.yml:5  HIGH     AW004  the workflow grants write-all to every job
testdata/vulnerable/.github/workflows/pr-preview.yml:9  HIGH     AW006  job "preview" runs on a self-hosted runner and the workflow is triggered by pull_request_target; if this repository is public, an outsider's code runs on that machine
testdata/vulnerable/.github/workflows/pr-preview.yml:11  LOW      AW001  this step uses actions/checkout, and the tag "v4" can be moved to different code
testdata/vulnerable/.github/workflows/pr-preview.yml:13  CRITICAL AW003  step "actions/checkout@v4" checks out the pull request's code (ref: ${{ github.event.pull_request.head.sha }}) in a pull_request_target workflow, which runs with the base repository's secrets and write token
testdata/vulnerable/.github/workflows/pr-preview.yml:14  HIGH     AW001  this step uses some-org/deploy-preview@main, which follows a branch: every push to it runs in your workflow
testdata/vulnerable/.github/workflows/pr-preview.yml:15  MEDIUM   AW008  step "step 3" pipes a download into a shell
testdata/vulnerable/.github/workflows/pr-preview.yml:17  LOW      AW001  this step uses actions/upload-artifact, and the tag "v4" can be moved to different code
testdata/vulnerable/.github/workflows/pr-preview.yml:20  HIGH     AW005  step "actions/upload-artifact@v4" uploads ".", which includes .git/config, where step "actions/checkout@v4" left the job's token (persist-credentials is not false)
testdata/vulnerable/.github/workflows/release.yml:7  MEDIUM   AW004  job "publish" has no permissions: block and neither has the workflow, so its token gets the repository or organisation default, which may be read/write
testdata/vulnerable/.github/workflows/release.yml:8  MEDIUM   AW001  job "publish" uses some-org/workflows/.github/workflows/publish.yml, and the tag "v2" can be moved to different code
testdata/vulnerable/.github/workflows/release.yml:9  MEDIUM   AW009  job "publish" passes every secret to the reusable workflow it calls
testdata/vulnerable/.github/workflows/triage.yml:9  MEDIUM   AW004  job "label" has no permissions: block and neither has the workflow, so its token gets the repository or organisation default, which may be read/write
testdata/vulnerable/.github/workflows/triage.yml:14  CRITICAL AW002  step "Greet" interpolates `github.event.issue.title` into a shell script; whoever controls that text controls the script
testdata/vulnerable/.github/workflows/triage.yml:17  MEDIUM   AW010  step "Slash command" has `if: ${{ github.event.comment.body }} == '/deploy'`; with text outside the `${{ }}` the whole value is a non-empty string, which is always true

14 finding(s): 2 critical, 4 high, 6 medium, 2 low, in 3 workflow(s)
```
<!-- demo:end -->

| Rule | Severity | What |
| --- | --- | --- |
| AW001 | low to high | action not pinned to a commit (high when it follows a branch) |
| AW002 | high, critical | untrusted text interpolated into a `run:` or `github-script` |
| AW003 | high, critical | `pull_request_target` / `workflow_run` checks out the pull request's code |
| AW004 | medium, high | no `permissions:` block, `write-all`, or write granted to every job |
| AW005 | high | checkout credentials can end up in an uploaded artifact |
| AW006 | medium, high | self-hosted runner reachable from a pull request or comment |
| AW007 | high | `::set-env`, `::add-path`, `ACTIONS_ALLOW_UNSECURE_COMMANDS` |
| AW008 | medium | `curl ... \| sh` |
| AW009 | low, medium | `secrets: inherit` |
| AW010 | medium | `if:` that is always true because `${{ }}` is only part of it |

`actionwarden rules` prints each with why it matters and how to fix it.
Severity moves with the trigger: the same injection is critical in a workflow
that `issues` or `pull_request_target` starts, because there the job has
secrets, and high in one that only `push` starts.

## It reads the expressions

Line 15 of `triage.yml` mentions `github.event.issue.body` and is **not**
reported. Line 14, which interpolates the title, is. The difference is that
the first is `contains(github.event.issue.body, 'stack trace')`, whose value
is `true` or `false`, and the second puts the title itself into the script.

A search for context names cannot tell them apart, and one that flags every
`contains()` gets switched off. actionwarden parses each `${{ }}` and follows
the value: through `||`, `&&`, `format()`, `toJSON()`, `fromJSON()` and
property reads, but not through comparisons or `contains()`. It also catches
what a search misses, such as `toJSON(github.event.issue)`, which carries the
title without naming it. See
[ADR 1](docs/adr/0001-parse-expressions-do-not-grep.md).

## Usage

```bash
go install github.com/sriharifortitude/actionwarden/cmd/actionwarden@v0.1.0

actionwarden scan                       # ./.github/workflows
actionwarden scan --brief .             # one line per finding
actionwarden scan --fail-on medium .    # exit 1 at medium or above (default: high)
actionwarden scan --format sarif . > actionwarden.sarif
actionwarden scan --format json .
```

Exit codes: 0 nothing at or above `--fail-on`, 1 at least one finding is, 2 a
usage error or a file that could not be read. A file that is not valid YAML
fails the run even when everything else is clean: a check that exits 0
because it could not read its input looks like a result and is not one.

`--format sarif` produces SARIF 2.1.0, which GitHub code scanning accepts
(upload it with `github/codeql-action/upload-sarif`, pinned to a commit
like everything else).

Suppress a finding with a reason, on its line or alone on the line above:

```yaml
- uses: vendor/tool@v2 # actionwarden:ignore AW001 -- vendored and reviewed 2026-10-01
```

A suppression without a reason suppresses nothing and is itself reported
(AW000). See [ADR 2](docs/adr/0002-a-suppression-needs-a-reason.md).

## Run on real workflows

**My own 25 repositories** (38 workflows, 2026-10-04): 164 findings, every one
AW001. 106 low (first-party actions by tag), 52 medium (third-party actions by
tag), 6 high: `dtolnay/rust-toolchain@stable` and `@master` in two repositories.
That action is designed to be used by branch name, and pinning it to a commit
means setting its `toolchain:` input instead. There were no injection
findings and no workflow without a `permissions:` block. I had not pinned my
own actions before running this, which is the kind of thing the tool is for.

**234 workflows from 11 public projects** (cli/cli, prometheus, terraform,
kind, grafana, next.js, vscode, cargo, flask, django, ruff), checked out on
2026-10-04: all 234 parsed. Findings: 300 AW001 (52 high, mostly one
organisation's own shared workflows referenced at `@main`), 39 AW004, 56 AW009,
5 AW006, 3 AW008, and none of AW002, AW003, AW005, AW007 or AW010.

What that does and does not show. It shows the parser copes with real
workflows from large projects. It does
not show the rules are accurate: there is no ground truth for those projects,
and I did not review the findings against each project's repository settings.
AW004 and AW006 in particular depend on settings the file does not contain.
I have not compared the output with other tools such as zizmor or actionlint.

## Tested

```bash
go test ./...   # 49 tests, 2 fuzz targets; CI runs them with -race and fuzzes 30s each
```

Each rule has cases that must fire and cases that must not, with line numbers
checked, including `${{ }}` inside `run: |` blocks. The expression engine has a
table of what flows and what does not. Several tests were run against
deliberately broken copies of the code to check they fail: `contains()`
treated as carrying text, the `format()` string treated as a value, `&&`/`||`
dropping an operand, the pwn-request check ignoring the trigger, the
permissions check removed, a reasonless suppression accepted, line numbers
inside `|` blocks lost, the size cap removed, and the exit code for an
unreadable file. One of those nine survived at first (nothing tested the exit
code for a file that exists but is invalid), and now has a test. CI also scans
this repository's own workflows at the strictest level, and its own actions are
pinned to commits.

**Not tested:** the rules follow GitHub's documentation and public write-ups
of these attack patterns. I have not run them against a set of workflows known
to be exploitable, so false negatives are unmeasured. The fixtures are mine.

## Not covered

- Composite actions (`action.yml`); only workflow files.
- `inputs.*`, `workflow_dispatch` inputs and `github.event.client_payload` as
  untrusted. They are untrusted only when the caller is.
- Whether a pinned commit is the one the tag claims, or is trustworthy.
  actionwarden does not resolve tags to commits for you.
- Cache and artifact poisoning across workflows, and `gh pr checkout` or
  `git fetch` of a pull request inside a `run:` (AW003 looks at
  `actions/checkout` only).
- Repository settings: default token permissions, fork-approval rules, branch
  protection. It sees the file, not the repository.
- A reusable workflow in the same repository referenced at `@main` is reported
  like any branch reference.

See [`docs/adr/`](docs/adr/) for the decisions behind it.

## Licence

MIT.
