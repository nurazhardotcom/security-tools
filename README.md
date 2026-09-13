# security-tools

> **Status:** Active — maintained toolkit. See [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

Six security automation assistants in Clojure/babashka. Zero external
dependencies, pure functions, deterministic output, fully tested.

## Requirements

- [babashka](https://babashka.org) >= 1.13
- (optional, for CI) [clj-kondo](https://clj-kondo.io) and
  [clojure-lsp](https://clojure-lsp.io)

## Quickstart

```sh
bb run test                     # 50 tests, 175 assertions
bb prioritize data/vulns.csv            # vulnerability remediation prioritizer
bb triage data/findings.csv             # security findings triage
bb classify data/requests.csv           # privileged-access request classifier
bb tickets data/policies.csv            # policy-to-ticket generator
bb match data/roles.csv data/jobs.csv   # IAM/PAM job-matching assistant
bb summarize data/access_reviews.csv    # access review summarizer (EDN to stdout)
```

Every tool reads a CSV and writes a CSV to stdout; pass a second (or third)
path to write to a file instead. Summarizer prints an EDN report and
optionally writes flagged rows to a CSV.

Note: the task is named `test`, so it runs as `bb run test` (a `test/`
directory shadows the bare `bb test`). Direct invocation also works:
`bb -m security.prioritizer <in.csv> [out.csv]`.

## Layout

```
src/security/
  core.clj          shared CSV parser/writer + helpers (no external deps)
  prioritizer.clj   weighted 0-10 score, priority band, due date, rationale
  summarizer.clj    rollups, duplicates, orphaned & unused access
  triage.clj        rule table -> action/priority/due_hours/reason
  classifier.clj    keyword rules -> approve/escalate/deny + risk level
  tickets.clj       policy rows -> tickets with acceptance criteria
  matcher.clj       token-overlap scoring -> best role + alternatives
test/security/      clojure.test suites + test-runner entry point
data/               sample CSVs (used by the tests too)
```

## Design rules (why it stays bug-free)

- Pure functions only; I/O is confined to `-main` entry points.
- Deterministic: same input CSV -> same output, always (sorted maps, stable
  sorts, no hashing order leaks).
- Self-contained CSV handling: quoted fields, escaped quotes, embedded
  newlines, CRLF, blank lines all covered by tests.
- Tests assert the spec, not the implementation: golden fixtures over the
  sample data plus boundary cases for every rule.

## CI

```sh
bb run test && clj-kondo --lint src test && clojure-lsp diagnostics --project-root .
```
