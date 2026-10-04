# 0001. Read the expression language; do not search for context names

**Status:** accepted

## Decision

To decide whether untrusted text reaches a script, actionwarden parses each
`${{ ... }}` with a small parser for GitHub's expression language and follows
the value through the expression: `||` and `&&` pass either side through,
`format()` passes its arguments (not its format string), `toJSON()` and
`fromJSON()` pass everything inside, and comparisons, `contains()`,
`startsWith()`, `endsWith()` and `!` yield a boolean and pass nothing.

An expression the parser cannot read is not cleared. A loose scan reports any
untrusted context named anywhere in its text.

## Reasoning

The simple approach is a regular expression for `github.event.issue.title` and
its relatives. It is wrong in both directions.

- `if: contains(github.event.issue.title, 'bug')` names the title and cannot
  inject anything, because its value is `true` or `false`. A search flags it,
  and a tool that flags every `contains()` in every `if:` gets switched off.
- `${{ format('{0}', github.event.issue.title) }}` and
  `${{ toJSON(github.event.issue) }}` carry the title straight into the script.
  A search for the exact path misses the second entirely, because the title
  is never named; the whole issue object is.

Both are one-line differences in real workflows, so the tool has to know the
difference. The lexer and parser are about 440 lines, fuzzed, with a nesting limit so a
hostile file cannot exhaust the stack.

`github.event` on its own is treated as harmless in a plain interpolation
(it renders as the word `Object`) and as untrusted once serialised.

## Costs

The list of untrusted contexts is maintained by hand from GitHub's guidance
and will lag it. It does not include `inputs.*`, `workflow_dispatch` inputs or
`github.event.client_payload`, which are untrusted only when the caller is.
The loose fallback over-reports on expressions it cannot parse, which is the
direction chosen on purpose.
