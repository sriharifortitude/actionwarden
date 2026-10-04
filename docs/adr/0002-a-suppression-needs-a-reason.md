# 0002. A suppression needs a reason, and an unreadable file is not a pass

**Status:** accepted

## Decision

A finding is suppressed by `# actionwarden:ignore AW001 -- reason`, on the
finding's line or alone on the line above it. If the reason is missing the
finding is **not** suppressed and a second finding, `AW000`, points at the
comment. Suppressed findings are counted in the summary.

A file that cannot be read or is not a workflow is reported by name, goes to
stderr, and makes the exit code 2, even when every other file is clean. A scan
that finds no workflow files is also an error.

## Reasoning

Every linter that can be silenced ends up with silences nobody remembers the
reason for. Requiring the reason at the point of suppression costs one
sentence and gives the next reader the thing they need. Refusing the
suppression rather than only warning means the reasonless comment cannot be
used to turn a build green.

A security check that exits 0 because it could not read the input is worse
than one that is missing, because it looks like a result. A typo in a path, a
workflow with invalid YAML, a file over the size limit: each is a failed scan
and says so.

## Costs

Suppressions are matched by line, so reformatting a workflow can move a
finding away from its comment, which then stops applying and the finding
returns. That fails safe. There is no baseline file and no "ignore this whole
rule" switch; if a rule does not fit, the answer is to change the rule.
