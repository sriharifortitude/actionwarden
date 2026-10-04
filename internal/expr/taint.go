package expr

import (
	"regexp"
	"sort"
	"strings"
)

// untrusted lists the context paths whose value an outside party chooses:
// the text of an issue, a pull request, a comment or a commit, and the name of
// a branch. A `*` segment matches any one segment. The list follows GitHub's
// own "Understanding the risk of script injections" guidance.
var untrusted = [][]string{
	strings.Split("github.event.issue.title", "."),
	strings.Split("github.event.issue.body", "."),
	strings.Split("github.event.pull_request.title", "."),
	strings.Split("github.event.pull_request.body", "."),
	strings.Split("github.event.pull_request.head.ref", "."),
	strings.Split("github.event.pull_request.head.label", "."),
	strings.Split("github.event.pull_request.head.repo.default_branch", "."),
	strings.Split("github.event.pull_request.head.repo.description", "."),
	strings.Split("github.event.pull_request.head.repo.homepage", "."),
	strings.Split("github.event.comment.body", "."),
	strings.Split("github.event.review.body", "."),
	strings.Split("github.event.review_comment.body", "."),
	strings.Split("github.event.discussion.title", "."),
	strings.Split("github.event.discussion.body", "."),
	strings.Split("github.event.pages.*.page_name", "."),
	strings.Split("github.event.commits.*.message", "."),
	strings.Split("github.event.commits.*.author.email", "."),
	strings.Split("github.event.commits.*.author.name", "."),
	strings.Split("github.event.head_commit.message", "."),
	strings.Split("github.event.head_commit.author.email", "."),
	strings.Split("github.event.head_commit.author.name", "."),
	strings.Split("github.event.workflow_run.head_branch", "."),
	strings.Split("github.event.workflow_run.head_commit.message", "."),
	strings.Split("github.event.workflow_run.head_commit.author.email", "."),
	strings.Split("github.event.workflow_run.head_commit.author.name", "."),
	strings.Split("github.event.workflow_run.head_repository.description", "."),
	strings.Split("github.event.workflow_run.pull_requests.*.head.ref", "."),
	strings.Split("github.head_ref", "."),
}

// untrustedCheckout lists the paths that point a checkout at code from a pull
// request's head, which is code an outside party wrote.
var untrustedCheckout = [][]string{
	strings.Split("github.event.pull_request.head", "."),
	strings.Split("github.event.pull_request.merge_commit_sha", "."),
	strings.Split("github.head_ref", "."),
	strings.Split("github.event.workflow_run.head_sha", "."),
	strings.Split("github.event.workflow_run.head_branch", "."),
	strings.Split("github.event.workflow_run.head_repository", "."),
	strings.Split("github.event.workflow_run.pull_requests", "."),
}

func segmentMatches(pattern, seg string) bool {
	return pattern == "*" || seg == "*" || seg == "?" || pattern == seg
}

// match reports whether path lies at or under one of the patterns (direct),
// or is a shorter path that leads towards one (contains), as github.event
// contains github.event.issue.title.
func match(patterns [][]string, path []string) (direct, contains bool) {
	for _, pat := range patterns {
		n := len(pat)
		if len(path) < n {
			n = len(path)
		}
		ok := true
		for i := 0; i < n; i++ {
			if !segmentMatches(pat[i], path[i]) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if len(path) >= len(pat) {
			direct = true
		} else {
			contains = true
		}
	}
	return direct, contains
}

// IsUntrusted reports whether a reference's value is attacker-chosen text.
func IsUntrusted(path []string) bool {
	d, _ := match(untrusted, path)
	return d
}

// PointsAtUntrustedCode reports whether a reference names a pull request's head.
func PointsAtUntrustedCode(path []string) bool {
	d, _ := match(untrustedCheckout, path)
	return d
}

type taint struct {
	direct   []string
	contains []string
}

func (t taint) union(o taint) taint {
	return taint{append(append([]string{}, t.direct...), o.direct...), append(append([]string{}, t.contains...), o.contains...)}
}

func analyze(n *Node) taint {
	switch n.Kind {
	case Ref:
		d, c := match(untrusted, n.Path)
		name := strings.Join(n.Path, ".")
		switch {
		case d:
			return taint{direct: []string{name}}
		case c:
			return taint{contains: []string{name}}
		}
	case Not:
		return taint{} // a boolean
	case Binary:
		switch n.Op {
		case "&&", "||":
			return analyze(n.Args[0]).union(analyze(n.Args[1]))
		}
		return taint{} // a comparison yields a boolean
	case Prop:
		// Reading a field of a computed value, such as fromJSON(x).name: the
		// field is as untrusted as whatever it was computed from.
		t := analyze(n.Args[0])
		return taint{direct: append(append([]string{}, t.direct...), t.contains...)}
	case Call:
		switch n.Op {
		case "contains", "startswith", "endswith", "hashfiles", "success", "failure", "always", "cancelled":
			return taint{}
		case "tojson", "fromjson":
			var t taint
			for _, a := range n.Args {
				t = t.union(analyze(a))
			}
			return taint{direct: append(append([]string{}, t.direct...), t.contains...)}
		case "format":
			// The format string is not the value; the arguments are.
			var t taint
			for _, a := range n.Args[min(1, len(n.Args)):] {
				t = t.union(analyze(a))
			}
			return taint{direct: t.direct}
		}
		var t taint
		for _, a := range n.Args {
			t = t.union(analyze(a))
		}
		return taint{direct: t.direct}
	}
	return taint{}
}

// Tainted returns the untrusted context references whose text can end up in
// the value of the expression, sorted and without repeats.
func Tainted(n *Node) []string {
	return dedupe(analyze(n).direct)
}

var looseRef = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_-]*(?:\.(?:[A-Za-z0-9_*][A-Za-z0-9_-]*)|\['[^']*'\]|\[\*\])*`)

// TaintedLoose is the fallback for an expression that did not parse: every
// untrusted reference that appears anywhere in the text. It over-reports (it
// cannot tell contains() from format()) because the alternative is to say
// nothing about an expression it did not understand.
func TaintedLoose(src string) []string {
	var out []string
	for _, m := range looseRef.FindAllString(src, -1) {
		norm := strings.ToLower(m)
		norm = strings.NewReplacer("['", ".", "']", "", "[*]", ".*").Replace(norm)
		path := strings.Split(norm, ".")
		if IsUntrusted(path) {
			out = append(out, strings.Join(path, "."))
		}
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Span is one `${{ ... }}` found in a string.
type Span struct {
	// Src is the text between the delimiters, trimmed.
	Src string
	// Start is the offset of the opening `${{` in the string searched.
	Start int
	// End is the offset just past the closing `}}`.
	End int
}

// Extract finds every `${{ ... }}` in s. A `}}` inside a quoted string does
// not end the expression, as in GitHub's own parser.
func Extract(s string) []Span {
	var out []Span
	for i := 0; i < len(s); {
		start := strings.Index(s[i:], "${{")
		if start < 0 {
			break
		}
		start += i
		inQuote := false
		end := -1
		for j := start + 3; j+1 < len(s); j++ {
			switch {
			case s[j] == '\'':
				inQuote = !inQuote
			case !inQuote && s[j] == '}' && s[j+1] == '}':
				end = j
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			break
		}
		out = append(out, Span{Src: strings.TrimSpace(s[start+3 : end]), Start: start, End: end + 2})
		i = end + 2
	}
	return out
}
