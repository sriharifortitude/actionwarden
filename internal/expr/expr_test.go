package expr

import (
	"reflect"
	"strings"
	"testing"
)

func tainted(t *testing.T, src string) []string {
	t.Helper()
	n, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return Tainted(n)
}

func TestTaintFollowsTheValue(t *testing.T) {
	title := []string{"github.event.issue.title"}
	cases := []struct {
		src  string
		want []string
	}{
		// The value is the attacker's text.
		{"github.event.issue.title", title},
		{"GitHub.Event.Issue.Title", title},
		{"github['event']['issue']['title']", title},
		{"github.event.issue.title || 'none'", title},
		{"'x' && github.event.issue.title", title},
		{"format('title: {0}', github.event.issue.title)", title},
		{"toJSON(github.event.issue)", nil}, // see below: contains, not direct, yet toJSON carries it
		{"join(github.event.commits.*.message, ', ')", []string{"github.event.commits.*.message"}},
		{"fromJSON(github.event.comment.body).command", []string{"github.event.comment.body"}},
		{"github.head_ref", []string{"github.head_ref"}},
		{"github.event.pull_request.head.ref", []string{"github.event.pull_request.head.ref"}},
		{"github.event.commits[0].author.email", []string{"github.event.commits.0.author.email"}},
		// The value is a boolean or fixed text.
		{"contains(github.event.issue.title, 'bug')", nil},
		{"startsWith(github.event.comment.body, '/deploy')", nil},
		{"github.event.issue.title == 'x'", nil},
		{"!github.event.issue.title", nil},
		{"github.event.pull_request.number", nil},
		{"github.actor", nil},
		{"format('{0} items', 3)", nil},
		{"format(github.event.issue.title, 'a')", nil}, // the format string is not the value
		{"success()", nil},
		{"hashFiles('**/go.sum')", nil},
	}
	for _, c := range cases {
		got := tainted(t, c.src)
		if c.src == "toJSON(github.event.issue)" {
			want := []string{"github.event.issue"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: got %v, want %v", c.src, got, want)
			}
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.src, got, c.want)
		}
	}
}

func TestAnObjectIsOnlyAHazardOnceSerialised(t *testing.T) {
	if got := tainted(t, "github.event"); got != nil {
		t.Errorf("an object in a string context renders as 'Object': %v", got)
	}
	if got := tainted(t, "toJSON(github.event)"); len(got) != 1 {
		t.Errorf("toJSON of the event carries every field: %v", got)
	}
	if got := tainted(t, "toJSON(github.event.pull_request.number)"); got != nil {
		t.Errorf("toJSON of a safe field: %v", got)
	}
}

func TestADynamicIndexMatchesAnything(t *testing.T) {
	if got := tainted(t, "github.event.issue[inputs.field]"); len(got) != 1 {
		t.Errorf("an index computed at run time might be 'title': %v", got)
	}
}

func TestParseErrors(t *testing.T) {
	for src, want := range map[string]string{
		"":                       "empty expression",
		"github.event.":          "expected a property name",
		"format('{0}'":           `expected ")"`,
		"'unterminated":          "unterminated string",
		"a b":                    "after the expression",
		"github.event.issue[":    "end of expression",
		"a @ b":                  "unexpected character",
		"github.event.title ||":  "end of expression",
		strings.Repeat("(", 500): "nested deeper",
	} {
		_, err := Parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want an error containing %q", src, err, want)
		}
	}
}

func TestLooseFallbackOverReports(t *testing.T) {
	got := TaintedLoose("contains(github.event.issue.title, 'x') @@ ")
	if !reflect.DeepEqual(got, []string{"github.event.issue.title"}) {
		t.Errorf("got %v", got)
	}
	if got := TaintedLoose("github['event']['comment']['body']"); !reflect.DeepEqual(got, []string{"github.event.comment.body"}) {
		t.Errorf("bracket form: %v", got)
	}
	if got := TaintedLoose("github.actor"); got != nil {
		t.Errorf("%v", got)
	}
}

func TestExtract(t *testing.T) {
	s := "echo ${{ github.event.issue.title }} and ${{ format('}}{0}', x) }} end ${{ unterminated"
	got := Extract(s)
	if len(got) != 2 {
		t.Fatalf("got %d spans: %+v", len(got), got)
	}
	if got[0].Src != "github.event.issue.title" || s[got[0].Start:got[0].End] != "${{ github.event.issue.title }}" {
		t.Errorf("first span: %+v", got[0])
	}
	if got[1].Src != "format('}}{0}', x)" {
		t.Errorf("a }} inside a string must not end the expression: %+v", got[1])
	}
}

func TestPointsAtUntrustedCode(t *testing.T) {
	for path, want := range map[string]bool{
		"github.event.pull_request.head.sha":            true,
		"github.event.pull_request.head.repo.full_name": true,
		"github.head_ref":                               true,
		"github.event.workflow_run.head_sha":            true,
		"github.event.pull_request.base.sha":            false,
		"github.sha":                                    false,
		"github.event.pull_request.number":              false,
	} {
		if got := PointsAtUntrustedCode(strings.Split(path, ".")); got != want {
			t.Errorf("%s: got %v", path, got)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"github.event.issue.title", "format('{0}', a.b[*].c)", "a || b && !c == 'd'", "((", "'", "1e", "-1 -2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := Parse(s)
		if err != nil {
			_ = TaintedLoose(s)
			return
		}
		_ = Tainted(n)
		_ = Refs(n)
	})
}
