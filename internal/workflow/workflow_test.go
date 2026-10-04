package workflow

import (
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, src string) *Workflow {
	t.Helper()
	w, err := Parse("wf.yml", []byte(strings.TrimLeft(src, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestTriggerForms(t *testing.T) {
	for _, c := range []struct {
		on   string
		want []string
	}{
		{"on: push", []string{"push"}},
		{"on: [push, Pull_Request]", []string{"pull_request", "push"}},
		{"on:\n  push:\n    branches: [main]\n  issues:\n    types: [opened]", []string{"issues", "push"}},
	} {
		w := parse(t, c.on+"\njobs:\n  a:\n    runs-on: x\n")
		var got []string
		for k := range w.Triggers {
			got = append(got, k)
		}
		if len(got) == 2 && got[0] > got[1] {
			got[0], got[1] = got[1], got[0]
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.on, got, c.want)
		}
	}
}

func TestRunsOnForms(t *testing.T) {
	for _, c := range []struct {
		runsOn string
		want   []string
	}{
		{"runs-on: ubuntu-latest", []string{"ubuntu-latest"}},
		{"runs-on: [self-hosted, linux]", []string{"self-hosted", "linux"}},
		{"runs-on:\n      group: big\n      labels: [self-hosted]", []string{"self-hosted"}},
	} {
		w := parse(t, "on: push\njobs:\n  a:\n    "+c.runsOn+"\n")
		var got []string
		for _, s := range w.Jobs[0].RunsOn {
			got = append(got, s.Value)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.runsOn, got, c.want)
		}
	}
}

func TestLinesPointAtTheRightPlace(t *testing.T) {
	w := parse(t, `
name: x
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: First
        run: |
          one
          two ${{ x }}
      - uses: actions/checkout@v4
`)
	if w.Permissions.Line != 3 || w.Jobs[0].Line != 6 {
		t.Errorf("permissions line %d, job line %d", w.Permissions.Line, w.Jobs[0].Line)
	}
	run := w.Jobs[0].Steps[0].Run
	if run.Line != 10 || run.LineAt(strings.Index(run.Value, "two")) != 12 {
		t.Errorf("run starts at %d; the second script line is at %d", run.Line, run.LineAt(strings.Index(run.Value, "two")))
	}
	if w.Jobs[0].Steps[1].Uses.Line != 13 || w.Jobs[0].Steps[1].Name != "actions/checkout@v4" {
		t.Errorf("an unnamed step is named after its action: %+v", w.Jobs[0].Steps[1])
	}
}

func TestAliasesAreFollowed(t *testing.T) {
	w := parse(t, `
on: push
x-steps: &steps
  - run: echo hi
jobs:
  a:
    runs-on: x
    steps: *steps
`)
	if len(w.Jobs[0].Steps) != 1 || w.Jobs[0].Steps[0].Run.Value != "echo hi" {
		t.Errorf("%+v", w.Jobs[0].Steps)
	}
}

func TestFoldedBlocksOnlyReportTheirFirstLine(t *testing.T) {
	w := parse(t, "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: >\n          one\n          two\n")
	run := w.Jobs[0].Steps[0].Run
	if run.Literal || run.LineAt(5) != run.Line {
		t.Errorf("folding changes the text, so offsets cannot be mapped to lines: %+v", run)
	}
}

func TestNotAWorkflow(t *testing.T) {
	for src, want := range map[string]string{
		"":                        "empty",
		"- a\n- b\n":              "not a mapping",
		"name: x\non: push\n":     "no jobs",
		"jobs: [a]\n":             "no jobs",
		"on: push\njobs: {a: [\n": "not valid YAML",
		"run: x\njobs:":           "no jobs",
	} {
		_, err := Parse("wf.yml", []byte(src))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error containing %q", src, err, want)
		}
	}
}

func TestPermissionsForms(t *testing.T) {
	w := parse(t, "on: push\npermissions: READ-ALL\njobs:\n  a:\n    runs-on: x\n    permissions:\n      Contents: Write\n      id-token: write\n")
	if w.Permissions.All != "read-all" {
		t.Errorf("%+v", w.Permissions)
	}
	if got := w.Jobs[0].Permissions.Scopes; !reflect.DeepEqual(got, map[string]string{"contents": "write", "id-token": "write"}) {
		t.Errorf("%v", got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n"))
	f.Add([]byte("jobs: &a\n  b: *a\n"))
	f.Add([]byte("on: [\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse("f.yml", data)
	})
}
