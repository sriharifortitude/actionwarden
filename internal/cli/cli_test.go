package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exec(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, strings.ReplaceAll(out.String(), "\r\n", "\n"), errb.String()
}

const vulnerable = "../../testdata/vulnerable"
const clean = "../../testdata/clean"

func TestVulnerableFixture(t *testing.T) {
	code, out, _ := exec("scan", vulnerable)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"triage.yml:14  CRITICAL AW002",
		"pr-preview.yml:13  CRITICAL AW003",
		"pr-preview.yml:5  HIGH     AW004",
		"pr-preview.yml:20  HIGH     AW005",
		"pr-preview.yml:9  HIGH     AW006",
		"pr-preview.yml:15  MEDIUM   AW008",
		"release.yml:9  MEDIUM   AW009",
		"triage.yml:17  MEDIUM   AW010",
		"14 finding(s): 2 critical, 4 high, 6 medium, 2 low, in 3 workflow(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// The contains() on line 15 of triage.yml is safe and must not be reported.
	if strings.Contains(out, "triage.yml:15") {
		t.Error("a boolean use of untrusted text was reported")
	}
}

func TestCleanFixture(t *testing.T) {
	code, out, errs := exec("scan", clean)
	if code != 0 || !strings.Contains(out, "0 finding(s): none, in 1 workflow(s)") || errs != "" {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
}

func TestFailOn(t *testing.T) {
	for level, want := range map[string]int{"low": 1, "medium": 1, "high": 1, "critical": 1, "none": 0} {
		if code, _, _ := exec("scan", "--fail-on", level, vulnerable); code != want {
			t.Errorf("--fail-on %s: exit %d, want %d", level, code, want)
		}
	}
	// The clean fixture has nothing at any level.
	if code, _, _ := exec("scan", "--fail-on=low", clean); code != 0 {
		t.Error("clean should pass at the strictest level")
	}
}

func TestJSON(t *testing.T) {
	code, out, _ := exec("scan", "--format", "json", vulnerable)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Workflows int `json:"workflows"`
		Findings  []struct {
			Rule, Name, Severity, File, Message string
			Line                                int
		} `json:"findings"`
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if doc.Workflows != 3 || len(doc.Findings) != 14 || len(doc.Errors) != 0 {
		t.Errorf("%d workflows, %d findings, errors %v", doc.Workflows, len(doc.Findings), doc.Errors)
	}
	if first := doc.Findings[0]; first.Rule == "" || first.Name == "" || first.Line == 0 || !strings.HasSuffix(first.File, ".yml") {
		t.Errorf("%+v", first)
	}
	if _, out, _ := exec("scan", "--format", "json", clean); !strings.Contains(out, `"findings": []`) || !strings.Contains(out, `"errors": []`) {
		t.Errorf("empty lists must be [], not null:\n%s", out)
	}
}

func TestSARIF(t *testing.T) {
	_, out, _ := exec("scan", "--format=sarif", vulnerable)
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					Physical struct {
						Artifact struct{ URI string }    `json:"artifactLocation"`
						Region   struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "actionwarden" {
		t.Fatalf("%+v", doc)
	}
	sarifRun := doc.Runs[0]
	if len(sarifRun.Tool.Driver.Rules) != 11 || len(sarifRun.Results) != 14 {
		t.Errorf("%d rules, %d results", len(sarifRun.Tool.Driver.Rules), len(sarifRun.Results))
	}
	levels := map[string]int{}
	for _, r := range sarifRun.Results {
		levels[r.Level]++
		loc := r.Locations[0].Physical
		if loc.Region.StartLine < 1 || strings.Contains(loc.Artifact.URI, `\`) {
			t.Errorf("%s: %+v", r.RuleID, loc)
		}
	}
	if levels["error"] != 6 || levels["warning"] != 6 || levels["note"] != 2 {
		t.Errorf("critical and high are errors, medium a warning, low a note: %v", levels)
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	_, a, _ := exec("scan", vulnerable)
	_, b, _ := exec("scan", vulnerable)
	if a != b {
		t.Error("two runs differ")
	}
}

func TestRulesCommand(t *testing.T) {
	code, out, _ := exec("rules")
	if code != 0 {
		t.Fatal(code)
	}
	for _, id := range []string{"AW001", "AW005", "AW010"} {
		if !strings.Contains(out, id+"  ") {
			t.Errorf("%s missing", id)
		}
	}
	if strings.Count(out, "    why: ") != 10 || strings.Count(out, "    fix: ") != 10 {
		t.Error("every rule explains why and how to fix")
	}
}

func TestAnUnreadableFileIsNamedAndFailsTheRun(t *testing.T) {
	code, out, errs := exec("scan", vulnerable, "../../testdata/does-not-exist.yml")
	if code != 2 || !strings.Contains(errs, "does-not-exist.yml: no such file") || out != "" {
		t.Errorf("exit %d out=%q err=%q", code, out, errs)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"nope"},
		{"scan", "--format", "xml"},
		{"scan", "--fail-on", "urgent"},
		{"scan", "--fail-on"},
		{"scan", "--bogus"},
		{"rules", "extra"},
	} {
		code, _, errs := exec(args...)
		if code != 2 || !strings.Contains(errs, "usage: actionwarden") {
			t.Errorf("%v: exit %d, %q", args, code, errs)
		}
	}
}

func TestADirectoryWithNoWorkflowsIsAnError(t *testing.T) {
	code, _, errs := exec("scan", t.TempDir())
	if code != 2 || !strings.Contains(errs, "no workflow files found") {
		t.Errorf("an empty scan must not pass silently: exit %d, %q", code, errs)
	}
}

func TestBrief(t *testing.T) {
	_, full, _ := exec("scan", vulnerable)
	code, brief, _ := exec("scan", "--brief", vulnerable)
	if code != 1 || strings.Contains(brief, "fix:") || !strings.Contains(full, "fix:") {
		t.Errorf("brief drops the fix lines and nothing else: exit %d", code)
	}
	if got := strings.Count(brief, "\n"); got != 16 {
		t.Errorf("14 findings, a blank line and the summary: %d lines", got)
	}
	if !strings.Contains(brief, "triage.yml:14  CRITICAL AW002  step \"Greet\" interpolates `github.event.issue.title`") {
		t.Errorf("brief keeps the specific message:\n%s", brief)
	}
}

func TestAnInvalidWorkflowFailsTheRunEvenWhenTheRestIsClean(t *testing.T) {
	dir := t.TempDir()
	good, err := os.ReadFile(clean + "/.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.yml"), good, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.yml"), []byte("on: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs := exec("scan", dir)
	if code != 2 {
		t.Errorf("a file that could not be read must not look like a pass: exit %d", code)
	}
	if !strings.Contains(errs, "broken.yml: not valid YAML") || !strings.Contains(errs, "1 file(s) could not be read") {
		t.Errorf("stderr: %s", errs)
	}
	if !strings.Contains(out, "0 finding(s): none, in 1 workflow(s)") {
		t.Errorf("the readable file is still scanned: %s", out)
	}
}
