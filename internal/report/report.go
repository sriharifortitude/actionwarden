// Package report renders a scan result as text for people, JSON, or SARIF for
// GitHub code scanning. All three are deterministic.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sriharifortitude/actionwarden/internal/rules"
	"github.com/sriharifortitude/actionwarden/internal/scan"
)

func sorted(findings []rules.Finding) []rules.Finding {
	out := append([]rules.Finding(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

// Summary counts findings by severity.
func Summary(res *scan.Result) string {
	counts := map[rules.Severity]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	detail := "none"
	if len(parts) > 0 {
		detail = strings.Join(parts, ", ")
	}
	text := fmt.Sprintf("%d finding(s): %s, in %d workflow(s)", len(res.Findings), detail, res.Workflows)
	if res.Suppressed > 0 {
		text += fmt.Sprintf("; %d suppressed with a reason", res.Suppressed)
	}
	return text
}

// Terminal writes the human-readable report. With brief set, each finding is
// one line (location, severity, rule, what is wrong) without the fix.
func Terminal(w io.Writer, res *scan.Result, brief bool) {
	for _, f := range sorted(res.Findings) {
		if brief {
			fmt.Fprintf(w, "%s:%d  %-8s %s  %s\n", f.File, f.Line, strings.ToUpper(f.Severity.String()), f.Rule, f.Message)
			continue
		}
		fmt.Fprintf(w, "%s:%d  %-8s %s  %s\n", f.File, f.Line, strings.ToUpper(f.Severity.String()), f.Rule, title(f.Rule))
		fmt.Fprintf(w, "    %s\n", f.Message)
		if f.Fix != "" {
			fmt.Fprintf(w, "    fix: %s\n", f.Fix)
		}
	}
	if len(res.Findings) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, Summary(res))
}

func title(id string) string {
	if r, ok := rules.ByID(id); ok {
		return r.Title
	}
	return id
}

type jsonFinding struct {
	Rule     string `json:"rule"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

// JSON writes the findings as one JSON document.
func JSON(w io.Writer, res *scan.Result) error {
	out := struct {
		Workflows  int           `json:"workflows"`
		Suppressed int           `json:"suppressed"`
		Findings   []jsonFinding `json:"findings"`
		Errors     []string      `json:"errors"`
	}{Workflows: res.Workflows, Suppressed: res.Suppressed, Findings: []jsonFinding{}, Errors: res.Errors}
	if out.Errors == nil {
		out.Errors = []string{}
	}
	for _, f := range sorted(res.Findings) {
		r, _ := rules.ByID(f.Rule)
		out.Findings = append(out.Findings, jsonFinding{f.Rule, r.Name, f.Severity.String(), f.File, f.Line, f.Message, f.Fix})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	}
	return "note"
}

// SARIF writes SARIF 2.1.0, which GitHub code scanning accepts.
func SARIF(w io.Writer, res *scan.Result) error {
	type text struct {
		Text string `json:"text"`
	}
	type ruleDesc struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		ShortDescription text   `json:"shortDescription"`
		FullDescription  text   `json:"fullDescription"`
		Help             text   `json:"help"`
		Config           struct {
			Level string `json:"level"`
		} `json:"defaultConfiguration"`
	}
	var descs []ruleDesc
	for _, r := range append([]rules.Rule{rules.Meta}, rules.All...) {
		d := ruleDesc{ID: r.ID, Name: r.Name, ShortDescription: text{r.Title}, FullDescription: text{r.Why}, Help: text{r.Fix}}
		d.Config.Level = sarifLevel(r.Severity)
		descs = append(descs, d)
	}
	type result struct {
		RuleID    string `json:"ruleId"`
		Level     string `json:"level"`
		Message   text   `json:"message"`
		Locations []struct {
			Physical struct {
				Artifact struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}
	results := []result{}
	for _, f := range sorted(res.Findings) {
		r := result{RuleID: f.Rule, Level: sarifLevel(f.Severity), Message: text{f.Message}}
		r.Locations = make([]struct {
			Physical struct {
				Artifact struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region struct {
					StartLine int `json:"startLine"`
				} `json:"region"`
			} `json:"physicalLocation"`
		}, 1)
		r.Locations[0].Physical.Artifact.URI = f.File
		r.Locations[0].Physical.Region.StartLine = f.Line
		results = append(results, r)
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "actionwarden", "informationUri": "https://github.com/sriharifortitude/actionwarden", "rules": descs}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
