// Package workflow reads a GitHub Actions workflow file into the parts the
// rules look at, keeping the line each part came from so that a finding can
// point at it.
package workflow

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scalar is a string value from the file with its position.
type Scalar struct {
	Value string
	Line  int
	// Literal is true for a `|` block, where the lines of Value are the lines
	// of the file and an offset in Value can be turned into a line number.
	Literal bool
}

// LineAt returns the file line of the character at offset in Value.
func (s *Scalar) LineAt(offset int) int {
	if !s.Literal {
		return s.Line
	}
	if offset > len(s.Value) {
		offset = len(s.Value)
	}
	return s.Line + 1 + strings.Count(s.Value[:offset], "\n")
}

// Permissions is a `permissions:` block at workflow or job level.
type Permissions struct {
	Line int
	// All is "read-all" or "write-all" when the block is that shorthand.
	All string
	// Scopes maps a scope such as "contents" to its level, lower-cased.
	Scopes map[string]string
}

// Step is one entry of a job's steps.
type Step struct {
	Line      int
	Name      string
	Uses      *Scalar
	Run       *Scalar
	If        *Scalar
	With      map[string]*Scalar
	WithOrder []string
	Env       map[string]*Scalar
}

// Job is one entry of the workflow's jobs.
type Job struct {
	ID          string
	Line        int
	Permissions *Permissions
	// RunsOn holds every runner label named, whether given as a string, a
	// list, or the labels of a runner group.
	RunsOn []Scalar
	// Uses is set when the job calls a reusable workflow.
	Uses *Scalar
	// SecretsInherit is the `secrets: inherit` value, if given.
	SecretsInherit *Scalar
	If             *Scalar
	Env            map[string]*Scalar
	Steps          []*Step
}

// Workflow is a parsed workflow file.
type Workflow struct {
	Path        string
	Name        string
	Triggers    map[string]bool
	Permissions *Permissions
	Env         map[string]*Scalar
	Jobs        []*Job
}

// resolve follows an alias to the node it stands for.
func resolve(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 32; i++ {
		n = n.Alias
	}
	return n
}

// get returns the key and value nodes for key in a mapping.
func get(m *yaml.Node, key string) (k, v *yaml.Node) {
	m = resolve(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], resolve(m.Content[i+1])
		}
	}
	return nil, nil
}

func scalar(n *yaml.Node) *Scalar {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return nil
	}
	return &Scalar{Value: n.Value, Line: n.Line, Literal: n.Style&yaml.LiteralStyle != 0}
}

func scalarMap(n *yaml.Node) map[string]*Scalar {
	n = resolve(n)
	out := map[string]*Scalar{}
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if s := scalar(n.Content[i+1]); s != nil {
			out[n.Content[i].Value] = s
		}
	}
	return out
}

func parsePermissions(key, v *yaml.Node) *Permissions {
	if key == nil || v == nil {
		return nil
	}
	p := &Permissions{Line: key.Line, Scopes: map[string]string{}}
	switch v.Kind {
	case yaml.ScalarNode:
		p.All = strings.ToLower(strings.TrimSpace(v.Value))
	case yaml.MappingNode:
		for scope, level := range scalarMap(v) {
			p.Scopes[strings.ToLower(scope)] = strings.ToLower(strings.TrimSpace(level.Value))
		}
	}
	return p
}

func parseTriggers(v *yaml.Node) map[string]bool {
	out := map[string]bool{}
	switch {
	case v == nil:
	case v.Kind == yaml.ScalarNode:
		out[strings.ToLower(v.Value)] = true
	case v.Kind == yaml.SequenceNode:
		for _, n := range v.Content {
			if n = resolve(n); n != nil && n.Kind == yaml.ScalarNode {
				out[strings.ToLower(n.Value)] = true
			}
		}
	case v.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(v.Content); i += 2 {
			out[strings.ToLower(v.Content[i].Value)] = true
		}
	}
	return out
}

func parseRunsOn(v *yaml.Node) []Scalar {
	var out []Scalar
	add := func(n *yaml.Node) {
		if s := scalar(n); s != nil {
			out = append(out, *s)
		}
	}
	switch {
	case v == nil:
	case v.Kind == yaml.ScalarNode:
		add(v)
	case v.Kind == yaml.SequenceNode:
		for _, n := range v.Content {
			add(n)
		}
	case v.Kind == yaml.MappingNode:
		if _, labels := get(v, "labels"); labels != nil {
			out = append(out, parseRunsOn(labels)...)
		}
	}
	return out
}

func parseStep(n *yaml.Node, index int) *Step {
	n = resolve(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	s := &Step{Line: n.Line, With: map[string]*Scalar{}}
	if _, v := get(n, "name"); v != nil && v.Kind == yaml.ScalarNode {
		s.Name = v.Value
	}
	_, uses := get(n, "uses")
	s.Uses = scalar(uses)
	if s.Name == "" {
		if s.Uses != nil {
			s.Name = s.Uses.Value
		} else {
			s.Name = fmt.Sprintf("step %d", index+1)
		}
	}
	_, run := get(n, "run")
	s.Run = scalar(run)
	_, cond := get(n, "if")
	s.If = scalar(cond)
	_, env := get(n, "env")
	s.Env = scalarMap(env)
	if _, with := get(n, "with"); with != nil && with.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(with.Content); i += 2 {
			key := with.Content[i].Value
			if v := scalar(with.Content[i+1]); v != nil {
				s.With[key] = v
				s.WithOrder = append(s.WithOrder, key)
			}
		}
	}
	return s
}

func parseJob(id *yaml.Node, n *yaml.Node) *Job {
	n = resolve(n)
	j := &Job{ID: id.Value, Line: id.Line}
	if n == nil || n.Kind != yaml.MappingNode {
		return j
	}
	pk, pv := get(n, "permissions")
	j.Permissions = parsePermissions(pk, pv)
	_, runsOn := get(n, "runs-on")
	j.RunsOn = parseRunsOn(runsOn)
	_, uses := get(n, "uses")
	j.Uses = scalar(uses)
	_, secrets := get(n, "secrets")
	j.SecretsInherit = scalar(secrets)
	_, cond := get(n, "if")
	j.If = scalar(cond)
	_, env := get(n, "env")
	j.Env = scalarMap(env)
	if _, steps := get(n, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
		for i, sn := range steps.Content {
			if s := parseStep(sn, i); s != nil {
				j.Steps = append(j.Steps, s)
			}
		}
	}
	return j
}

// Parse reads a workflow. path is only used to label findings.
func Parse(path string, src []byte) (*Workflow, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("the file is empty")
	}
	root := resolve(doc.Content[0])
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: the top level is not a mapping, so this is not a workflow", root.Line)
	}
	_, jobs := get(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("no jobs: mapping, so this is not a workflow")
	}

	w := &Workflow{Path: path}
	if _, v := get(root, "name"); v != nil && v.Kind == yaml.ScalarNode {
		w.Name = v.Value
	}
	_, on := get(root, "on")
	w.Triggers = parseTriggers(on)
	pk, pv := get(root, "permissions")
	w.Permissions = parsePermissions(pk, pv)
	_, env := get(root, "env")
	w.Env = scalarMap(env)
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		w.Jobs = append(w.Jobs, parseJob(jobs.Content[i], jobs.Content[i+1]))
	}
	return w, nil
}
