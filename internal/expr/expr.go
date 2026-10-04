// Package expr parses the expression language inside `${{ ... }}` in GitHub
// Actions workflows, far enough to answer one question: can the value of this
// expression contain text an outside party controls?
//
// A text search for "github.event.issue.title" gets that wrong in both
// directions. `contains(github.event.issue.title, 'bug')` yields a boolean and
// cannot inject anything; `format('{0}', github.event.issue.title)` and
// `toJSON(github.event.issue)` carry the title straight through. Telling them
// apart needs the expression's structure, so this is a real, small parser.
package expr

import (
	"fmt"
	"strings"
)

// Kind is the type of an expression node.
type Kind int

const (
	// Literal is a string, number, boolean or null written in the expression.
	Literal Kind = iota
	// Ref is a context reference such as github.event.issue.title.
	Ref
	// Call is a function call such as format('{0}', x).
	Call
	// Not is logical negation.
	Not
	// Binary is a comparison or a logical operator.
	Binary
	// Prop is a property read from something that is not a plain context
	// reference, for example fromJSON(x).name.
	Prop
)

// Node is one node of a parsed expression.
type Node struct {
	Kind Kind
	// Op is the operator of a Binary node or the lower-cased function name of
	// a Call node.
	Op string
	// Path is the lower-cased segments of a Ref. A segment is "*" for a
	// wildcard and "?" for an index that is computed at run time.
	Path []string
	// Args are a Call's arguments, a Binary's two operands, a Not's operand,
	// or a Prop's base.
	Args []*Node
}

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tNumber
	tString
	tOp
)

type token struct {
	kind tokKind
	text string
}

const maxDepth = 200

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) || c == '-' }

func lex(src string) ([]token, error) {
	var toks []token
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case isIdentStart(c):
			j := i + 1
			for j < len(src) && isIdentPart(src[j]) {
				j++
			}
			toks = append(toks, token{tIdent, src[i:j]})
			i = j
		case isDigit(c) || (c == '-' && i+1 < len(src) && isDigit(src[i+1]) && !endsOperand(toks)):
			j := i + 1
			for j < len(src) && isDigit(src[j]) {
				j++
			}
			if j+1 < len(src) && src[j] == '.' && isDigit(src[j+1]) {
				j++
				for j < len(src) && isDigit(src[j]) {
					j++
				}
			}
			if j < len(src) && (src[j] == 'e' || src[j] == 'E') {
				k := j + 1
				if k < len(src) && (src[k] == '+' || src[k] == '-') {
					k++
				}
				if k < len(src) && isDigit(src[k]) {
					for k < len(src) && isDigit(src[k]) {
						k++
					}
					j = k
				}
			}
			toks = append(toks, token{tNumber, src[i:j]})
			i = j
		case c == '\'':
			var b strings.Builder
			j := i + 1
			for {
				if j >= len(src) {
					return nil, fmt.Errorf("unterminated string starting at offset %d", i)
				}
				if src[j] == '\'' {
					if j+1 < len(src) && src[j+1] == '\'' {
						b.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(src[j])
				j++
			}
			toks = append(toks, token{tString, b.String()})
			i = j + 1
		default:
			if i+1 < len(src) {
				switch two := src[i : i+2]; two {
				case "==", "!=", "<=", ">=", "&&", "||":
					toks = append(toks, token{tOp, two})
					i += 2
					continue
				}
			}
			switch c {
			case '(', ')', '[', ']', ',', '.', '!', '<', '>', '*':
				toks = append(toks, token{tOp, string(c)})
				i++
			default:
				return nil, fmt.Errorf("unexpected character %q at offset %d", c, i)
			}
		}
	}
	return toks, nil
}

// endsOperand reports whether the previous token ends an operand, which makes
// a following '-' not the start of a negative number.
func endsOperand(toks []token) bool {
	if len(toks) == 0 {
		return false
	}
	last := toks[len(toks)-1]
	switch last.kind {
	case tIdent, tNumber, tString:
		return true
	}
	return last.text == ")" || last.text == "]"
}

type parser struct {
	toks  []token
	i     int
	depth int
}

func (p *parser) peek() token {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return token{kind: tEOF}
}

func (p *parser) next() token {
	t := p.peek()
	if p.i < len(p.toks) {
		p.i++
	}
	return t
}

func (p *parser) isOp(text string) bool {
	t := p.peek()
	return t.kind == tOp && t.text == text
}

func (p *parser) expectOp(text string) error {
	if !p.isOp(text) {
		return fmt.Errorf("expected %q, found %s", text, describe(p.peek()))
	}
	p.i++
	return nil
}

func describe(t token) string {
	if t.kind == tEOF {
		return "end of expression"
	}
	return fmt.Sprintf("%q", t.text)
}

// Parse parses the text between `${{` and `}}`.
func Parse(src string) (*Node, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("empty expression")
	}
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, fmt.Errorf("unexpected %s after the expression", describe(t))
	}
	return n, nil
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return fmt.Errorf("expression nested deeper than %d levels", maxDepth)
	}
	return nil
}

func (p *parser) parseOr() (*Node, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isOp("||") {
		p.i++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &Node{Kind: Binary, Op: "||", Args: []*Node{left, right}}
	}
	return left, nil
}

func (p *parser) parseAnd() (*Node, error) {
	left, err := p.parseCompare()
	if err != nil {
		return nil, err
	}
	for p.isOp("&&") {
		p.i++
		right, err := p.parseCompare()
		if err != nil {
			return nil, err
		}
		left = &Node{Kind: Binary, Op: "&&", Args: []*Node{left, right}}
	}
	return left, nil
}

func (p *parser) parseCompare() (*Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for _, op := range []string{"==", "!=", "<", ">", "<=", ">="} {
		for p.isOp(op) {
			p.i++
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = &Node{Kind: Binary, Op: op, Args: []*Node{left, right}}
		}
	}
	return left, nil
}

func (p *parser) parseUnary() (*Node, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	if p.isOp("!") {
		p.i++
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &Node{Kind: Not, Args: []*Node{x}}, nil
	}
	return p.parsePostfix()
}

func (p *parser) parsePostfix() (*Node, error) {
	n, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.isOp("."):
			p.i++
			t := p.next()
			var seg string
			switch {
			case t.kind == tIdent || t.kind == tNumber:
				seg = strings.ToLower(t.text)
			case t.kind == tOp && t.text == "*":
				seg = "*"
			default:
				return nil, fmt.Errorf("expected a property name after '.', found %s", describe(t))
			}
			n = extend(n, seg)
		case p.isOp("["):
			p.i++
			seg := "?"
			switch t := p.peek(); {
			case t.kind == tString:
				seg = strings.ToLower(t.text)
				p.i++
			case t.kind == tNumber:
				seg = t.text
				p.i++
			case t.kind == tOp && t.text == "*":
				seg = "*"
				p.i++
			default:
				if _, err := p.parseOr(); err != nil {
					return nil, err
				}
			}
			if err := p.expectOp("]"); err != nil {
				return nil, err
			}
			n = extend(n, seg)
		default:
			return n, nil
		}
	}
}

// extend adds a property to n: onto the path of a plain reference, as a Prop
// node for anything else.
func extend(n *Node, seg string) *Node {
	if n.Kind == Ref {
		path := make([]string, len(n.Path), len(n.Path)+1)
		copy(path, n.Path)
		return &Node{Kind: Ref, Path: append(path, seg)}
	}
	return &Node{Kind: Prop, Args: []*Node{n}}
}

func (p *parser) parsePrimary() (*Node, error) {
	t := p.next()
	switch t.kind {
	case tNumber, tString:
		return &Node{Kind: Literal}, nil
	case tIdent:
		lower := strings.ToLower(t.text)
		if p.isOp("(") {
			return p.parseCall(lower)
		}
		switch lower {
		case "true", "false", "null":
			return &Node{Kind: Literal}, nil
		}
		return &Node{Kind: Ref, Path: []string{lower}}, nil
	case tOp:
		if t.text == "(" {
			inner, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(")"); err != nil {
				return nil, err
			}
			return inner, nil
		}
	}
	return nil, fmt.Errorf("unexpected %s", describe(t))
}

func (p *parser) parseCall(name string) (*Node, error) {
	p.i++ // the '('
	call := &Node{Kind: Call, Op: name}
	if p.isOp(")") {
		p.i++
		return call, nil
	}
	for {
		arg, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		call.Args = append(call.Args, arg)
		if p.isOp(",") {
			p.i++
			continue
		}
		if err := p.expectOp(")"); err != nil {
			return nil, err
		}
		return call, nil
	}
}

// Refs returns the path of every context reference in the expression, whether
// or not its value reaches the result.
func Refs(n *Node) [][]string {
	var out [][]string
	var walk func(*Node)
	walk = func(n *Node) {
		if n.Kind == Ref {
			out = append(out, n.Path)
		}
		for _, a := range n.Args {
			walk(a)
		}
	}
	walk(n)
	return out
}
