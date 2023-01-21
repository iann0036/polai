package polai

import (
	"fmt"
	"io"
	"strconv"
)

// PolicyStatement represents a set of Cedar policy statements
type PolicyStatement struct {
	Effect          Token
	AnyPrincipal    bool
	Principal       string
	PrincipalParent string
	AnyAction       bool
	Action          string
	ActionParents   []string
	AnyResource     bool
	Resource        string
	ResourceParent  string
	Conditions      []ConditionClause
}

type ConditionClause struct {
	Type     Token
	Sequence []SequenceItem
}

func (cc *ConditionClause) ToString() string {
	ret := fmt.Sprintf("%q", cc.Type)

	for _, seqItem := range cc.Sequence {
		ret += seqItem.Literal
	}

	return ret
}

type SequenceItem struct {
	Token      Token
	Literal    string
	Normalized string
}

// Parser represents a parser.
type Parser struct {
	s   *Scanner
	buf struct {
		tok Token  // last read token
		lit string // last read literal
		n   int    // buffer size (max=1)
	}
}

// NewParser returns a new instance of Parser.
func NewParser(r io.Reader) *Parser {
	return &Parser{s: NewScanner(r)}
}

// Parse parses a policy.
func (p *Parser) Parse() (*[]PolicyStatement, error) {
	stmts := []PolicyStatement{}

	tok, lit := p.scanIgnoreWhitespace()
	if tok == EOF {
		return nil, fmt.Errorf("no policy statements found")
	}

	for tok != EOF {
		stmt := PolicyStatement{
			AnyPrincipal: true,
			AnyAction:    true,
			AnyResource:  true,
		}

		// Head

		switch tok {
		case PERMIT, FORBID:
			stmt.Effect = tok
		default:
			return nil, fmt.Errorf("found %q, expected permit or forbid", lit)
		}

		if tok, lit = p.scanIgnoreWhitespace(); tok != LEFT_PAREN {
			return nil, fmt.Errorf("found %q, expected left parentheses", lit)
		}

		if tok, lit = p.scanIgnoreWhitespace(); tok != PRINCIPAL {
			return nil, fmt.Errorf("found %q, expected principal", lit)
		}

		tok, lit = p.scanIgnoreWhitespace()
		switch tok {
		case COMMA:
		case EQUALITY:
			stmt.AnyPrincipal = false

			entityName, err := p.scanEntity()
			if err != nil {
				return nil, err
			}
			stmt.Principal = entityName

			if tok, lit = p.scanIgnoreWhitespace(); tok != COMMA {
				return nil, fmt.Errorf("found %q, expected comma", lit)
			}
		case IN:
			stmt.AnyPrincipal = false

			entityName, err := p.scanEntity()
			if err != nil {
				return nil, err
			}
			stmt.PrincipalParent = entityName

			if tok, lit = p.scanIgnoreWhitespace(); tok != COMMA {
				return nil, fmt.Errorf("found %q, expected comma", lit)
			}
		default:
			return nil, fmt.Errorf("found %q, expected comma, equality operator, or in", lit)
		}

		if tok, lit = p.scanIgnoreWhitespace(); tok != ACTION {
			return nil, fmt.Errorf("found %q, expected action", lit)
		}

		tok, lit = p.scanIgnoreWhitespace()
		switch tok {
		case COMMA:
		case EQUALITY:
			stmt.AnyAction = false

			entityName, err := p.scanEntity()
			if err != nil {
				return nil, err
			}
			stmt.Action = entityName

			if tok, lit = p.scanIgnoreWhitespace(); tok != COMMA {
				return nil, fmt.Errorf("found %q, expected comma", lit)
			}
		case IN:
			stmt.AnyAction = false

			tok, lit = p.scanIgnoreWhitespace()

			if tok == IDENT {
				p.unscan()
				entityName, err := p.scanEntity()
				if err != nil {
					return nil, err
				}
				stmt.ActionParents = []string{entityName}
			} else if tok == LEFT_SQB {
				tok = COMMA

				for tok != RIGHT_SQB {
					if tok != COMMA {
						return nil, fmt.Errorf("found %q, expected comma or right square bracket", lit)
					}

					entityName, err := p.scanEntity()
					if err != nil {
						return nil, err
					}
					stmt.ActionParents = append(stmt.ActionParents, entityName)

					tok, lit = p.scanIgnoreWhitespace()
				}
			} else {
				return nil, fmt.Errorf("found %q, expected entity or left square bracket", lit)
			}

			if tok, lit = p.scanIgnoreWhitespace(); tok != COMMA {
				return nil, fmt.Errorf("found %q, expected comma", lit)
			}
		default:
			return nil, fmt.Errorf("found %q, expected comma, equality operator, or in", lit)
		}

		if tok, lit = p.scanIgnoreWhitespace(); tok != RESOURCE {
			return nil, fmt.Errorf("found %q, expected resource", lit)
		}

		tok, lit = p.scanIgnoreWhitespace()
		switch tok {
		case RIGHT_PAREN:
		case EQUALITY:
			stmt.AnyResource = false

			entityName, err := p.scanEntity()
			if err != nil {
				return nil, err
			}
			stmt.Resource = entityName

			if tok, lit = p.scanIgnoreWhitespace(); tok != RIGHT_PAREN {
				return nil, fmt.Errorf("found %q, expected right parentheses", lit)
			}
		case IN:
			stmt.AnyResource = false

			entityName, err := p.scanEntity()
			if err != nil {
				return nil, err
			}
			stmt.ResourceParent = entityName

			if tok, lit = p.scanIgnoreWhitespace(); tok != RIGHT_PAREN {
				return nil, fmt.Errorf("found %q, expected right parentheses", lit)
			}
		default:
			return nil, fmt.Errorf("found %q, expected right parentheses, equality operator, or in", lit)
		}

		// Condition Clauses

		tok, lit = p.scanIgnoreWhitespace()

		for tok == WHEN || tok == UNLESS {
			condClause, err := p.scanConditionClause(tok)
			if err != nil {
				return nil, err
			}

			stmt.Conditions = append(stmt.Conditions, *condClause)

			tok, lit = p.scanIgnoreWhitespace()
		}

		if tok != SEMICOLON {
			return nil, fmt.Errorf("found %q, expected semicolon", lit)
		}

		stmts = append(stmts, stmt)

		tok, lit = p.scanIgnoreWhitespace()
	}

	return &stmts, nil
}

// scan returns the next token from the underlying scanner.
// If a token has been unscanned then read that instead.
func (p *Parser) scan() (tok Token, lit string) {
	// If we have a token on the buffer, then return it.
	if p.buf.n != 0 {
		p.buf.n = 0
		return p.buf.tok, p.buf.lit
	}

	// Otherwise read the next token from the scanner.
	tok, lit = p.s.Scan()

	// Save it to the buffer in case we unscan later.
	p.buf.tok, p.buf.lit = tok, lit

	return
}

// scanIgnoreWhitespace scans the next non-whitespace token.
func (p *Parser) scanIgnoreWhitespace() (tok Token, lit string) {
	tok, lit = p.scan()
	for tok == WHITESPC || tok == COMMENT {
		tok, lit = p.scan()
	}
	return
}

// scanConditionClause scans a condition clause
func (p *Parser) scanConditionClause(condType Token) (condClause *ConditionClause, err error) {
	condClause = &ConditionClause{
		Type: condType,
	}

	if tok, lit := p.scanIgnoreWhitespace(); tok != LEFT_BRACE {
		return nil, fmt.Errorf("found %q, expected left brace", lit)
	}

	braceLevel := 0

	tok, lit := p.scanIgnoreWhitespace()
	for tok != RIGHT_BRACE || braceLevel > 0 {
		switch tok {
		case LEFT_BRACE:
			condClause.Sequence = append(condClause.Sequence, SequenceItem{
				Token:      tok,
				Literal:    lit,
				Normalized: lit,
			})
			braceLevel++
		case RIGHT_BRACE:
			condClause.Sequence = append(condClause.Sequence, SequenceItem{
				Token:      tok,
				Literal:    lit,
				Normalized: lit,
			})
			braceLevel--
		case IDENT:
			p.unscan()
			item, err := p.scanEntityOrFunction()
			if err != nil {
				return nil, err
			}
			condClause.Sequence = append(condClause.Sequence, item)
		case PERIOD:
			condClause.Sequence = append(condClause.Sequence, SequenceItem{
				Token:      tok,
				Literal:    lit,
				Normalized: lit,
			})
			tok, lit := p.scan()
			if tok != IDENT {
				return nil, fmt.Errorf("found %q, expected attribute or function", lit)
			}
			tok, _ = p.scan()
			if tok != LEFT_PAREN {
				p.unscan()
				condClause.Sequence = append(condClause.Sequence, SequenceItem{
					Token:      ATTRIBUTE,
					Literal:    lit,
					Normalized: lit,
				})
			} else {
				p.unscan()
				condClause.Sequence = append(condClause.Sequence, SequenceItem{
					Token:      FUNCTION,
					Literal:    lit,
					Normalized: lit,
				})
			}
		// TODO: INT to LONG
		case INT:
			i, err := strconv.ParseInt(lit, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("error parsing long")
			}
			condClause.Sequence = append(condClause.Sequence, SequenceItem{
				Token:      tok,
				Literal:    lit,
				Normalized: strconv.FormatInt(i, 10),
			})
		// TODO: align possible token sequences to spec
		case TRUE, FALSE, DBLQUOTESTR, PRINCIPAL, ACTION, RESOURCE, CONTEXT, LEFT_SQB, LEFT_PAREN, RIGHT_SQB, RIGHT_PAREN, COMMA, HAS, LIKE, EQUALITY, INEQUALITY, LT, LTE, GT, GTE, IN, EXCLAMATION, DASH, PLUS, MULTIPLIER, AND, OR, IF, THEN, ELSE:
			condClause.Sequence = append(condClause.Sequence, SequenceItem{
				Token:      tok,
				Literal:    lit,
				Normalized: lit,
			})
		default:
			return nil, fmt.Errorf("unexpected token found in condition clause %q (%q, %v)", lit, tok, tok)
		}

		tok, lit = p.scanIgnoreWhitespace()
	}

	return condClause, nil
}

// scanEntity scans an entity type
func (p *Parser) scanEntity() (entityName string, err error) { // TODO: deprecate?
	tok, lit := p.scanIgnoreWhitespace()
	entityName = lit

	if tok != IDENT {
		return entityName, fmt.Errorf("found %q, expected entity namespace", lit)
	}
	if tok, lit = p.scan(); tok != NAMESPACE {
		return entityName, fmt.Errorf("found %q, expected namespace separator", lit)
	}
	entityName += "::"

	for {
		tok, lit = p.scan()
		if tok == IDENT {
			entityName += lit
			if tok, lit = p.scan(); tok != NAMESPACE {
				return entityName, fmt.Errorf("found %q, expected subnamespace separator", lit)
			}
			entityName += "::"
		} else if tok == DBLQUOTESTR {
			entityName += lit
			break
		} else {
			return entityName, fmt.Errorf("found %q, expected double quoted string or entity namespace", lit)
		}
	}

	return entityName, nil
}

// scanEntityOrFunction scans an entity or function type
func (p *Parser) scanEntityOrFunction() (item SequenceItem, err error) {
	tok, lit := p.scanIgnoreWhitespace()
	name := lit

	if tok != IDENT {
		return SequenceItem{}, fmt.Errorf("found %q, expected entity namespace", lit)
	}
	tok, lit = p.scan()
	if tok == LEFT_PAREN {
		p.unscan()
		return SequenceItem{
			Token:      FUNCTION,
			Literal:    name,
			Normalized: name,
		}, nil
	}
	if tok != NAMESPACE {
		return SequenceItem{}, fmt.Errorf("found %q, expected namespace separator", lit)
	}
	name += "::"

	for {
		tok, lit = p.scan()
		if tok == IDENT {
			name += lit
			if tok, lit = p.scan(); tok != NAMESPACE {
				return SequenceItem{}, fmt.Errorf("found %q, expected subnamespace separator", lit)
			}
			name += "::"
		} else if tok == DBLQUOTESTR {
			name += lit
			break
		} else {
			return SequenceItem{}, fmt.Errorf("found %q, expected double quoted string or entity namespace", lit)
		}
	}

	return SequenceItem{
		Token:      ENTITY,
		Literal:    name,
		Normalized: name,
	}, nil
}

// unscan pushes the previously read token back onto the buffer.
func (p *Parser) unscan() { p.buf.n = 1 }
