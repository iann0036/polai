package polai

import (
	"fmt"
	"io"
	"strconv"
)

var OP_PRECEDENCE = map[Token]int{
	AND:        1,
	OR:         1,
	EQUALITY:   2,
	INEQUALITY: 2,
	LT:         2,
	LTE:        2,
	GT:         2,
	GTE:        2,
	IN:         2,
	PLUS:       3,
	DASH:       3,
	MULTIPLIER: 4,
}

var LEFT_ASSOCIATIVE = map[Token]bool{
	LT:   true,
	LTE:  true,
	GT:   true,
	GTE:  true,
	IN:   true,
	DASH: true,
}

// Evaluator represents an evaluator.
type Evaluator struct {
	p *Parser
}

// NewEvaluator returns a new instance of Evaluator.
func NewEvaluator(policyReader io.Reader) *Evaluator {
	return &Evaluator{p: NewParser(policyReader)}
}

func (e *Evaluator) Evaluate(principal, action, resource, context string) (bool, error) {
	policyStatements, err := e.p.Parse()
	if err != nil {
		return false, err
	}

	// evaluate forbids
ForbidLoop:
	for _, stmt := range *policyStatements {
		if stmt.Effect == FORBID {
			if !stmt.AnyPrincipal {
				// TODO: PrincipalParent
				if stmt.Principal != "" && stmt.Principal != principal {
					continue
				}
			}
			if !stmt.AnyAction {
				// TODO: ActionParent
				skip := true
				for _, stmtAction := range stmt.Actions {
					if action == stmtAction {
						skip = false
						break
					}
				}
				if skip {
					continue
				}
			}
			if !stmt.AnyResource {
				// TODO: ResourceParent
				if stmt.Resource != "" && stmt.Resource != resource {
					continue
				}
			}

			for _, stmtCondition := range stmt.Conditions {
				//stmtCondition.Type
				for len(stmtCondition.Sequence) > 1 {
					stmtCondition.ApplyOrderOfOperationsParenthesis()
					stmtCondition, err = e.reduce(stmtCondition, principal, action, resource, context)
					if err != nil {
						return false, err
					}
				}
				if stmtCondition.Type == WHEN {
					if stmtCondition.Sequence[0].Token == FALSE {
						continue ForbidLoop
					} else if stmtCondition.Sequence[0].Token != TRUE {
						return false, fmt.Errorf("reduced statement condition clause is not bool")
					}
				} else if stmtCondition.Type == UNLESS {
					if stmtCondition.Sequence[0].Token == TRUE {
						continue ForbidLoop
					} else if stmtCondition.Sequence[0].Token != FALSE {
						return false, fmt.Errorf("reduced statement condition clause is not bool")
					}
				} else {
					return false, fmt.Errorf("unreachable code 1")
				}
			}

			return false, nil
		}
	}

	// evaluate permits
PermitLoop:
	for _, stmt := range *policyStatements {
		if stmt.Effect == PERMIT {
			if !stmt.AnyPrincipal {
				// TODO: PrincipalParent
				if stmt.Principal != "" && stmt.Principal != principal {
					continue
				}
			}
			if !stmt.AnyAction {
				// TODO: ActionParent
				skip := true
				for _, stmtAction := range stmt.Actions {
					if action == stmtAction {
						skip = false
						break
					}
				}
				if skip {
					continue
				}
			}
			if !stmt.AnyResource {
				// TODO: ResourceParent
				if stmt.Resource != "" && stmt.Resource != resource {
					continue
				}
			}

			for _, stmtCondition := range stmt.Conditions {
				for len(stmtCondition.Sequence) > 1 {
					stmtCondition.ApplyOrderOfOperationsParenthesis()
					stmtCondition, err = e.reduce(stmtCondition, principal, action, resource, context)
					if err != nil {
						return false, err
					}
				}
				if stmtCondition.Type == WHEN {
					if stmtCondition.Sequence[0].Token == FALSE {
						continue PermitLoop
					} else if stmtCondition.Sequence[0].Token != TRUE {
						return false, fmt.Errorf("reduced statement condition clause is not bool")
					}
				} else if stmtCondition.Type == UNLESS {
					if stmtCondition.Sequence[0].Token == TRUE {
						continue PermitLoop
					} else if stmtCondition.Sequence[0].Token != FALSE {
						return false, fmt.Errorf("reduced statement condition clause is not bool")
					}
				} else {
					return false, fmt.Errorf("unreachable code")
				}
			}

			return true, nil // explicit allow
		}
	}

	return false, nil // implicit deny
}

func (e *Evaluator) opp(cc ConditionClause, principal, action, resource, context string) (bool, error) {
	var outputQueue []SequenceItem
	var operatorStack []SequenceItem

	for _, s := range cc.Sequence {
		switch s.Token {
		case TRUE, FALSE, INT, DBLQUOTESTR:
			outputQueue = append(outputQueue, s)
		case LEFT_PAREN:
			operatorStack = append(operatorStack, s)
		case RIGHT_PAREN:
			for {
				if len(operatorStack) < 1 {
					return false, fmt.Errorf("mismatched parenthesis")
				}
				pop := operatorStack[len(operatorStack)-1]
				operatorStack = operatorStack[:len(operatorStack)-1]

				if pop.Token != LEFT_PAREN {
					outputQueue = append(outputQueue, pop)
				} else {
					break
				}
			}
		case EQUALITY, INEQUALITY, AND, OR, LT, LTE, GT, GTE, PLUS, DASH, MULTIPLIER, IN:
			for OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] != 0 && (OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] > OP_PRECEDENCE[s.Token] || (OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] == OP_PRECEDENCE[s.Token] && LEFT_ASSOCIATIVE[s.Token])) {
				pop := operatorStack[len(operatorStack)-1]
				operatorStack = operatorStack[:len(operatorStack)-1]
				outputQueue = append(outputQueue, pop)
			}
			operatorStack = append(operatorStack, s)
		default:
			return false, fmt.Errorf("unknown token: %q", s.Token)
		}
	}
	for len(operatorStack) > 0 {
		pop := operatorStack[len(operatorStack)-1]
		operatorStack = operatorStack[:len(operatorStack)-1]
		if pop.Token == LEFT_PAREN {
			return false, fmt.Errorf("mismatched parenthesis")
		}
		outputQueue = append(outputQueue, pop)
	}

	// TODO

	return false, nil
}

func (e *Evaluator) reduce(cc ConditionClause, principal, action, resource, context string) (ConditionClause, error) {
	cc, err := e.reduceParen(cc, principal, action, resource, context)
	if err != nil {
		return cc, err
	}

	if !(len(cc.Sequence) > 1) {
		return cc, nil
	}

	seqLhs, err := cc.Shift()
	if err != nil {
		return cc, err
	}

	// TODO: other types
	if seqLhs.Token == TRUE || seqLhs.Token == FALSE {
		seqOper, err := cc.Shift()
		if err != nil {
			return cc, err
		}
		if seqOper.Token == EQUALITY || seqOper.Token == INEQUALITY {
			cc, err = e.reduceParen(cc, principal, action, resource, context)
			if err != nil {
				return cc, err
			}

			seqRhs, err := cc.Shift()
			if err != nil {
				return cc, err
			}

			if seqRhs.Token == TRUE || seqRhs.Token == FALSE {
				if seqOper.Token == EQUALITY {
					if seqLhs.Token == seqRhs.Token {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				} else if seqOper.Token == INEQUALITY {
					if seqLhs.Token != seqRhs.Token {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				} else {
					return cc, fmt.Errorf("unreachable code")
				}
			} else {
				if seqOper.Token == EQUALITY { // equality of two different types is always false
					cc.Unshift(SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				} else if seqOper.Token == INEQUALITY { // inequality of two different types is always true
					cc.Unshift(SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				} else {
					return cc, fmt.Errorf("unreachable code")
				}
			}
		} else if seqOper.Token == AND || seqOper.Token == OR {
			cc, err = e.reduceParen(cc, principal, action, resource, context)
			if err != nil {
				return cc, err
			}

			seqRhs, err := cc.Shift()
			if err != nil {
				return cc, err
			}

			if seqRhs.Token == TRUE || seqRhs.Token == FALSE {
				if seqOper.Token == AND {
					if seqLhs.Token == TRUE && seqRhs.Token == TRUE {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				} else if seqOper.Token == OR {
					if seqLhs.Token == TRUE || seqRhs.Token == TRUE {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				} else {
					return cc, fmt.Errorf("unreachable code")
				}
			} else {
				return cc, fmt.Errorf("cannot combine boolean and token: %q", seqRhs.Literal)
			}
		} else {
			return cc, fmt.Errorf("cannot process oper token type: %q", seqOper.Literal)
		}
	} else if seqLhs.Token == INT {
		seqOper, err := cc.Shift()
		if err != nil {
			return cc, err
		}
		if seqOper.Token == EQUALITY || seqOper.Token == INEQUALITY || seqOper.Token == LT || seqOper.Token == LTE || seqOper.Token == GT || seqOper.Token == GTE || seqOper.Token == PLUS || seqOper.Token == DASH || seqOper.Token == MULTIPLIER {
			cc, err = e.reduceParen(cc, principal, action, resource, context)
			if err != nil {
				return cc, err
			}

			seqRhs, err := cc.Shift()
			if err != nil {
				return cc, err
			}

			if seqRhs.Token == INT {
				lhsL, err := strconv.ParseInt(seqLhs.Literal, 10, 64)
				if err != nil {
					return cc, err
				}
				rhsL, err := strconv.ParseInt(seqRhs.Literal, 10, 64)
				if err != nil {
					return cc, err
				}

				switch seqOper.Token {
				case EQUALITY:
					if lhsL == rhsL {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				case INEQUALITY:
					if lhsL != rhsL {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				case LT:
					if lhsL < rhsL {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				case LTE:
					if lhsL <= rhsL {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				case GT:
					if lhsL > rhsL {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				case GTE:
					if lhsL >= rhsL {
						cc.Unshift(SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						cc.Unshift(SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				case PLUS:
					cc.Unshift(SequenceItem{
						Token:   INT,
						Literal: strconv.FormatInt(lhsL+rhsL, 10),
					})
				case DASH:
					cc.Unshift(SequenceItem{
						Token:   INT,
						Literal: strconv.FormatInt(lhsL-rhsL, 10),
					})
				case MULTIPLIER:
					cc.Unshift(SequenceItem{
						Token:   INT,
						Literal: strconv.FormatInt(lhsL*rhsL, 10),
					})
				default:
					return cc, fmt.Errorf("unreachable code")
				}
			} else {
				if seqOper.Token == EQUALITY { // equality of two different types is always false
					cc.Unshift(SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				} else if seqOper.Token == INEQUALITY { // inequality of two different types is always true
					cc.Unshift(SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				} else {
					return cc, fmt.Errorf("cannot perform operation on two different data types")
				}
			}
		} else {
			return cc, fmt.Errorf("cannot process oper token type: %q", seqOper.Literal)
		}
	} else {
		return cc, fmt.Errorf("cannot process lhs token type: %q", seqLhs.Token)
	}

	return cc, nil
}

func (e *Evaluator) reduceParen(cc ConditionClause, principal, action, resource, context string) (ConditionClause, error) {
	if len(cc.Sequence) < 1 {
		return cc, nil
	} else if cc.Sequence[0].Token != LEFT_PAREN {
		return cc, nil
	}

	i := 0
	parenLevel := 1
	for {
		i++
		if i >= len(cc.Sequence) {
			return cc, fmt.Errorf("found left parenthesis without matching right parenthesis")
		}
		if cc.Sequence[i].Token == LEFT_PAREN {
			parenLevel++
		}
		if cc.Sequence[i].Token == RIGHT_PAREN {
			parenLevel--
			if parenLevel == 0 {
				break
			}
		}
	}

	var err error

	subcc := ConditionClause{
		Sequence: cc.Sequence[1:i],
	}
	for len(subcc.Sequence) > 1 {
		subcc, err = e.reduce(subcc, principal, action, resource, context)
		if err != nil {
			return cc, err
		}
	}

	cc.Sequence = append(subcc.Sequence, cc.Sequence[i+1:]...)

	return cc, nil
}
