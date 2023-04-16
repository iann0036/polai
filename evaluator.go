package polai

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"

	match "github.com/iann0036/match-wildcard"
)

var OP_PRECEDENCE = map[Token]int{
	AND:         2,
	OR:          2,
	EQUALITY:    3,
	INEQUALITY:  3,
	LT:          3,
	LTE:         3,
	GT:          3,
	GTE:         3,
	IN:          3,
	LIKE:        3,
	PLUS:        4,
	DASH:        4,
	MULTIPLIER:  5,
	EXCLAMATION: 5,
	PERIOD:      6,
	FUNCTION:    7,
	RIGHT_SQB:   7,
}

var LEFT_ASSOCIATIVE = map[Token]bool{
	OR:          true, // to allow for custom short-circuiting logic
	LT:          true,
	LTE:         true,
	GT:          true,
	GTE:         true,
	IN:          true,
	LIKE:        true,
	DASH:        true,
	EXCLAMATION: true,
	PERIOD:      true,
	FUNCTION:    true,
}

// Evaluator represents an evaluator.
type Evaluator struct {
	p                    *Parser
	es                   *EntityStore
	AllowShortCircuiting bool
}

// NewEvaluator returns a new instance of Evaluator.
func NewEvaluator(policyReader io.Reader) *Evaluator {
	return &Evaluator{
		p:                    NewParser(policyReader),
		AllowShortCircuiting: true,
	}
}

func (e *Evaluator) SetEntities(entityReader io.Reader) {
	if e.es == nil {
		e.es = NewEntityStore(entityReader)
	} else {
		e.es.SetEntities(entityReader)
	}
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
				if stmt.Principal != "" {
					if stmt.Principal != principal {
						continue
					}
				} else if stmt.PrincipalParent != "" {
					if stmt.PrincipalParent != principal {
						if e.es == nil {
							continue
						} else {
							descendants, err := e.es.GetEntityDescendents([]string{stmt.PrincipalParent})
							if err != nil {
								return false, err
							}
							if !containsEntity(descendants, principal) {
								continue
							}
						}
					}
				} else {
					return false, fmt.Errorf("unknown policy state")
				}
			}
			if !stmt.AnyAction {
				if stmt.Action != "" {
					if !strings.Contains(stmt.Action, "::Action::\"") && !strings.HasPrefix(stmt.Action, "Action::\"") {
						return false, fmt.Errorf("actions in scope must use Action:: namespace")
					}
					if stmt.Action != action {
						continue
					}
				} else { // assumed ActionParent populated
					if !contains(stmt.ActionParents, action) {
						if e.es == nil {
							continue
						} else {
							descendants, err := e.es.GetEntityDescendents(stmt.ActionParents)
							if err != nil {
								return false, err
							}
							for _, v := range descendants {
								if !strings.Contains(v.Identifier, "::Action::\"") && !strings.HasPrefix(v.Identifier, "Action::\"") {
									return false, fmt.Errorf("actions in scope must use Action:: namespace")
								}
							}
							if !containsEntity(descendants, action) {
								continue
							}
						}
					}
				}
			}
			if !stmt.AnyResource {
				if stmt.Resource != "" {
					if stmt.Resource != resource {
						continue
					}
				} else if stmt.ResourceParent != "" {
					if stmt.ResourceParent != resource {
						if e.es == nil {
							continue
						} else {
							descendants, err := e.es.GetEntityDescendents([]string{stmt.ResourceParent})
							if err != nil {
								return false, err
							}
							if !containsEntity(descendants, resource) {
								continue
							}
						}
					}
				} else {
					return false, fmt.Errorf("unknown policy state")
				}
			}

			for _, stmtCondition := range stmt.Conditions {
				condEvalResult, err := e.condEval(stmtCondition, principal, action, resource, context)
				if err != nil {
					return false, err
				}

				if condEvalResult.Token != TRUE && condEvalResult.Token != FALSE {
					return false, fmt.Errorf("condition return is not boolean")
				}

				if stmtCondition.Type == WHEN && condEvalResult.Token == FALSE {
					continue ForbidLoop
				} else if stmtCondition.Type == UNLESS && condEvalResult.Token == TRUE {
					continue ForbidLoop
				}
			}

			return false, nil // explicit forbid
		}
	}

	// evaluate permits
PermitLoop:
	for _, stmt := range *policyStatements {
		if stmt.Effect == PERMIT {
			if !stmt.AnyPrincipal {
				if stmt.Principal != "" {
					if stmt.Principal != principal {
						continue
					}
				} else if stmt.PrincipalParent != "" {
					if stmt.PrincipalParent != principal {
						if e.es == nil {
							continue
						} else {
							descendants, err := e.es.GetEntityDescendents([]string{stmt.PrincipalParent})
							if err != nil {
								return false, err
							}
							if !containsEntity(descendants, principal) {
								continue
							}
						}
					}
				} else {
					return false, fmt.Errorf("unknown policy state")
				}
			}
			if !stmt.AnyAction {
				if stmt.Action != "" {
					if !strings.Contains(stmt.Action, "::Action::\"") && !strings.HasPrefix(stmt.Action, "Action::\"") {
						return false, fmt.Errorf("actions in scope must use Action:: namespace")
					}
					if stmt.Action != action {
						continue
					}
				} else { // assumed ActionParent populated
					if !contains(stmt.ActionParents, action) {
						if e.es == nil {
							continue
						} else {
							descendants, err := e.es.GetEntityDescendents(stmt.ActionParents)
							if err != nil {
								return false, err
							}
							for _, v := range descendants {
								if !strings.Contains(v.Identifier, "::Action::\"") && !strings.HasPrefix(v.Identifier, "Action::\"") {
									return false, fmt.Errorf("actions in scope must use Action:: namespace")
								}
							}
							if !containsEntity(descendants, action) {
								continue
							}
						}
					}
				}
			}
			if !stmt.AnyResource {
				if stmt.Resource != "" {
					if stmt.Resource != resource {
						continue
					}
				} else if stmt.ResourceParent != "" {
					if stmt.ResourceParent != resource {
						if e.es == nil {
							continue
						} else {
							descendants, err := e.es.GetEntityDescendents([]string{stmt.ResourceParent})
							if err != nil {
								return false, err
							}
							if !containsEntity(descendants, resource) {
								continue
							}
						}
					}
				} else {
					return false, fmt.Errorf("unknown policy state")
				}
			}

			for _, stmtCondition := range stmt.Conditions {
				condEvalResult, err := e.condEval(stmtCondition, principal, action, resource, context)
				if err != nil {
					return false, err
				}

				if condEvalResult.Token != TRUE && condEvalResult.Token != FALSE {
					return false, fmt.Errorf("condition return is not boolean")
				}

				if stmtCondition.Type == WHEN && condEvalResult.Token == FALSE {
					continue PermitLoop
				} else if stmtCondition.Type == UNLESS && condEvalResult.Token == TRUE {
					continue PermitLoop
				}
			}

			return true, nil // explicit allow
		}
	}

	return false, nil // implicit deny
}

func (e *Evaluator) wrapIfThenElse(sequenceItemList []SequenceItem) []SequenceItem {
	i := 0
	for i < len(sequenceItemList) {
		if sequenceItemList[i].Token == IF {
			// splice ( after
			sequenceItemList = append(sequenceItemList[:i+2], sequenceItemList[i+1:]...)
			sequenceItemList[i+1] = SequenceItem{Token: LEFT_PAREN, Literal: "(", Normalized: "("}
			i++
		} else if sequenceItemList[i].Token == THEN {
			// splice ) before
			sequenceItemList = append(sequenceItemList[:i+1], sequenceItemList[i:]...)
			sequenceItemList[i] = SequenceItem{Token: RIGHT_PAREN, Literal: ")", Normalized: ")"}
			// splice ( after
			sequenceItemList = append(sequenceItemList[:i+3], sequenceItemList[i+2:]...)
			sequenceItemList[i+2] = SequenceItem{Token: LEFT_PAREN, Literal: "(", Normalized: "("}
			i += 2
		} else if sequenceItemList[i].Token == ELSE {
			// splice ) before
			sequenceItemList = append(sequenceItemList[:i+1], sequenceItemList[i:]...)
			sequenceItemList[i] = SequenceItem{Token: RIGHT_PAREN, Literal: ")", Normalized: ")"}
			i++
		}
		i++
	}

	return sequenceItemList
}

func (e *Evaluator) condEval(cc ConditionClause, principal, action, resource, context string) (SequenceItem, error) {
	var outputQueue []SequenceItem
	var operatorStack []SequenceItem

	// wrap the tokens between if -> then & then -> else to ensure embedded if-then-else may work
	cc.Sequence = e.wrapIfThenElse(cc.Sequence)

	// restructure to rpn using shunting yard, and set normalized if not set
	for _, s := range cc.Sequence {
		switch s.Token {
		case TRUE, FALSE, LONG, DBLQUOTESTR, ENTITY, ATTRIBUTE:
			outputQueue = append(outputQueue, s)
		case PRINCIPAL:
			s.Token = ENTITY
			s.Normalized = principal
			outputQueue = append(outputQueue, s)
		case ACTION:
			s.Token = ENTITY
			s.Normalized = action
			outputQueue = append(outputQueue, s)
		case RESOURCE:
			s.Token = ENTITY
			s.Normalized = resource
			outputQueue = append(outputQueue, s)
		case CONTEXT:
			s.Normalized = context
			outputQueue = append(outputQueue, s)
		case LEFT_SQB:
			outputQueue = append(outputQueue, s)
		case LEFT_BRACE:
			outputQueue = append(outputQueue, s)
		case COMMA:
			outputQueue = append(outputQueue, s)
		case COLON:
			operatorStack = append(outputQueue, s)
		case RIGHT_SQB:
			operatorStack = append(operatorStack, s)
		case RIGHT_BRACE:
			operatorStack = append(operatorStack, s)
		case LEFT_PAREN:
			operatorStack = append(operatorStack, s)
		case FUNCTION:
			operatorStack = append(operatorStack, s)
		case RIGHT_PAREN:
			for {
				if len(operatorStack) < 1 {
					return SequenceItem{}, fmt.Errorf("mismatched parenthesis")
				}
				pop := operatorStack[len(operatorStack)-1]
				operatorStack = operatorStack[:len(operatorStack)-1]

				if pop.Token != LEFT_PAREN {
					outputQueue = append(outputQueue, pop)
				} else {
					break
				}
			}
		case EQUALITY, INEQUALITY, AND, OR, LT, LTE, GT, GTE, PLUS, DASH, MULTIPLIER, IN, HAS, LIKE, PERIOD, EXCLAMATION, IF, THEN, ELSE, RECORDKEY:
			for len(operatorStack) > 0 && OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] != 0 && (OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] > OP_PRECEDENCE[s.Token] || (OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] == OP_PRECEDENCE[s.Token] && LEFT_ASSOCIATIVE[s.Token])) {
				pop := operatorStack[len(operatorStack)-1]
				operatorStack = operatorStack[:len(operatorStack)-1]
				outputQueue = append(outputQueue, pop)
			}
			operatorStack = append(operatorStack, s)
		default:
			return SequenceItem{}, fmt.Errorf("unknown token: (%v)", s.Token)
		}
	}

	for len(operatorStack) > 0 {
		pop := operatorStack[len(operatorStack)-1]
		operatorStack = operatorStack[:len(operatorStack)-1]
		if pop.Token == LEFT_PAREN {
			return SequenceItem{}, fmt.Errorf("mismatched parenthesis")
		}
		outputQueue = append(outputQueue, pop)
	}

	var evalStack []SequenceItem
	var lhs SequenceItem
	var rhs SequenceItem
	for _, s := range outputQueue {
		switch s.Token {
		case COMMA:
		case TRUE, FALSE, LONG, DBLQUOTESTR, ENTITY, ATTRIBUTE, CONTEXT, LEFT_SQB, LEFT_BRACE, COLON:
			evalStack = append(evalStack, s)
		case EXCLAMATION: // TODO: limit to 4x sequentially, also negation unary
			rhs = evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]

			if bubbleErrors(&evalStack, rhs) {
				continue
			}

			if rhs.Token == TRUE {
				evalStack = append(evalStack, SequenceItem{
					Token:      FALSE,
					Literal:    "false",
					Normalized: "false",
				})
			} else if rhs.Token == FALSE {
				evalStack = append(evalStack, SequenceItem{
					Token:      TRUE,
					Literal:    "true",
					Normalized: "true",
				})
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    "attempted to negate non-boolean",
					Normalized: "attempted to negate non-boolean",
				})
				continue
			}
		case IF:
			thenElseResult := evalStack[len(evalStack)-1]
			ifResult := evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if e.AllowShortCircuiting && ((ifResult.Token == TRUE && thenElseResult.Token == THEN_TRUE_ELSE_TRUE) ||
				(ifResult.Token == TRUE && thenElseResult.Token == THEN_TRUE_ELSE_FALSE) ||
				(ifResult.Token == TRUE && thenElseResult.Token == THEN_TRUE_ELSE_ERROR) ||
				(ifResult.Token == FALSE && thenElseResult.Token == THEN_FALSE_ELSE_TRUE) ||
				(ifResult.Token == FALSE && thenElseResult.Token == THEN_TRUE_ELSE_TRUE) ||
				(ifResult.Token == FALSE && thenElseResult.Token == THEN_ERROR_ELSE_TRUE)) {
				evalStack = append(evalStack, SequenceItem{
					Token:      TRUE,
					Literal:    "true",
					Normalized: "true",
				})
			} else if e.AllowShortCircuiting && ((ifResult.Token == TRUE && thenElseResult.Token == THEN_FALSE_ELSE_FALSE) ||
				(ifResult.Token == TRUE && thenElseResult.Token == THEN_FALSE_ELSE_TRUE) ||
				(ifResult.Token == TRUE && thenElseResult.Token == THEN_FALSE_ELSE_ERROR) ||
				(ifResult.Token == FALSE && thenElseResult.Token == THEN_FALSE_ELSE_FALSE) ||
				(ifResult.Token == FALSE && thenElseResult.Token == THEN_TRUE_ELSE_FALSE) ||
				(ifResult.Token == FALSE && thenElseResult.Token == THEN_ERROR_ELSE_FALSE)) {
				evalStack = append(evalStack, SequenceItem{
					Token:      FALSE,
					Literal:    "false",
					Normalized: "false",
				})
			} else {
				if bubbleErrors(&evalStack, ifResult, thenElseResult) {
					continue
				}

				if (ifResult.Token == TRUE && thenElseResult.Token == THEN_TRUE_ELSE_TRUE) ||
					(ifResult.Token == TRUE && thenElseResult.Token == THEN_TRUE_ELSE_FALSE) ||
					(ifResult.Token == FALSE && thenElseResult.Token == THEN_FALSE_ELSE_TRUE) ||
					(ifResult.Token == FALSE && thenElseResult.Token == THEN_TRUE_ELSE_TRUE) {
					evalStack = append(evalStack, SequenceItem{
						Token:      TRUE,
						Literal:    "true",
						Normalized: "true",
					})
				} else if (ifResult.Token == TRUE && thenElseResult.Token == THEN_FALSE_ELSE_FALSE) ||
					(ifResult.Token == TRUE && thenElseResult.Token == THEN_FALSE_ELSE_TRUE) ||
					(ifResult.Token == FALSE && thenElseResult.Token == THEN_FALSE_ELSE_FALSE) ||
					(ifResult.Token == FALSE && thenElseResult.Token == THEN_TRUE_ELSE_FALSE) {
					evalStack = append(evalStack, SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					})
				} else {
					return SequenceItem{}, fmt.Errorf("invalid use of if-then-else block, got if %v, then-else %v", ifResult.Token, thenElseResult.Token)
				}
			}
		case THEN:
			elseResult := evalStack[len(evalStack)-1]
			thenResult := evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if thenResult.Token == TRUE && elseResult.Token == ELSE_TRUE {
				evalStack = append(evalStack, SequenceItem{
					Token:      THEN_TRUE_ELSE_TRUE,
					Literal:    "THEN_TRUE_ELSE_TRUE",
					Normalized: "THEN_TRUE_ELSE_TRUE",
				})
			} else if thenResult.Token == TRUE && elseResult.Token == ELSE_FALSE {
				evalStack = append(evalStack, SequenceItem{
					Token:      THEN_TRUE_ELSE_FALSE,
					Literal:    "THEN_TRUE_ELSE_FALSE",
					Normalized: "THEN_TRUE_ELSE_FALSE",
				})
			} else if thenResult.Token == TRUE && elseResult.Token == ERROR {
				evalStack = append(evalStack, SequenceItem{
					Token:      THEN_TRUE_ELSE_ERROR,
					Literal:    elseResult.Literal,
					Normalized: elseResult.Normalized,
				})
			} else if thenResult.Token == FALSE && elseResult.Token == ELSE_TRUE {
				evalStack = append(evalStack, SequenceItem{
					Token:      THEN_FALSE_ELSE_TRUE,
					Literal:    "THEN_FALSE_ELSE_TRUE",
					Normalized: "THEN_FALSE_ELSE_TRUE",
				})
			} else if thenResult.Token == FALSE && elseResult.Token == ELSE_FALSE {
				evalStack = append(evalStack, SequenceItem{
					Token:      THEN_FALSE_ELSE_FALSE,
					Literal:    "THEN_FALSE_ELSE_FALSE",
					Normalized: "THEN_FALSE_ELSE_FALSE",
				})
			} else if thenResult.Token == FALSE && elseResult.Token == ERROR {
				evalStack = append(evalStack, SequenceItem{
					Token:      THEN_FALSE_ELSE_ERROR,
					Literal:    elseResult.Literal,
					Normalized: elseResult.Normalized,
				})
			} else if thenResult.Token == ERROR && elseResult.Token == ELSE_TRUE {
				evalStack = append(evalStack, SequenceItem{
					Token:      THEN_ERROR_ELSE_TRUE,
					Literal:    thenResult.Literal,
					Normalized: thenResult.Normalized,
				})
			} else if thenResult.Token == ERROR && elseResult.Token == ELSE_FALSE {
				evalStack = append(evalStack, SequenceItem{
					Token:      THEN_ERROR_ELSE_FALSE,
					Literal:    thenResult.Literal,
					Normalized: thenResult.Normalized,
				})
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    fmt.Sprintf("invalid use of if-then-else block, got then %v, else %v", thenResult.Token, elseResult.Token),
					Normalized: fmt.Sprintf("invalid use of if-then-else block, got then %v, else %v", thenResult.Token, elseResult.Token),
				})
				continue
			}
		case ELSE:
			elseResult := evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]

			if bubbleErrors(&evalStack, elseResult) {
				continue
			}

			if elseResult.Token == TRUE {
				evalStack = append(evalStack, SequenceItem{
					Token:      ELSE_TRUE,
					Literal:    "ELSE_TRUE",
					Normalized: "ELSE_TRUE",
				})
			} else if elseResult.Token == FALSE {
				evalStack = append(evalStack, SequenceItem{
					Token:      ELSE_FALSE,
					Literal:    "ELSE_FALSE",
					Normalized: "ELSE_FALSE",
				})
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    fmt.Sprintf("invalid use of if-then-else block, got else %v", elseResult.Token),
					Normalized: fmt.Sprintf("invalid use of if-then-else block, got else %v", elseResult.Token),
				})
				continue
			}
		case FUNCTION:
			rhs = evalStack[len(evalStack)-1]
			lit := rhs.Normalized

			if s.Normalized == "ip" {
				evalStack = evalStack[:len(evalStack)-1]

				if bubbleErrors(&evalStack, rhs) {
					continue
				}

				normalized := lit
				if !strings.Contains(lit, "/") {
					if strings.Count(lit, ":") >= 2 {
						normalized += "/128"
					} else {
						normalized += "/32"
					}
				}
				_, ipNet, err := net.ParseCIDR(normalized)
				if err != nil {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    "invalid ip",
						Normalized: "invalid ip",
					})
					continue
				}
				evalStack = append(evalStack, SequenceItem{
					Token:      IP,
					Literal:    lit,
					Normalized: ipNet.String(),
				})
			} else if s.Normalized == "decimal" {
				evalStack = evalStack[:len(evalStack)-1]

				if bubbleErrors(&evalStack, rhs) {
					continue
				}

				i := strings.IndexByte(lit, '.')
				if i > -1 {
					if (len(lit) - i - 1) > 4 {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "too much precision in decimal",
							Normalized: "too much precision in decimal",
						})
						continue
					}
				}
				f, err := strconv.ParseFloat(lit, 64)
				if err != nil {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    "error parsing decimal",
						Normalized: "error parsing decimal",
					})
					continue
				}
				evalStack = append(evalStack, SequenceItem{
					Token:      DECIMAL,
					Literal:    lit,
					Normalized: strconv.FormatFloat(f, 'f', 4, 64),
				})
			} else {
				evalStack = append(evalStack, s)
			}
		case PERIOD:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if bubbleErrors(&evalStack, lhs, rhs) {
				continue
			}

			// TODO: Record attribute handling

			if lhs.Token == CONTEXT && rhs.Token == ATTRIBUTE {
				item, err := e.getAttributeAttributeSequenceItem(lhs.Normalized, rhs.Normalized)
				if err != nil {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    err.Error(),
						Normalized: err.Error(),
					})
					continue
				}
				evalStack = append(evalStack, item)
			} else if lhs.Token == ENTITY && rhs.Token == ATTRIBUTE {
				if e.es == nil {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    fmt.Sprintf("invalid attribute access (no entities available): (%v)", s.Token),
						Normalized: fmt.Sprintf("invalid attribute access (no entities available): (%v)", s.Token),
					})
					continue
				} else {
					item, err := e.getEntityAttributeSequenceItem(lhs.Normalized, rhs.Normalized)
					if err != nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    err.Error(),
							Normalized: err.Error(),
						})
						continue
					}
					evalStack = append(evalStack, item)
				}
			} else if lhs.Token == ATTRIBUTE && rhs.Token == ATTRIBUTE {
				item, err := e.getAttributeAttributeSequenceItem(lhs.Normalized, rhs.Normalized)
				if err != nil {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    err.Error(),
						Normalized: err.Error(),
					})
					continue
				}
				evalStack = append(evalStack, item)
			} else if rhs.Token == FUNCTION {
				if rhs.Normalized == "contains" {
					actualLhs := evalStack[len(evalStack)-1]
					evalStack = evalStack[:len(evalStack)-1]

					if bubbleErrors(&evalStack, actualLhs) {
						continue
					}

					if actualLhs.Token != SET {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "unexpected use of contains function",
							Normalized: "unexpected use of contains function",
						})
						continue
					}
					var actualLhsSet []interface{}
					err := json.Unmarshal([]byte(actualLhs.Normalized), &actualLhsSet)
					if err != nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    err.Error(),
							Normalized: err.Error(),
						})
						continue
					}
					item := SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					}
					for _, setItem := range actualLhsSet {
						if lhs.Normalized == setItem {
							item = SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							}
							break
						}
					}
					evalStack = append(evalStack, item)
				} else if lhs.Token == SET {
					if rhs.Normalized == "containsAll" {
						actualLhs := evalStack[len(evalStack)-1]
						evalStack = evalStack[:len(evalStack)-1]

						if bubbleErrors(&evalStack, actualLhs) {
							continue
						}

						if actualLhs.Token != SET {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "unexpected use of containsAll function",
								Normalized: "unexpected use of containsAll function",
							})
							continue
						}
						var actualLhsSet []interface{}
						err := json.Unmarshal([]byte(actualLhs.Normalized), &actualLhsSet)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    err.Error(),
								Normalized: err.Error(),
							})
							continue
						}
						var actualRhsSet []interface{}
						err = json.Unmarshal([]byte(lhs.Normalized), &actualRhsSet)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    err.Error(),
								Normalized: err.Error(),
							})
							continue
						}
						item := SequenceItem{
							Token:      TRUE,
							Literal:    "true",
							Normalized: "true",
						}
						for _, rhsSetItem := range actualRhsSet {
							found := false
							for _, lhsSetItem := range actualLhsSet {
								if rhsSetItem == lhsSetItem {
									found = true
									break
								}
							}
							if !found {
								item = SequenceItem{
									Token:      FALSE,
									Literal:    "false",
									Normalized: "false",
								}
								break
							}
						}
						evalStack = append(evalStack, item)
					} else if rhs.Normalized == "containsAny" {
						actualLhs := evalStack[len(evalStack)-1]
						evalStack = evalStack[:len(evalStack)-1]

						if bubbleErrors(&evalStack, actualLhs) {
							continue
						}

						if actualLhs.Token != SET {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "unexpected use of containsAny function",
								Normalized: "unexpected use of containsAny function",
							})
							continue
						}
						var actualLhsSet []interface{}
						err := json.Unmarshal([]byte(actualLhs.Normalized), &actualLhsSet)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    err.Error(),
								Normalized: err.Error(),
							})
							continue
						}
						var actualRhsSet []interface{}
						err = json.Unmarshal([]byte(lhs.Normalized), &actualRhsSet)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    err.Error(),
								Normalized: err.Error(),
							})
							continue
						}
						item := SequenceItem{
							Token:      FALSE,
							Literal:    "false",
							Normalized: "false",
						}
					ActualRhsSetLoop:
						for _, rhsSetItem := range actualRhsSet {
							for _, lhsSetItem := range actualLhsSet {
								if rhsSetItem == lhsSetItem {
									item = SequenceItem{
										Token:      TRUE,
										Literal:    "true",
										Normalized: "true",
									}
									break ActualRhsSetLoop
								}
							}
						}
						evalStack = append(evalStack, item)
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    fmt.Sprintf("unknown function: %s", rhs.Literal),
							Normalized: fmt.Sprintf("unknown function: %s", rhs.Literal),
						})
						continue
					}
				} else if lhs.Token == IP {
					if rhs.Normalized == "isIpv4" {
						if strings.Count(lhs.Normalized, ":") < 2 {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if rhs.Normalized == "isIpv6" {
						if strings.Count(lhs.Normalized, ":") >= 2 {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if rhs.Normalized == "isInRange" {
						insideRange := evalStack[len(evalStack)-1]
						evalStack = evalStack[:len(evalStack)-1]

						if bubbleErrors(&evalStack, insideRange) {
							continue
						}

						_, ipNet, err := net.ParseCIDR(lhs.Normalized)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "invalid IP",
								Normalized: "invalid IP",
							})
							continue
						}
						_, insideIpNet, err := net.ParseCIDR(insideRange.Normalized)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "invalid IP",
								Normalized: "invalid IP",
							})
							continue
						}

						for i := range insideIpNet.IP {
							insideIpNet.IP[i] &= insideIpNet.Mask[i]
						}
						firstIPInCIDR := insideIpNet.IP

						for i := range insideIpNet.IP {
							insideIpNet.IP[i] |= ^insideIpNet.Mask[i]
						}
						lastIPInCIDR := insideIpNet.IP

						if ipNet.Contains(firstIPInCIDR) && ipNet.Contains(lastIPInCIDR) {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if rhs.Normalized == "isLoopback" {
						_, ipNet, err := net.ParseCIDR(lhs.Normalized)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "invalid IP",
								Normalized: "invalid IP",
							})
							continue
						}

						for i := range ipNet.IP {
							ipNet.IP[i] &= ipNet.Mask[i]
						}
						firstIPInCIDR := ipNet.IP

						for i := range ipNet.IP {
							ipNet.IP[i] |= ^ipNet.Mask[i]
						}
						lastIPInCIDR := ipNet.IP

						if firstIPInCIDR.IsLoopback() && lastIPInCIDR.IsLoopback() {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if rhs.Normalized == "isMulticast" {
						_, ipNet, err := net.ParseCIDR(lhs.Normalized)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "invalid IP",
								Normalized: "invalid IP",
							})
							continue
						}

						for i := range ipNet.IP {
							ipNet.IP[i] &= ipNet.Mask[i]
						}
						firstIPInCIDR := ipNet.IP

						for i := range ipNet.IP {
							ipNet.IP[i] |= ^ipNet.Mask[i]
						}
						lastIPInCIDR := ipNet.IP

						if firstIPInCIDR.IsMulticast() && lastIPInCIDR.IsMulticast() {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    fmt.Sprintf("unknown IP function: %s", rhs.Literal),
							Normalized: fmt.Sprintf("unknown IP function: %s", rhs.Literal),
						})
						continue
					}
				} else if lhs.Token == DECIMAL {
					if rhs.Normalized == "lessThan" {
						actualLhs := evalStack[len(evalStack)-1]
						evalStack = evalStack[:len(evalStack)-1]

						if bubbleErrors(&evalStack, actualLhs) {
							continue
						}

						lhsD, err := strconv.ParseFloat(actualLhs.Normalized, 64)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "error parsing decimal",
								Normalized: "error parsing decimal",
							})
							continue
						}
						rhsD, err := strconv.ParseFloat(lhs.Normalized, 64)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "error parsing decimal",
								Normalized: "error parsing decimal",
							})
							continue
						}

						if lhsD < rhsD {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if rhs.Normalized == "lessThanOrEqual" {
						actualLhs := evalStack[len(evalStack)-1]
						evalStack = evalStack[:len(evalStack)-1]

						if bubbleErrors(&evalStack, actualLhs) {
							continue
						}

						lhsD, err := strconv.ParseFloat(actualLhs.Normalized, 64)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "error parsing decimal",
								Normalized: "error parsing decimal",
							})
							continue
						}
						rhsD, err := strconv.ParseFloat(lhs.Normalized, 64)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "error parsing decimal",
								Normalized: "error parsing decimal",
							})
							continue
						}

						if lhsD <= rhsD {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if rhs.Normalized == "greaterThan" {
						actualLhs := evalStack[len(evalStack)-1]
						evalStack = evalStack[:len(evalStack)-1]

						if bubbleErrors(&evalStack, actualLhs) {
							continue
						}

						lhsD, err := strconv.ParseFloat(actualLhs.Normalized, 64)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "error parsing decimal",
								Normalized: "error parsing decimal",
							})
							continue
						}
						rhsD, err := strconv.ParseFloat(lhs.Normalized, 64)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "error parsing decimal",
								Normalized: "error parsing decimal",
							})
							continue
						}

						if lhsD > rhsD {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if rhs.Normalized == "greaterThanOrEqual" {
						actualLhs := evalStack[len(evalStack)-1]
						evalStack = evalStack[:len(evalStack)-1]

						if bubbleErrors(&evalStack, actualLhs) {
							continue
						}

						lhsD, err := strconv.ParseFloat(actualLhs.Normalized, 64)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "error parsing decimal",
								Normalized: "error parsing decimal",
							})
							continue
						}
						rhsD, err := strconv.ParseFloat(lhs.Normalized, 64)
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    "error parsing decimal",
								Normalized: "error parsing decimal",
							})
							continue
						}

						if lhsD >= rhsD {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    fmt.Sprintf("unknown decimal function: %s", rhs.Literal),
							Normalized: fmt.Sprintf("unknown decimal function: %s", rhs.Literal),
						})
						continue
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    fmt.Sprintf("unknown function: %s", rhs.Literal),
						Normalized: fmt.Sprintf("unknown function: %s", rhs.Literal),
					})
					continue
				}
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    fmt.Sprintf("invalid period use, unknown function or attribute access: %q (%v)", lhs.Token, lhs.Token),
					Normalized: fmt.Sprintf("invalid period use, unknown function or attribute access: %q (%v)", lhs.Token, lhs.Token),
				})
				continue
			}
		case RIGHT_BRACE:
			record := SequenceItem{
				Token: RECORD,
			}
			var vals []SequenceItem

			rhs = evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]

			for rhs.Token != LEFT_BRACE {
				if rhs.Token == COLON {
					rhs = evalStack[len(evalStack)-1]
					evalStack = evalStack[:len(evalStack)-1]

					if len(vals) == 0 {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "error whilst processing record, nothing found for value",
							Normalized: "error whilst processing record, nothing found for value",
						})
						continue
					}

					if rhs.Token == DBLQUOTESTR || rhs.Token == RECORDKEY {
						_, ok := record.RecordKeyValuePairs[rhs.Normalized]
						if !ok { // set only if not already set
							// evaluate the inner expr value
							condEvalResult, err := e.condEval(ConditionClause{Type: cc.Type, Sequence: vals}, principal, action, resource, context)
							if err != nil {
								condEvalResult = SequenceItem{
									Token:      ERROR,
									Literal:    fmt.Sprintf("error whilst evaluating record value: %s", err.Error()),
									Normalized: fmt.Sprintf("error whilst evaluating record value: %s", err.Error()),
								}
							}

							record.RecordKeyValuePairs[rhs.Normalized] = condEvalResult
							vals = []SequenceItem{}
						}
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "error whilst processing record, non-string key",
							Normalized: "error whilst processing record, non-string key",
						})
						continue
					}
				} else {
					vals = append(vals, rhs)
				}
				rhs = evalStack[len(evalStack)-1]
				evalStack = evalStack[:len(evalStack)-1]
			}

			if len(vals) == 0 {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    "error whilst processing record",
					Normalized: "error whilst processing record",
				})
				continue
			}

			evalStack = append(evalStack, record)
		case RIGHT_SQB:
			var rawSet []SequenceItem
			var set []string

			rhs = evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]

			for rhs.Token != LEFT_SQB {
				rawSet = append(rawSet, rhs) // TODO: read until comma, recurse condEval
				set = append(set, rhs.Normalized)
				rhs = evalStack[len(evalStack)-1]
				evalStack = evalStack[:len(evalStack)-1]
			}

			if bubbleErrors(&evalStack, rawSet...) {
				continue
			}

			b, err := json.Marshal(set)
			if err != nil {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    "error whilst processing set",
					Normalized: "error whilst processing set",
				})
				continue
			}

			evalStack = append(evalStack, SequenceItem{
				Token:      SET,
				Literal:    string(b),
				Normalized: string(b),
			})
		case LIKE:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if bubbleErrors(&evalStack, lhs, rhs) {
				continue
			}

			if lhs.Token == DBLQUOTESTR {
				if rhs.Token == DBLQUOTESTR {
					matched, stopped := match.MatchLimit(lhs.Normalized, rhs.Normalized, 100)
					if stopped {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "string match too complex",
							Normalized: "string match too complex",
						})
						continue
					}
					if matched {
						evalStack = append(evalStack, SequenceItem{
							Token:      TRUE,
							Literal:    "true",
							Normalized: "true",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      FALSE,
							Literal:    "false",
							Normalized: "false",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					})
				}
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    fmt.Sprintf("unknown token near like: (%v)", s.Token),
					Normalized: fmt.Sprintf("unknown token near like: (%v)", s.Token),
				})
				continue
			}
		case IN:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if bubbleErrors(&evalStack, lhs, rhs) {
				continue
			}

			if lhs.Token == ENTITY {
				if rhs.Token == ENTITY {
					if lhs.Normalized == rhs.Normalized {
						evalStack = append(evalStack, SequenceItem{
							Token:      TRUE,
							Literal:    "true",
							Normalized: "true",
						})
					} else {
						if e.es == nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						} else {
							descendants, err := e.es.GetEntityDescendents([]string{rhs.Normalized})
							if err != nil {
								evalStack = append(evalStack, SequenceItem{
									Token:      ERROR,
									Literal:    err.Error(),
									Normalized: err.Error(),
								})
								continue
							}
							if containsEntity(descendants, lhs.Normalized) {
								evalStack = append(evalStack, SequenceItem{
									Token:      TRUE,
									Literal:    "true",
									Normalized: "true",
								})
							} else {
								evalStack = append(evalStack, SequenceItem{
									Token:      FALSE,
									Literal:    "false",
									Normalized: "false",
								})
							}
						}
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					})
				}
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    fmt.Sprintf("unknown token near in: (%v)", s.Token),
					Normalized: fmt.Sprintf("unknown token near in: (%v)", s.Token),
				})
				continue
			}
		case HAS:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if bubbleErrors(&evalStack, lhs, rhs) {
				continue
			}

			if lhs.Token == ENTITY {
				if rhs.Token == ATTRIBUTE {
					if e.es == nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      FALSE,
							Literal:    "false",
							Normalized: "false",
						})
					} else {
						entities, err := e.es.GetEntities()
						if err != nil {
							evalStack = append(evalStack, SequenceItem{
								Token:      ERROR,
								Literal:    err.Error(),
								Normalized: err.Error(),
							})
							continue
						}

						item := SequenceItem{
							Token:      FALSE,
							Literal:    "false",
							Normalized: "false",
						}

						for _, entity := range entities {
							if entity.Identifier == lhs.Normalized {
								for _, attribute := range entity.Attributes {
									if attribute.Name == rhs.Normalized {
										item = SequenceItem{
											Token:      TRUE,
											Literal:    "true",
											Normalized: "true",
										}
									}
								}
							}
						}

						evalStack = append(evalStack, item)
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    fmt.Sprintf("unknown token near has: (%v)", s.Token),
						Normalized: fmt.Sprintf("unknown token near has: (%v)", s.Token),
					})
					continue
				}
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    fmt.Sprintf("unknown token near has: (%v)", s.Token),
					Normalized: fmt.Sprintf("unknown token near has: (%v)", s.Token),
				})
				continue
			}
		case LT, LTE, GT, GTE, PLUS, DASH, MULTIPLIER:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if bubbleErrors(&evalStack, lhs, rhs) {
				continue
			}

			if lhs.Token == LONG {
				if rhs.Token == LONG {
					lhsL, err := strconv.ParseInt(lhs.Normalized, 10, 64)
					if err != nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    err.Error(),
							Normalized: err.Error(),
						})
						continue
					}
					rhsL, err := strconv.ParseInt(rhs.Normalized, 10, 64)
					if err != nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    err.Error(),
							Normalized: err.Error(),
						})
						continue
					}

					if s.Token == LT {
						if lhsL < rhsL {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if s.Token == LTE {
						if lhsL <= rhsL {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if s.Token == GT {
						if lhsL > rhsL {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if s.Token == GTE {
						if lhsL >= rhsL {
							evalStack = append(evalStack, SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							})
						}
					} else if s.Token == PLUS {
						evalStack = append(evalStack, SequenceItem{
							Token:      LONG,
							Literal:    strconv.FormatInt(lhsL+rhsL, 10),
							Normalized: strconv.FormatInt(lhsL+rhsL, 10),
						})
					} else if s.Token == DASH {
						evalStack = append(evalStack, SequenceItem{
							Token:      LONG,
							Literal:    strconv.FormatInt(lhsL-rhsL, 10),
							Normalized: strconv.FormatInt(lhsL-rhsL, 10),
						})
					} else if s.Token == MULTIPLIER {
						evalStack = append(evalStack, SequenceItem{
							Token:      LONG,
							Literal:    strconv.FormatInt(lhsL*rhsL, 10),
							Normalized: strconv.FormatInt(lhsL*rhsL, 10),
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    fmt.Sprintf("unknown token near comparitor or math operator: (%v)", s.Token),
						Normalized: fmt.Sprintf("unknown token near comparitor or math operator: (%v)", s.Token),
					})
					continue
				}
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      ERROR,
					Literal:    fmt.Sprintf("unknown token near comparitor or math operator: (%v)", s.Token),
					Normalized: fmt.Sprintf("unknown token near comparitor or math operator: (%v)", s.Token),
				})
				continue
			}
		case EQUALITY:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if bubbleErrors(&evalStack, lhs, rhs) {
				continue
			}

			if lhs.Token == TRUE || lhs.Token == FALSE {
				if rhs.Token == lhs.Token {
					evalStack = append(evalStack, SequenceItem{
						Token:      TRUE,
						Literal:    "true",
						Normalized: "true",
					})
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					})
				}
			} else if lhs.Token == IP {
				if rhs.Token == IP {
					// needs to compare individual IPs and CIDR form
					normalized := lhs.Normalized
					if !strings.Contains(normalized, "/") {
						if strings.Count(normalized, ":") >= 2 {
							normalized += "/128"
						} else {
							normalized += "/32"
						}
					}
					_, lhsNet, err := net.ParseCIDR(normalized)
					if err != nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "invalid ip",
							Normalized: "invalid ip",
						})
						continue
					}

					normalized = rhs.Normalized
					if !strings.Contains(normalized, "/") {
						if strings.Count(normalized, ":") >= 2 {
							normalized += "/128"
						} else {
							normalized += "/32"
						}
					}
					_, rhsNet, err := net.ParseCIDR(normalized)
					if err != nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "invalid ip",
							Normalized: "invalid ip",
						})
						continue
					}

					for i := range lhsNet.IP {
						lhsNet.IP[i] &= lhsNet.Mask[i]
					}
					firstIPInLhsCIDR := lhsNet.IP

					for i := range lhsNet.IP {
						lhsNet.IP[i] |= ^lhsNet.Mask[i]
					}
					lastIPInLhsCIDR := lhsNet.IP

					for i := range rhsNet.IP {
						rhsNet.IP[i] &= rhsNet.Mask[i]
					}
					firstIPInRhsCIDR := rhsNet.IP

					for i := range rhsNet.IP {
						rhsNet.IP[i] |= ^rhsNet.Mask[i]
					}
					lastIPInRhsCIDR := rhsNet.IP

					if firstIPInLhsCIDR.String() == firstIPInRhsCIDR.String() && lastIPInLhsCIDR.String() == lastIPInRhsCIDR.String() {
						evalStack = append(evalStack, SequenceItem{
							Token:      TRUE,
							Literal:    "true",
							Normalized: "true",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      FALSE,
							Literal:    "false",
							Normalized: "false",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					})
				}
			} else if lhs.Token == rhs.Token {
				if lhs.Normalized == rhs.Normalized {
					evalStack = append(evalStack, SequenceItem{
						Token:      TRUE,
						Literal:    "true",
						Normalized: "true",
					})
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					})
				}
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      FALSE,
					Literal:    "false",
					Normalized: "false",
				})
			}
		case INEQUALITY:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if bubbleErrors(&evalStack, lhs, rhs) {
				continue
			}

			if lhs.Token == TRUE || lhs.Token == FALSE {
				if rhs.Token == lhs.Token {
					evalStack = append(evalStack, SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					})
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      TRUE,
						Literal:    "true",
						Normalized: "true",
					})
				}
			} else if lhs.Token == IP {
				if rhs.Token == IP {
					// needs to compare individual IPs and CIDR form
					normalized := lhs.Normalized
					if !strings.Contains(normalized, "/") {
						if strings.Count(normalized, ":") >= 2 {
							normalized += "/128"
						} else {
							normalized += "/32"
						}
					}
					_, lhsNet, err := net.ParseCIDR(normalized)
					if err != nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "invalid ip",
							Normalized: "invalid ip",
						})
						continue
					}

					normalized = rhs.Normalized
					if !strings.Contains(normalized, "/") {
						if strings.Count(normalized, ":") >= 2 {
							normalized += "/128"
						} else {
							normalized += "/32"
						}
					}
					_, rhsNet, err := net.ParseCIDR(normalized)
					if err != nil {
						evalStack = append(evalStack, SequenceItem{
							Token:      ERROR,
							Literal:    "invalid ip",
							Normalized: "invalid ip",
						})
						continue
					}

					for i := range lhsNet.IP {
						lhsNet.IP[i] &= lhsNet.Mask[i]
					}
					firstIPInLhsCIDR := lhsNet.IP

					for i := range lhsNet.IP {
						lhsNet.IP[i] |= ^lhsNet.Mask[i]
					}
					lastIPInLhsCIDR := lhsNet.IP

					for i := range rhsNet.IP {
						rhsNet.IP[i] &= rhsNet.Mask[i]
					}
					firstIPInRhsCIDR := rhsNet.IP

					for i := range rhsNet.IP {
						rhsNet.IP[i] |= ^rhsNet.Mask[i]
					}
					lastIPInRhsCIDR := rhsNet.IP

					if firstIPInLhsCIDR.String() == firstIPInRhsCIDR.String() && lastIPInLhsCIDR.String() == lastIPInRhsCIDR.String() {
						evalStack = append(evalStack, SequenceItem{
							Token:      FALSE,
							Literal:    "false",
							Normalized: "false",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      TRUE,
							Literal:    "true",
							Normalized: "true",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      TRUE,
						Literal:    "true",
						Normalized: "true",
					})
				}
			} else if lhs.Token == rhs.Token {
				if lhs.Normalized == rhs.Normalized {
					evalStack = append(evalStack, SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					})
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      TRUE,
						Literal:    "true",
						Normalized: "true",
					})
				}
			} else {
				evalStack = append(evalStack, SequenceItem{
					Token:      TRUE,
					Literal:    "true",
					Normalized: "true",
				})
			}
		case AND:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if e.AllowShortCircuiting && lhs.Token == FALSE {
				evalStack = append(evalStack, SequenceItem{
					Token:      FALSE,
					Literal:    "false",
					Normalized: "false",
				})
			} else {
				if bubbleErrors(&evalStack, lhs, rhs) {
					continue
				}

				if (lhs.Token == TRUE || lhs.Token == FALSE) && (rhs.Token == TRUE || rhs.Token == FALSE) {
					if lhs.Token == TRUE && rhs.Token == TRUE {
						evalStack = append(evalStack, SequenceItem{
							Token:      TRUE,
							Literal:    "true",
							Normalized: "true",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      FALSE,
							Literal:    "false",
							Normalized: "false",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    fmt.Sprintf("unknown token near and: (%v)", s.Token),
						Normalized: fmt.Sprintf("unknown token near and: (%v)", s.Token),
					})
					continue
				}
			}
		case OR:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if e.AllowShortCircuiting && lhs.Token == TRUE {
				evalStack = append(evalStack, SequenceItem{
					Token:      TRUE,
					Literal:    "true",
					Normalized: "true",
				})
			} else {
				if bubbleErrors(&evalStack, lhs, rhs) {
					continue
				}

				if (lhs.Token == TRUE || lhs.Token == FALSE) && (rhs.Token == TRUE || rhs.Token == FALSE) {
					if lhs.Token == TRUE || rhs.Token == TRUE {
						evalStack = append(evalStack, SequenceItem{
							Token:      TRUE,
							Literal:    "true",
							Normalized: "true",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:      FALSE,
							Literal:    "false",
							Normalized: "false",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:      ERROR,
						Literal:    fmt.Sprintf("unknown token near or: (%v)", s.Token),
						Normalized: fmt.Sprintf("unknown token near or: (%v)", s.Token),
					})
					continue
				}
			}
		default:
			return SequenceItem{}, fmt.Errorf("unknown token: (%v)", s.Token)
		}
	}

	if len(evalStack) != 1 {
		return SequenceItem{}, fmt.Errorf("invalid stack state")
	}

	if evalStack[0].Token == ERROR {
		return SequenceItem{}, fmt.Errorf(evalStack[0].Literal)
	}

	return evalStack[0], nil
}

func (e *Evaluator) getEntityAttributeSequenceItem(entityName, attributeName string) (SequenceItem, error) {
	if e.es == nil {
		return SequenceItem{}, fmt.Errorf("attribute access on invalid entity store")
	}

	entities, err := e.es.GetEntities()
	if err != nil {
		return SequenceItem{}, err
	}

	for _, entity := range entities {
		if entity.Identifier == entityName {
			for _, attribute := range entity.Attributes {
				if attribute.Name == attributeName {
					if attribute.StringValue != nil {
						b, _ := json.Marshal(*attribute.StringValue)
						return SequenceItem{
							Token:      DBLQUOTESTR,
							Literal:    string(b),
							Normalized: *attribute.StringValue,
						}, nil
					}
					if attribute.LongValue != nil {
						return SequenceItem{
							Token:      LONG,
							Literal:    strconv.FormatInt(*attribute.LongValue, 10),
							Normalized: strconv.FormatInt(*attribute.LongValue, 10),
						}, nil
					}
					if attribute.BooleanValue != nil {
						if *attribute.BooleanValue {
							return SequenceItem{
								Token:      TRUE,
								Literal:    "true",
								Normalized: "true",
							}, nil
						} else {
							return SequenceItem{
								Token:      FALSE,
								Literal:    "false",
								Normalized: "false",
							}, nil
						}
					}
					if attribute.RecordValue != nil {
						b, err := json.Marshal(*attribute.RecordValue)
						if err != nil {
							return SequenceItem{}, err
						}
						return SequenceItem{
							Token:      ATTRIBUTE,
							Literal:    string(b),
							Normalized: string(b),
						}, nil
					}
					if attribute.SetValue != nil {
						b, err := json.Marshal(*attribute.SetValue)
						if err != nil {
							return SequenceItem{}, err
						}
						return SequenceItem{
							Token:      SET,
							Literal:    string(b),
							Normalized: string(b),
						}, nil
					}
					break
				}
			}
			break
		}
	}

	return SequenceItem{}, fmt.Errorf("attribute not set")
}

func (e *Evaluator) getAttributeAttributeSequenceItem(sourceAttribute, attributeName string) (SequenceItem, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(sourceAttribute), &obj); err != nil {
		return SequenceItem{}, err
	}

	for attrName, attrVal := range obj {
		if attrName == attributeName {
			switch attrVal.(type) {
			case int:
				val := int64(attrVal.(int))
				return SequenceItem{
					Token:      LONG,
					Literal:    strconv.FormatInt(val, 10),
					Normalized: strconv.FormatInt(val, 10),
				}, nil
			case int64:
				val := attrVal.(int64)
				return SequenceItem{
					Token:      LONG,
					Literal:    strconv.FormatInt(val, 10),
					Normalized: strconv.FormatInt(val, 10),
				}, nil
			case float64:
				val := int64(attrVal.(float64))
				return SequenceItem{
					Token:      LONG,
					Literal:    strconv.FormatInt(val, 10),
					Normalized: strconv.FormatInt(val, 10),
				}, nil
			case string:
				b, _ := json.Marshal(attrVal.(string))
				return SequenceItem{
					Token:      DBLQUOTESTR,
					Literal:    string(b),
					Normalized: attrVal.(string),
				}, nil
			case bool:
				val := attrVal.(bool)
				if val {
					return SequenceItem{
						Token:      TRUE,
						Literal:    "true",
						Normalized: "true",
					}, nil
				} else {
					return SequenceItem{
						Token:      FALSE,
						Literal:    "false",
						Normalized: "false",
					}, nil
				}
			case map[string]interface{}:
				val := attrVal.(map[string]interface{})
				b, err := json.Marshal(val)
				if err != nil {
					return SequenceItem{}, err
				}
				return SequenceItem{
					Token:      ATTRIBUTE,
					Literal:    string(b),
					Normalized: string(b),
				}, nil
			case []interface{}:
				val := attrVal.([]interface{})
				b, err := json.Marshal(val)
				if err != nil {
					return SequenceItem{}, err
				}
				return SequenceItem{
					Token:      SET,
					Literal:    string(b),
					Normalized: string(b),
				}, nil
			default:
				return SequenceItem{}, fmt.Errorf("unknown type in attribute block: %v (%s)", attrVal, reflect.TypeOf(attrVal).String())
			}

		}
	}

	return SequenceItem{}, fmt.Errorf("attribute not set")
}

// bubbleErrors interprets lhs, rhs etc. SequenceItems and returns any errors to the evalQueue. The function returns true if there was a bubbled error.
func bubbleErrors(evalStack *[]SequenceItem, items ...SequenceItem) bool {
	bubbleOccurred := false
	var foundErrors []string

	for _, item := range items {
		if item.Token == ERROR || item.Token == THEN_TRUE_ELSE_ERROR || item.Token == THEN_FALSE_ELSE_ERROR || item.Token == THEN_ERROR_ELSE_TRUE || item.Token == THEN_ERROR_ELSE_FALSE {
			foundErrors = append(foundErrors, item.Literal)
			bubbleOccurred = true
		}
	}

	if bubbleOccurred {
		*evalStack = append(*evalStack, SequenceItem{
			Token:      ERROR,
			Literal:    strings.Join(foundErrors, ". "),
			Normalized: strings.Join(foundErrors, ". "),
		})
	}

	return bubbleOccurred
}
