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
	p  *Parser
	es *EntityStore
}

// NewEvaluator returns a new instance of Evaluator.
func NewEvaluator(policyReader io.Reader) *Evaluator {
	return &Evaluator{p: NewParser(policyReader)}
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
					return false, fmt.Errorf("invalid stack state")
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
					return false, fmt.Errorf("invalid stack state")
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

func (e *Evaluator) condEval(cc ConditionClause, principal, action, resource, context string) (SequenceItem, error) {
	var outputQueue []SequenceItem
	var operatorStack []SequenceItem

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
		case COMMA:
			outputQueue = append(outputQueue, s)
		case RIGHT_SQB:
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
		case EQUALITY, INEQUALITY, AND, OR, LT, LTE, GT, GTE, PLUS, DASH, MULTIPLIER, IN, HAS, LIKE, PERIOD, EXCLAMATION, IF, THEN, ELSE:
			for len(operatorStack) > 0 && OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] != 0 && (OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] > OP_PRECEDENCE[s.Token] || (OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] == OP_PRECEDENCE[s.Token] && LEFT_ASSOCIATIVE[s.Token])) {
				pop := operatorStack[len(operatorStack)-1]
				operatorStack = operatorStack[:len(operatorStack)-1]
				outputQueue = append(outputQueue, pop)
			}
			operatorStack = append(operatorStack, s)
		default:
			return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
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
		case TRUE, FALSE, LONG, DBLQUOTESTR, ENTITY, ATTRIBUTE, CONTEXT, LEFT_SQB:
			evalStack = append(evalStack, s)
		case EXCLAMATION: // TODO: limit to 4x sequentially, also negation unary
			rhs = evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]

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
				return SequenceItem{}, fmt.Errorf("attempted to negate non-boolean")
			}
		case IF:
			thenElseResult := evalStack[len(evalStack)-1]
			ifResult := evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

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
				return SequenceItem{}, fmt.Errorf("invalid use of if-then-else block, got %v, %v", ifResult.Token, thenElseResult.Token)
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
			} else {
				return SequenceItem{}, fmt.Errorf("invalid use of if-then-else block, got %v, %v", thenResult.Token, elseResult.Token)
			}
		case ELSE:
			elseResult := evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]

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
				return SequenceItem{}, fmt.Errorf("invalid use of if-then-else block, got %v", elseResult.Token)
			}
		case FUNCTION:
			rhs = evalStack[len(evalStack)-1]
			lit := rhs.Normalized

			if s.Normalized == "ip" {
				evalStack = evalStack[:len(evalStack)-1]

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
					return SequenceItem{}, fmt.Errorf("invalid ip")
				}
				evalStack = append(evalStack, SequenceItem{
					Token:      IP,
					Literal:    lit,
					Normalized: ipNet.String(),
				})
			} else if s.Normalized == "decimal" {
				evalStack = evalStack[:len(evalStack)-1]

				i := strings.IndexByte(lit, '.')
				if i > -1 {
					if (len(lit) - i - 1) > 4 {
						return SequenceItem{}, fmt.Errorf("too much precision in decimal")
					}
				}
				f, err := strconv.ParseFloat(lit, 64)
				if err != nil {
					return SequenceItem{}, fmt.Errorf("error parsing decimal")
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

			if lhs.Token == CONTEXT && rhs.Token == ATTRIBUTE {
				item, err := e.getAttributeAttributeSequenceItem(lhs.Normalized, rhs.Normalized)
				if err != nil {
					return SequenceItem{}, err
				}
				evalStack = append(evalStack, item)
			} else if lhs.Token == ENTITY && rhs.Token == ATTRIBUTE {
				if e.es == nil {
					return SequenceItem{}, fmt.Errorf("invalid attribute access (no entities available): %q (%v)", s.Token, s.Token)
				} else {
					item, err := e.getEntityAttributeSequenceItem(lhs.Normalized, rhs.Normalized)
					if err != nil {
						return SequenceItem{}, err
					}
					evalStack = append(evalStack, item)
				}
			} else if lhs.Token == ATTRIBUTE && rhs.Token == ATTRIBUTE {
				item, err := e.getAttributeAttributeSequenceItem(lhs.Normalized, rhs.Normalized)
				if err != nil {
					return SequenceItem{}, err
				}
				evalStack = append(evalStack, item)
			} else if rhs.Token == FUNCTION {
				if rhs.Normalized == "contains" {
					actualLhs := evalStack[len(evalStack)-1]
					evalStack = evalStack[:len(evalStack)-1]
					if actualLhs.Token != SET {
						return SequenceItem{}, fmt.Errorf("unexpected use of contains function")
					}
					var actualLhsSet []interface{}
					err := json.Unmarshal([]byte(actualLhs.Normalized), &actualLhsSet)
					if err != nil {
						return SequenceItem{}, err
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
						if actualLhs.Token != SET {
							return SequenceItem{}, fmt.Errorf("unexpected use of contains function")
						}
						var actualLhsSet []interface{}
						err := json.Unmarshal([]byte(actualLhs.Normalized), &actualLhsSet)
						if err != nil {
							return SequenceItem{}, err
						}
						var actualRhsSet []interface{}
						err = json.Unmarshal([]byte(lhs.Normalized), &actualRhsSet)
						if err != nil {
							return SequenceItem{}, err
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
						if actualLhs.Token != SET {
							return SequenceItem{}, fmt.Errorf("unexpected use of contains function")
						}
						var actualLhsSet []interface{}
						err := json.Unmarshal([]byte(actualLhs.Normalized), &actualLhsSet)
						if err != nil {
							return SequenceItem{}, err
						}
						var actualRhsSet []interface{}
						err = json.Unmarshal([]byte(lhs.Normalized), &actualRhsSet)
						if err != nil {
							return SequenceItem{}, err
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
						return SequenceItem{}, fmt.Errorf("unknown function: %s", rhs.Literal)
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

						_, ipNet, err := net.ParseCIDR(lhs.Normalized)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("invalid IP")
						}
						_, insideIpNet, err := net.ParseCIDR(insideRange.Normalized)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("invalid IP")
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
							return SequenceItem{}, fmt.Errorf("invalid IP")
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
							return SequenceItem{}, fmt.Errorf("invalid IP")
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
						return SequenceItem{}, fmt.Errorf("unknown IP function: %s", rhs.Literal)
					}
				} else if lhs.Token == DECIMAL {
					if rhs.Normalized == "lessThan" {
						actualLhs := evalStack[len(evalStack)-1]
						evalStack = evalStack[:len(evalStack)-1]

						lhsD, err := strconv.ParseFloat(actualLhs.Normalized, 64)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("error parsing decimal")
						}
						rhsD, err := strconv.ParseFloat(lhs.Normalized, 64)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("error parsing decimal")
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

						lhsD, err := strconv.ParseFloat(actualLhs.Normalized, 64)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("error parsing decimal")
						}
						rhsD, err := strconv.ParseFloat(lhs.Normalized, 64)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("error parsing decimal")
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

						lhsD, err := strconv.ParseFloat(actualLhs.Normalized, 64)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("error parsing decimal")
						}
						rhsD, err := strconv.ParseFloat(lhs.Normalized, 64)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("error parsing decimal")
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

						lhsD, err := strconv.ParseFloat(actualLhs.Normalized, 64)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("error parsing decimal")
						}
						rhsD, err := strconv.ParseFloat(lhs.Normalized, 64)
						if err != nil {
							return SequenceItem{}, fmt.Errorf("error parsing decimal")
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
						return SequenceItem{}, fmt.Errorf("unknown decimal function: %s", rhs.Literal)
					}
				} else {
					return SequenceItem{}, fmt.Errorf("unknown function: %s", rhs.Literal)
				}
			} else {
				return SequenceItem{}, fmt.Errorf("invalid period use, unknown function or attribute access: %q (%v)", lhs.Token, lhs.Token)
			}
		case RIGHT_SQB:
			var set []interface{}

			rhs = evalStack[len(evalStack)-1]
			evalStack = evalStack[:len(evalStack)-1]
			for rhs.Token != LEFT_SQB {
				set = append(set, rhs.Normalized)
				rhs = evalStack[len(evalStack)-1]
				evalStack = evalStack[:len(evalStack)-1]
			}

			b, err := json.Marshal(set)
			if err != nil {
				return SequenceItem{}, fmt.Errorf("error whilst processing set")
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

			if lhs.Token == DBLQUOTESTR {
				if rhs.Token == DBLQUOTESTR {
					matched, stopped := match.MatchLimit(lhs.Normalized, rhs.Normalized, 100)
					if stopped {
						return SequenceItem{}, fmt.Errorf("string match too complex")
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
				return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case IN:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

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
								return SequenceItem{}, err
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
				return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case HAS:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

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
							return SequenceItem{}, err
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
					return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
				}
			} else {
				return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case LT, LTE, GT, GTE, PLUS, DASH, MULTIPLIER:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == LONG {
				if rhs.Token == LONG {
					lhsL, err := strconv.ParseInt(lhs.Normalized, 10, 64)
					if err != nil {
						return SequenceItem{}, err
					}
					rhsL, err := strconv.ParseInt(rhs.Normalized, 10, 64)
					if err != nil {
						return SequenceItem{}, err
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
					return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
				}
			} else {
				return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case EQUALITY:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

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
						return SequenceItem{}, fmt.Errorf("invalid ip")
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
						return SequenceItem{}, fmt.Errorf("invalid ip")
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
						return SequenceItem{}, fmt.Errorf("invalid ip")
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
						return SequenceItem{}, fmt.Errorf("invalid ip")
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

			if lhs.Token == TRUE || lhs.Token == FALSE && rhs.Token == TRUE || rhs.Token == FALSE {
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
				return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case OR:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == TRUE || lhs.Token == FALSE && rhs.Token == TRUE || rhs.Token == FALSE {
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
				return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		default:
			return SequenceItem{}, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
		}
	}

	if len(evalStack) != 1 {
		return SequenceItem{}, fmt.Errorf("invalid stack state")
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
