package polai

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
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
	PERIOD:     5,
}

var LEFT_ASSOCIATIVE = map[Token]bool{
	LT:     true,
	LTE:    true,
	GT:     true,
	GTE:    true,
	IN:     true,
	DASH:   true,
	PERIOD: true,
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
				if stmtCondition.Type == WHEN && !condEvalResult {
					continue ForbidLoop
				} else if stmtCondition.Type == UNLESS && condEvalResult {
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
				if stmtCondition.Type == WHEN && !condEvalResult {
					continue PermitLoop
				} else if stmtCondition.Type == UNLESS && condEvalResult {
					continue PermitLoop
				}
			}

			return true, nil // explicit allow
		}
	}

	return false, nil // implicit deny
}

func (e *Evaluator) condEval(cc ConditionClause, principal, action, resource, context string) (bool, error) {
	var outputQueue []SequenceItem
	var operatorStack []SequenceItem

	// restructure to rpn using shunting yard
	for _, s := range cc.Sequence {
		switch s.Token {
		case TRUE, FALSE, INT, DBLQUOTESTR, ENTITY, ATTRIBUTE:
			outputQueue = append(outputQueue, s)
		case PRINCIPAL:
			s.Token = ENTITY
			s.Literal = principal
			outputQueue = append(outputQueue, s)
		case ACTION:
			s.Token = ENTITY
			s.Literal = action
			outputQueue = append(outputQueue, s)
		case RESOURCE:
			s.Token = ENTITY
			s.Literal = resource
			outputQueue = append(outputQueue, s)
		case CONTEXT:
			s.Literal = context
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
		case EQUALITY, INEQUALITY, AND, OR, LT, LTE, GT, GTE, PLUS, DASH, MULTIPLIER, IN, PERIOD:
			for len(operatorStack) > 0 && OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] != 0 && (OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] > OP_PRECEDENCE[s.Token] || (OP_PRECEDENCE[operatorStack[len(operatorStack)-1].Token] == OP_PRECEDENCE[s.Token] && LEFT_ASSOCIATIVE[s.Token])) {
				pop := operatorStack[len(operatorStack)-1]
				operatorStack = operatorStack[:len(operatorStack)-1]
				outputQueue = append(outputQueue, pop)
			}
			operatorStack = append(operatorStack, s)
		default:
			return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
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

	var evalStack []SequenceItem
	var lhs SequenceItem
	var rhs SequenceItem
	for _, s := range outputQueue {
		switch s.Token {
		case TRUE, FALSE, INT, DBLQUOTESTR, ENTITY, ATTRIBUTE, CONTEXT:
			evalStack = append(evalStack, s)
		case PERIOD:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == ENTITY {
				if rhs.Token == ATTRIBUTE {
					if e.es == nil {
						return false, fmt.Errorf("invalid attribute access (no entities available): %q (%v)", s.Token, s.Token)
					} else {
						item, err := e.getEntityAttributeSequenceItem(lhs.Literal, rhs.Literal)
						if err != nil {
							return false, err
						}
						evalStack = append(evalStack, item)
					}
				} else {
					return false, fmt.Errorf("invalid attribute access: %q (%v)", rhs.Token, rhs.Token)
				}
			} else if lhs.Token == ATTRIBUTE {
				if rhs.Token == ATTRIBUTE {
					item, err := e.getAttributeAttributeSequenceItem(lhs.Literal, rhs.Literal)
					if err != nil {
						return false, err
					}
					evalStack = append(evalStack, item)
				} else {
					return false, fmt.Errorf("invalid attribute access: %q (%v)", rhs.Token, rhs.Token)
				}
			} else {
				return false, fmt.Errorf("invalid period use: %q (%v)", lhs.Token, lhs.Token)
			}
		case IN:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == ENTITY {
				if rhs.Token == ENTITY {
					if lhs.Literal == rhs.Literal {
						evalStack = append(evalStack, SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						if e.es == nil {
							evalStack = append(evalStack, SequenceItem{
								Token:   FALSE,
								Literal: "false",
							})
						} else {
							descendants, err := e.es.GetEntityDescendents([]string{rhs.Literal})
							if err != nil {
								return false, err
							}
							if containsEntity(descendants, lhs.Literal) {
								evalStack = append(evalStack, SequenceItem{
									Token:   TRUE,
									Literal: "true",
								})
							} else {
								evalStack = append(evalStack, SequenceItem{
									Token:   FALSE,
									Literal: "false",
								})
							}
						}
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				}
			} else {
				return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case LT, LTE, GT, GTE, PLUS, DASH, MULTIPLIER:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == INT {
				if rhs.Token == INT {
					lhsL, err := strconv.ParseInt(lhs.Literal, 10, 64)
					if err != nil {
						return false, err
					}
					rhsL, err := strconv.ParseInt(rhs.Literal, 10, 64)
					if err != nil {
						return false, err
					}

					if s.Token == LT {
						if lhsL < rhsL {
							evalStack = append(evalStack, SequenceItem{
								Token:   TRUE,
								Literal: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:   FALSE,
								Literal: "false",
							})
						}
					} else if s.Token == LTE {
						if lhsL <= rhsL {
							evalStack = append(evalStack, SequenceItem{
								Token:   TRUE,
								Literal: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:   FALSE,
								Literal: "false",
							})
						}
					} else if s.Token == GT {
						if lhsL > rhsL {
							evalStack = append(evalStack, SequenceItem{
								Token:   TRUE,
								Literal: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:   FALSE,
								Literal: "false",
							})
						}
					} else if s.Token == GTE {
						if lhsL >= rhsL {
							evalStack = append(evalStack, SequenceItem{
								Token:   TRUE,
								Literal: "true",
							})
						} else {
							evalStack = append(evalStack, SequenceItem{
								Token:   FALSE,
								Literal: "false",
							})
						}
					} else if s.Token == PLUS {
						evalStack = append(evalStack, SequenceItem{
							Token:   INT,
							Literal: strconv.FormatInt(lhsL+rhsL, 10),
						})
					} else if s.Token == DASH {
						evalStack = append(evalStack, SequenceItem{
							Token:   INT,
							Literal: strconv.FormatInt(lhsL-rhsL, 10),
						})
					} else if s.Token == MULTIPLIER {
						evalStack = append(evalStack, SequenceItem{
							Token:   INT,
							Literal: strconv.FormatInt(lhsL*rhsL, 10),
						})
					}
				} else {
					return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
				}
			} else {
				return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case EQUALITY:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == TRUE || lhs.Token == FALSE {
				if rhs.Token == lhs.Token {
					evalStack = append(evalStack, SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				}
			} else if lhs.Token == INT {
				if rhs.Token == INT {
					lhsL, err := strconv.ParseInt(lhs.Literal, 10, 64)
					if err != nil {
						return false, err
					}
					rhsL, err := strconv.ParseInt(rhs.Literal, 10, 64)
					if err != nil {
						return false, err
					}
					if lhsL == rhsL {
						evalStack = append(evalStack, SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				}
			} else if lhs.Token == DBLQUOTESTR {
				if rhs.Token == DBLQUOTESTR {
					if lhs.Literal == rhs.Literal {
						evalStack = append(evalStack, SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				}
			} else if lhs.Token == ENTITY {
				if rhs.Token == ENTITY {
					if lhs.Literal == rhs.Literal {
						evalStack = append(evalStack, SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				}
			} else {
				return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case INEQUALITY:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == TRUE || lhs.Token == FALSE {
				if rhs.Token == lhs.Token {
					evalStack = append(evalStack, SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				}
			} else if lhs.Token == INT {
				if rhs.Token == INT {
					lhsL, err := strconv.ParseInt(lhs.Literal, 10, 64)
					if err != nil {
						return false, err
					}
					rhsL, err := strconv.ParseInt(rhs.Literal, 10, 64)
					if err != nil {
						return false, err
					}
					if lhsL == rhsL {
						evalStack = append(evalStack, SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				}
			} else if lhs.Token == DBLQUOTESTR {
				if rhs.Token == DBLQUOTESTR {
					if lhs.Literal == rhs.Literal {
						evalStack = append(evalStack, SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				}
			} else if lhs.Token == ENTITY {
				if rhs.Token == ENTITY {
					if lhs.Literal == rhs.Literal {
						evalStack = append(evalStack, SequenceItem{
							Token:   FALSE,
							Literal: "false",
						})
					} else {
						evalStack = append(evalStack, SequenceItem{
							Token:   TRUE,
							Literal: "true",
						})
					}
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				}
			} else {
				return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case AND:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == TRUE || lhs.Token == FALSE && rhs.Token == TRUE || rhs.Token == FALSE {
				if lhs.Token == TRUE && rhs.Token == TRUE {
					evalStack = append(evalStack, SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				}
			} else {
				return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		case OR:
			rhs = evalStack[len(evalStack)-1]
			lhs = evalStack[len(evalStack)-2]
			evalStack = evalStack[:len(evalStack)-2]

			if lhs.Token == TRUE || lhs.Token == FALSE && rhs.Token == TRUE || rhs.Token == FALSE {
				if lhs.Token == TRUE || rhs.Token == TRUE {
					evalStack = append(evalStack, SequenceItem{
						Token:   TRUE,
						Literal: "true",
					})
				} else {
					evalStack = append(evalStack, SequenceItem{
						Token:   FALSE,
						Literal: "false",
					})
				}
			} else {
				return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
			}
		default:
			return false, fmt.Errorf("unknown token: %q (%v)", s.Token, s.Token)
		}
	}

	if len(evalStack) != 1 {
		return false, fmt.Errorf("invalid stack state")
	}

	if evalStack[0].Token == TRUE {
		return true, nil
	} else if evalStack[0].Token == FALSE {
		return false, nil
	}

	return false, fmt.Errorf("invalid stack state")
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
						return SequenceItem{
							Token:   DBLQUOTESTR,
							Literal: *attribute.StringValue,
						}, nil
					}
					if attribute.LongValue != nil {
						return SequenceItem{
							Token:   INT,
							Literal: strconv.FormatInt(*attribute.LongValue, 10),
						}, nil
					}
					if attribute.BooleanValue != nil {
						if *attribute.BooleanValue {
							return SequenceItem{
								Token:   TRUE,
								Literal: "true",
							}, nil
						} else {
							return SequenceItem{
								Token:   FALSE,
								Literal: "false",
							}, nil
						}
					}
					if attribute.RecordValue != nil {
						b, err := json.Marshal(*attribute.RecordValue)
						if err != nil {
							return SequenceItem{}, err
						}
						return SequenceItem{
							Token:   ATTRIBUTE,
							Literal: string(b),
						}, nil
					}
					if attribute.SetValue != nil {
						b, err := json.Marshal(*attribute.SetValue)
						if err != nil {
							return SequenceItem{}, err
						}
						return SequenceItem{
							Token:   SET,
							Literal: string(b),
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
					Token:   INT,
					Literal: strconv.FormatInt(val, 10),
				}, nil
			case int64:
				val := attrVal.(int64)
				return SequenceItem{
					Token:   INT,
					Literal: strconv.FormatInt(val, 10),
				}, nil
			case float64:
				val := int64(attrVal.(float64))
				return SequenceItem{
					Token:   INT,
					Literal: strconv.FormatInt(val, 10),
				}, nil
			case string:
				val := attrVal.(string)
				return SequenceItem{
					Token:   DBLQUOTESTR,
					Literal: val,
				}, nil
			case bool:
				val := attrVal.(bool)
				if val {
					return SequenceItem{
						Token:   TRUE,
						Literal: "true",
					}, nil
				} else {
					return SequenceItem{
						Token:   FALSE,
						Literal: "false",
					}, nil
				}
			case map[string]interface{}:
				val := attrVal.(map[string]interface{})
				b, err := json.Marshal(val)
				if err != nil {
					return SequenceItem{}, err
				}
				return SequenceItem{
					Token:   ATTRIBUTE,
					Literal: string(b),
				}, nil
			case []interface{}:
				val := attrVal.([]interface{})
				b, err := json.Marshal(val)
				if err != nil {
					return SequenceItem{}, err
				}
				return SequenceItem{
					Token:   SET,
					Literal: string(b),
				}, nil
			default:
				return SequenceItem{}, fmt.Errorf("unknown type in attribute block: %v (%s)", attrVal, reflect.TypeOf(attrVal).String())
			}

		}
	}

	return SequenceItem{}, fmt.Errorf("attribute not set")
}
