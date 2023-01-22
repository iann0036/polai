package polai_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/iann0036/polai"
)

// Ensure the evaluator produces correct results.
func TestEvaluator_EvaluateStatement(t *testing.T) {
	var tests = []struct {
		s              string
		expectedResult bool
		principal      string
		action         string
		resource       string
		context        string
		entities       string
		err            string
	}{
		// Basic permit
		{
			s: `
			permit (
				principal,
				action,
				resource
			);`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Basic forbid
		{
			s: `
			forbid (
				principal,
				action,
				resource
			);`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Multiple statements
		{
			s: `
			permit (
				principal,
				action,
				resource
			);
			forbid (
				principal,
				action,
				resource
			);`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Comments
		{
			s: `
			// comment stuff
			permit (
				// comment stuff
				principal, // comment stuff
				action,
				resource // comment stuff
			); // comment stuff`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Scope with equality
		{
			s: `
			permit (
				principal == Namespace::"Identifier",
				action == Namespace2::"Identifier2",
				resource == Namespace3::"Identifier3"
			);`,
			principal:      "Namespace::\"Identifier\"",
			action:         "Namespace2::\"Identifier2\"",
			resource:       "Namespace3::\"Identifier3\"",
			expectedResult: true,
		},

		// Scope with in set
		{
			s: `
			permit (
				principal,
				action in [ Namespace::"Identifier", Namespace2::"Identifier2" ],
				resource
			);`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Namespace::\"Identifier\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Scope with in entity
		{
			s: `
			permit (
				principal in Namespace::"Identifier",
				action in Namespace2::"Identifier2",
				resource in Namespace3::"Identifier3"
			);`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Scope with in entity (self)
		{
			s: `
			permit (
				principal in Namespace::"Identifier",
				action in Namespace2::"Identifier2",
				resource in Namespace3::"Identifier3"
			);`,
			principal:      "Namespace::\"Identifier\"",
			action:         "Namespace2::\"Identifier2\"",
			resource:       "Namespace3::\"Identifier3\"",
			expectedResult: true,
		},

		// Basic when with int equality
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				123 == 123
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Basic when with literal true
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				true
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Basic when with int equality (failure)
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				234 == 235
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Basic with negation
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				!true
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Basic with negation 2
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				!(2 > 3)
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Basic with negation 3
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				!(principal == Principal::"MyPrincipal")
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Mix eventual types
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				2>3 || 345 == 345 && true
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Complex long operators
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				2 > 1 && 3 < 4 && 1 != 2 && 2 == 2 && 1 >= 1 && 2 <= 3
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Boolean logic with parameter groups
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				(false || true) && (true && true)
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Math order of operations
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				2 + 3 * 4 + 5 == 19
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Entity equality
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				Principal::"MyPrincipal" == Principal::"MyPrincipal"
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Entity inequality
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				Principal::"MyPrincipal" != Principal::"MyPrincipal"
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Entity in (self)
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				Principal::"MyPrincipal" in Principal::"MyPrincipal"
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Mismatch type equality
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				Principal::"MyPrincipal" == 123
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Mismatch type inequality
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				Principal::"MyPrincipal" != 123
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// in operator (scope)
		{
			s: `
			permit (
				principal in Principal::"Parent",
				action in Action::"Parent",
				resource in Resource::"Parent"
			);`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"parents": [
						"Principal::\"Parent\""
					]
				},
				{
					"uid": "Action::\"MyAction\"",
					"parents": [
						"Action::\"Parent\""
					]
				},
				{
					"uid": "Resource::\"MyResource\"",
					"parents": [
						"Resource::\"Parent\""
					]
				}
			]`,
			expectedResult: true,
		},

		// in operator (scope, invariant)
		{
			s: `
			permit (
				principal in Principal::"MyPrincipal",
				action in Action::"MyAction",
				resource in Resource::"MyResource"
			);`,
			principal: "Principal::\"Parent\"",
			action:    "Action::\"Parent\"",
			resource:  "Resource::\"Parent\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"parents": [
						"Principal::\"Parent\""
					]
				},
				{
					"uid": "Action::\"MyAction\"",
					"parents": [
						"Action::\"Parent\""
					]
				},
				{
					"uid": "Resource::\"MyResource\"",
					"parents": [
						"Resource::\"Parent\""
					]
				}
			]`,
			expectedResult: false,
		},

		// in operator (condition)
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				principal in Principal::"Parent" &&
				action in Action::"Parent" &&
				resource in Resource::"Parent"
			};`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"parents": [
						"Principal::\"Parent\""
					]
				},
				{
					"uid": "Action::\"MyAction\"",
					"parents": [
						"Action::\"Parent\""
					]
				},
				{
					"uid": "Resource::\"MyResource\"",
					"parents": [
						"Resource::\"Parent\""
					]
				}
			]`,
			expectedResult: true,
		},

		// in operator (scope, deep)
		{
			s: `
			permit (
				principal in Principal::"Grandparent",
				action in Action::"Grandparent",
				resource in Resource::"Grandparent"
			);`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"parents": [
						"Principal::\"Parent\""
					]
				},
				{
					"uid": "Action::\"MyAction\"",
					"parents": [
						"Action::\"Parent\""
					]
				},
				{
					"uid": "Resource::\"MyResource\"",
					"parents": [
						"Resource::\"Parent\""
					]
				},
				{
					"uid": "Principal::\"Parent\"",
					"parents": [
						"Principal::\"Grandparent\""
					]
				},
				{
					"uid": "Action::\"Parent\"",
					"parents": [
						"Action::\"Grandparent\""
					]
				},
				{
					"uid": "Resource::\"Parent\"",
					"parents": [
						"Resource::\"Grandparent\""
					]
				}
			]`,
			expectedResult: true,
		},

		// in operator (condition, deep)
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				principal in Principal::"Grandparent" &&
				action in Action::"Grandparent" &&
				resource in Resource::"Grandparent"
			};`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"parents": [
						"Principal::\"Parent\""
					]
				},
				{
					"uid": "Action::\"MyAction\"",
					"parents": [
						"Action::\"Parent\""
					]
				},
				{
					"uid": "Resource::\"MyResource\"",
					"parents": [
						"Resource::\"Parent\""
					]
				},
				{
					"uid": "Principal::\"Parent\"",
					"parents": [
						"Principal::\"Grandparent\""
					]
				},
				{
					"uid": "Action::\"Parent\"",
					"parents": [
						"Action::\"Grandparent\""
					]
				},
				{
					"uid": "Resource::\"Parent\"",
					"parents": [
						"Resource::\"Grandparent\""
					]
				}
			]`,
			expectedResult: true,
		},

		// context basic
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				context.s == "abc"
			};`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			context: `
			{
				"s": "abc",
				"i": 123,
				"b": true,
				"r": {
					"s": "abc",
					"i": 123,
					"b": true,
					"l": ["def"]
				},
				"l": ["def"]
			}`,
			expectedResult: true,
		},

		// context
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				context.s == "abc" &&
				context.i > 100 &&
				context.b != false
			};`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			context: `
			{
				"s": "abc",
				"i": 123,
				"b": true,
				"r": {
					"s": "abc",
					"i": 123,
					"b": true,
					"l": ["def"]
				},
				"l": ["def"]
			}`,
			expectedResult: true,
		},

		// entity attributes
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				principal.s == "abc" &&
				principal.i > 100 &&
				principal.b != false
			};`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"r": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				},
				{
					"uid": "Action::\"MyAction\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"m": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				},
				{
					"uid": "Resource::\"MyResource\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"m": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				}
			]`,
			expectedResult: true,
		},

		// entity attributes (deep)
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				principal.r.s == "abc" &&
				principal.r.i > 100 &&
				principal.r.b != false
			};`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"r": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				},
				{
					"uid": "Action::\"MyAction\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"m": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				},
				{
					"uid": "Resource::\"MyResource\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"m": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				}
			]`,
			expectedResult: true,
		},

		// entity has
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				principal has s
			};`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"r": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				},
				{
					"uid": "Action::\"MyAction\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"m": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				},
				{
					"uid": "Resource::\"MyResource\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"m": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				}
			]`,
			expectedResult: true,
		},

		// IP Function
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				ip("10.0.0.1") == ip("10.0.0.1")
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// IP Function (negate)
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				ip("10.0.0.1") == ip("10.0.0.2")
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// IP Function isInRange
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				ip("10.0.0.5/24").isInRange(ip("10.0.2.7/8"))
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// IP Function basic bool checks
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				ip("10.0.0.1").isIpv4() &&
				ip("2001:0db8:85a3::8a2e:0370:7334").isIpv6() &&
				ip("127.0.0.1").isLoopback() &&
				ip("224.0.0.1").isMulticast()
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Decimal Function
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				decimal("12.34") == decimal("12.340")
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// Decimal Function (negate)
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				decimal("12.34") == decimal("12.341")
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Decimal Function basic bool checks
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				decimal("12.34").lessThan(decimal("20")) &&
				decimal("12.34").lessThanOrEqual(decimal("12.34")) &&
				decimal("12.34").greaterThan(decimal("10")) &&
				decimal("12.34").greaterThanOrEqual(decimal("12.34"))
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// contains from attribute
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				principal.l.contains("def") &&
				principal.l.containsAll(principal.l) &&
				principal.l.containsAny(principal.l)
			};`,
			principal: "Principal::\"MyPrincipal\"",
			action:    "Action::\"MyAction\"",
			resource:  "Resource::\"MyResource\"",
			entities: `
			[
				{
					"uid": "Principal::\"MyPrincipal\"",
					"attrs": {
						"s": "abc",
						"i": 123,
						"b": true,
						"r": {
							"s": "abc",
							"i": 123,
							"b": true,
							"l": ["def"]
						},
						"l": ["def"]
					}
				}
			]`,
			expectedResult: true,
		},

		// contains from square brackets
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				[1, 2, 3].contains(2) &&
				[1, 2, 3].containsAll([1, 2]) &&
				[1, 2, 3].containsAny([5, 4, 3])
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: true,
		},

		// contains from square brackets (negate)
		{
			s: `
			permit (
				principal,
				action,
				resource
			) when {
				[1, 2, 3].containsAny([6, 5, 4])
			};`,
			principal:      "Principal::\"MyPrincipal\"",
			action:         "Action::\"MyAction\"",
			resource:       "Resource::\"MyResource\"",
			expectedResult: false,
		},

		// Errors
		{s: `foo`, err: `found "foo", expected permit or forbid`},
	}

	for i, tt := range tests {
		e := polai.NewEvaluator(strings.NewReader(tt.s))
		if tt.entities != "" {
			e.SetEntities(strings.NewReader(tt.entities))
		}
		result, err := e.Evaluate(tt.principal, tt.action, tt.resource, tt.context)
		if !reflect.DeepEqual(tt.err, errstring(err)) {
			t.Errorf("%d. %q: error mismatch:\n  exp=%s\n  got=%s\n\n", i, tt.s, tt.err, err)
		} else if tt.err == "" && tt.expectedResult != result {
			t.Errorf("%d. %q\n\result mismatch:\n\nexp=%#v\n\ngot=%#v\n\n", i, tt.s, tt.expectedResult, result)
		}
	}
}
