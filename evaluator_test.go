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
