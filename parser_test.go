package polai_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/iann0036/polai"
)

// Ensure the parser can parse strings into Statement ASTs.
func TestParser_ParseStatement(t *testing.T) {
	var tests = []struct {
		s     string
		stmts *[]polai.PolicyStatement
		err   string
	}{
		// Basic permit
		{
			s: `
			permit (
				principal,
				action,
				resource
			);`,
			stmts: &[]polai.PolicyStatement{
				{
					Effect:       polai.PERMIT,
					AnyPrincipal: true,
					AnyAction:    true,
					AnyResource:  true,
				},
			},
		},

		// Basic forbid
		{
			s: `
			forbid (
				principal,
				action,
				resource
			);`,
			stmts: &[]polai.PolicyStatement{
				{
					Effect:       polai.FORBID,
					AnyPrincipal: true,
					AnyAction:    true,
					AnyResource:  true,
				},
			},
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
			stmts: &[]polai.PolicyStatement{
				{
					Effect:       polai.PERMIT,
					AnyPrincipal: true,
					AnyAction:    true,
					AnyResource:  true,
				},
				{
					Effect:       polai.FORBID,
					AnyPrincipal: true,
					AnyAction:    true,
					AnyResource:  true,
				},
			},
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
			stmts: &[]polai.PolicyStatement{
				{
					Effect:       polai.PERMIT,
					AnyPrincipal: true,
					AnyAction:    true,
					AnyResource:  true,
				},
			},
		},

		// Scope with equality
		{
			s: `
			permit (
				principal == Namespace::"Identifier",
				action == Namespace2::"Identifier2",
				resource == Namespace3::"Identifier3"
			);`,
			stmts: &[]polai.PolicyStatement{
				{
					Effect:       polai.PERMIT,
					Principal:    "Namespace::\"Identifier\"",
					Actions:      []string{"Namespace2::\"Identifier2\""},
					Resource:     "Namespace3::\"Identifier3\"",
					AnyPrincipal: false,
					AnyAction:    false,
					AnyResource:  false,
				},
			},
		},

		// Scope with in set
		{
			s: `
			permit (
				principal,
				action in [ Namespace::"Identifier", Namespace2::"Identifier2" ],
				resource
			);`,
			stmts: &[]polai.PolicyStatement{
				{
					Effect:       polai.PERMIT,
					Actions:      []string{"Namespace::\"Identifier\"", "Namespace2::\"Identifier2\""},
					AnyPrincipal: true,
					AnyAction:    false,
					AnyResource:  true,
				},
			},
		},

		// Scope with in entity
		{
			s: `
			permit (
				principal in Namespace::"Identifier",
				action in Namespace2::"Identifier2",
				resource in Namespace3::"Identifier3"
			);`,
			stmts: &[]polai.PolicyStatement{
				{
					Effect:          polai.PERMIT,
					PrincipalParent: "Namespace::\"Identifier\"",
					ActionParent:    "Namespace2::\"Identifier2\"",
					ResourceParent:  "Namespace3::\"Identifier3\"",
					AnyPrincipal:    false,
					AnyAction:       false,
					AnyResource:     false,
				},
			},
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
			stmts: &[]polai.PolicyStatement{
				{
					Effect:       polai.PERMIT,
					AnyPrincipal: true,
					AnyAction:    true,
					AnyResource:  true,
					Conditions: []polai.ConditionClause{
						{
							Type: polai.WHEN,
							Sequence: []polai.SequenceItem{
								{Token: polai.INT, Literal: "123", IsEntity: false},
								{Token: polai.EQUALITY, Literal: "==", IsEntity: false},
								{Token: polai.INT, Literal: "123", IsEntity: false},
							},
						},
					},
				},
			},
		},

		// Errors
		{s: `foo`, err: `found "foo", expected permit or forbid`},
	}

	for i, tt := range tests {
		stmts, err := polai.NewParser(strings.NewReader(tt.s)).Parse()
		if !reflect.DeepEqual(tt.err, errstring(err)) {
			t.Errorf("%d. %q: error mismatch:\n  exp=%s\n  got=%s\n\n", i, tt.s, tt.err, err)
		} else if tt.err == "" && !reflect.DeepEqual(tt.stmts, stmts) {
			t.Errorf("%d. %q\n\nstmt mismatch:\n\nexp=%#v\n\ngot=%#v\n\n", i, tt.s, tt.stmts, stmts)
		}
	}
}

// errstring returns the string representation of an error.
func errstring(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
