package polai_test

import (
	"strings"
	"testing"

	"github.com/iann0036/polai"
)

// Ensure the scanner can scan tokens correctly.
func TestScanner_Scan(t *testing.T) {
	var tests = []struct {
		s   string
		tok polai.Token
		lit string
	}{
		// Special tokens (EOF, ILLEGAL, WS)
		{s: ``, tok: polai.EOF},
		{s: `#`, tok: polai.ILLEGAL, lit: `#`},
		{s: ` `, tok: polai.WHITESPC, lit: " "},
		{s: "\t", tok: polai.WHITESPC, lit: "\t"},
		{s: "\n", tok: polai.WHITESPC, lit: "\n"},

		// Misc characters
		{s: `,`, tok: polai.COMMA, lit: ","},

		// Identifiers
		{s: `foo`, tok: polai.IDENT, lit: `foo`},
		{s: `Zx12_3U_-`, tok: polai.IDENT, lit: `Zx12_3U_`},

		// Keywords
		{s: `permit`, tok: polai.PERMIT, lit: "permit"},
		{s: `forbid`, tok: polai.FORBID, lit: "forbid"},
	}

	for i, tt := range tests {
		s := polai.NewScanner(strings.NewReader(tt.s))
		tok, lit := s.Scan()
		if tt.tok != tok {
			t.Errorf("%d. %q token mismatch: exp=%q got=%q <%q>", i, tt.s, tt.tok, tok, lit)
		} else if tt.lit != lit {
			t.Errorf("%d. %q literal mismatch: exp=%q got=%q", i, tt.s, tt.lit, lit)
		}
	}
}
