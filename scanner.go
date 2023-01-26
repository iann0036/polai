package polai

import (
	"bufio"
	"bytes"
	"io"
)

// Scanner represents a lexical scanner.
type Scanner struct {
	r *bufio.Reader
}

// NewScanner returns a new instance of Scanner.
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{r: bufio.NewReader(r)}
}

// Scan returns the next token and literal value.
func (s *Scanner) Scan() (tok Token, lit string) {
	// Read the next rune.
	ch := s.read()
	lit = string(ch)

	// If we see whitespace then consume all contiguous whitespace.
	// If we see a letter then consume as an ident or reserved word.
	// If we see a digit then consume as a number.
	if isWhitespace(ch) {
		s.unread()
		return s.scanWhitespace()
	} else if isLetter(ch) {
		s.unread()
		return s.scanIdent()
	} else if isDigit(ch) {
		ch = s.read()
		for isDigit(ch) {
			lit += string(ch)
			ch = s.read()
		}
		s.unread()
		return LONG, lit
	}

	// Otherwise read the individual character.
	switch ch {
	case eof:
		return EOF, ""
	case ',':
		return COMMA, lit
	case '(':
		return LEFT_PAREN, lit
	case ')':
		return RIGHT_PAREN, lit
	case '[':
		return LEFT_SQB, lit
	case ']':
		return RIGHT_SQB, lit
	case '{':
		return LEFT_BRACE, lit
	case '}':
		return RIGHT_BRACE, lit
	case ';':
		return SEMICOLON, lit
	case '+':
		return PLUS, lit
	case '*':
		return MULTIPLIER, lit
	case '.':
		return PERIOD, lit
	case '<':
		ch = s.read()
		if ch == '=' {
			lit += string(ch)
			return LTE, lit
		}
		s.unread()

		return LT, lit
	case '>':
		ch = s.read()
		if ch == '=' {
			lit += string(ch)
			return GTE, lit
		}
		s.unread()

		return GT, lit
	case '-':
		ch = s.read()
		if !isDigit(ch) {
			s.unread()
			return DASH, lit
		}
		lit += string(ch)
		ch = s.read()
		for isDigit(ch) {
			lit += string(ch)
			ch = s.read()
		}
		s.unread()
		return LONG, lit
	case '"':
		for {
			ch = s.read()
			lit += string(ch)
			if ch == '"' {
				break
			}
			if ch == '\\' {
				ch = s.read()
				lit += string(ch)
			}
			if ch == rune(0) {
				return ILLEGAL, lit
			}
		}
		return DBLQUOTESTR, lit
	case '=':
		ch = s.read()
		lit += string(ch)
		if ch == '=' {
			return EQUALITY, lit
		}
	case '!':
		ch = s.read()
		lit += string(ch)
		if ch == '=' {
			return INEQUALITY, lit
		}
		s.unread()
		return EXCLAMATION, lit
	case ':':
		ch = s.read()
		lit += string(ch)
		if ch == ':' {
			return NAMESPACE, lit
		}
	case '&':
		ch = s.read()
		lit += string(ch)
		if ch == '&' {
			return AND, lit
		}
	case '|':
		ch = s.read()
		lit += string(ch)
		if ch == '|' {
			return OR, lit
		}
	case '/':
		ch = s.read()
		lit += string(ch)
		if ch == '/' {
			ch = s.read()
			for ch != '\n' && ch != eof {
				lit += string(ch)
				ch = s.read()
			}
			s.unread()
			return COMMENT, lit
		}
	}

	return ILLEGAL, lit
}

// scanWhitespace consumes the current rune and all contiguous whitespace.
func (s *Scanner) scanWhitespace() (tok Token, lit string) {
	// Create a buffer and read the current character into it.
	var buf bytes.Buffer
	buf.WriteRune(s.read())

	// Read every subsequent whitespace character into the buffer.
	// Non-whitespace characters and EOF will cause the loop to exit.
	for {
		if ch := s.read(); ch == eof {
			break
		} else if !isWhitespace(ch) {
			s.unread()
			break
		} else {
			buf.WriteRune(ch)
		}
	}

	return WHITESPC, buf.String()
}

// scanIdent consumes the current rune and all contiguous ident runes.
func (s *Scanner) scanIdent() (tok Token, lit string) {
	// Create a buffer and read the current character into it.
	var buf bytes.Buffer
	buf.WriteRune(s.read())

	// Read every subsequent ident character into the buffer.
	// Non-ident characters and EOF will cause the loop to exit.
	for {
		if ch := s.read(); ch == eof {
			break
		} else if !isLetter(ch) && !isDigit(ch) && ch != '_' {
			s.unread()
			break
		} else {
			_, _ = buf.WriteRune(ch)
		}
	}

	// If the string matches a keyword then return that keyword.
	switch buf.String() {
	case "permit":
		return PERMIT, buf.String()
	case "forbid":
		return FORBID, buf.String()
	case "principal":
		return PRINCIPAL, buf.String()
	case "action":
		return ACTION, buf.String()
	case "resource":
		return RESOURCE, buf.String()
	case "context":
		return CONTEXT, buf.String()
	case "in":
		return IN, buf.String()
	case "when":
		return WHEN, buf.String()
	case "unless":
		return UNLESS, buf.String()
	case "has":
		return HAS, buf.String()
	case "like":
		return LIKE, buf.String()
	case "if":
		return IF, buf.String()
	case "then":
		return THEN, buf.String()
	case "else":
		return ELSE, buf.String()
	case "true":
		return TRUE, buf.String()
	case "false":
		return FALSE, buf.String()
	}

	// Otherwise return as a regular identifier.
	return IDENT, buf.String()
}

// read reads the next rune from the buffered reader.
// Returns the rune(0) if an error occurs (or io.EOF is returned).
func (s *Scanner) read() rune {
	ch, _, err := s.r.ReadRune()
	if err != nil {
		return eof
	}
	return ch
}

// unread places the previously read rune back on the reader.
func (s *Scanner) unread() { _ = s.r.UnreadRune() }

// isWhitespace returns true if the rune is a space, tab, or newline.
func isWhitespace(ch rune) bool { return ch == ' ' || ch == '\t' || ch == '\n' }

// isLetter returns true if the rune is a letter.
func isLetter(ch rune) bool { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') }

// isDigit returns true if the rune is a digit.
func isDigit(ch rune) bool { return (ch >= '0' && ch <= '9') }

// eof represents a marker rune for the end of the reader.
var eof = rune(0)
