package polai

// Token represents a lexical token.
type Token int

const (
	// Special tokens
	ILLEGAL Token = iota
	EOF
	WHITESPC

	// Literals
	IDENT       // unknown identifier
	INT         // 123 | -123
	DBLQUOTESTR // "...abc..."
	COMMENT     // // ...abc...

	ENTITY // Namespace::"ID"

	// Misc characters
	LEFT_PAREN  // (
	RIGHT_PAREN // )
	LEFT_SQB    // [
	RIGHT_SQB   // ]
	LEFT_BRACE  // {
	RIGHT_BRACE // }
	PERIOD      // .
	COMMA       // ,
	SEMICOLON   // ;
	EXCLAMATION // !
	LT          // <
	GT          // >
	DASH        // -
	PLUS        // +
	MULTIPLIER  // *

	// Misc
	NAMESPACE  // ::
	EQUALITY   // ==
	INEQUALITY // !=
	LTE        // <=
	GTE        // >=
	AND        // &&
	OR         // ||

	// Keywords
	PERMIT
	FORBID
	WHEN
	UNLESS
	TRUE
	FALSE
	IF
	THEN
	ELSE
	IN
	LIKE
	HAS
	PRINCIPAL
	ACTION
	RESOURCE
	CONTEXT
)
