<a href="https://godoc.org/github.com/iann0036/polai" title="GoDoc">
  <img src="https://godoc.org/github.com/iann0036/polai?status.svg">
</a>

# polai

> A Cedar policy language lexer, parser & evaluator

## Installation

```sh
$ go get github.com/iann0036/polai
```

Please add `-u` flag to update in the future.

## Usage

```go
package main

import (
    "fmt"
    "strings"

    "github.com/iann0036/polai"
)

func main() {
    e := polai.NewEvaluator(strings.NewReader(`
    permit (
        principal == User::"alice",
        action,
        resource == Folder::"My Folder"
    ) when {
        context.ssl == true
    };`))
    result, _ := e.Evaluate(`User::"alice"`, `Action::"listFiles"`, `Folder::"My Folder"`, `{
        "ssl": true
    }`)

    if result {
        fmt.Println("Authorized")
    } else {
        fmt.Println("Not Authorized")
    }
}
```

## Features

- [x] Policy language interpreter
- [x] Basic permit and forbid evaluation logic
- [x] Equality / inequality operator within `principal`, `action`, and `resource` within the scope block
- [x] Inheritance (`in`) within scope block
- [x] Basic set (`in`) for `action` within scope block
- [x] Basic when and unless evaluation logic
- [x] Logical operators for basic types (string, long, boolean) within condition block
- [x] Entity store interpreter
- [x] Inheritance (`in`) within condition block
- [x] Entity attributes evaluation
- [x] IP and Decimal extensions
- [x] Context object
- [x] Set operations
- [x] `has` operation
- [x] Logical not `!` operation
- [x] `like` operator
- [ ] if-then-else ternary
- [ ] `-` unary
- [ ] Enforce `Action::` namespace for actions
- [ ] `__expr` syntax in context

## License

This project is under MIT license. See the [LICENSE](LICENSE) file for the full license text.