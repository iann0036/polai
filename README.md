# polai

[![GoDoc](https://godoc.org/github.com/iann0036/polai?status.svg)](https://godoc.org/github.com/iann0036/polai)

A [Cedar](https://www.cedarpolicy.com/) policy language lexer, parser & evaluator.

## Installation

```sh
go get github.com/iann0036/polai
```

Please add `-u` flag to update in the future.

## Usage

### Basic Usage

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
        principal,
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

### Advanced Options

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
        principal,
        action,
        resource == Folder::"My Folder"
    ) when {
        if context.ssl == true && principal.hasTraining
        then true
        else principal.invalidproperty
    };`))

    e.AllowShortCircuiting = true // evaluation will fail when set to false

    e.SetEntities(strings.NewReader(`
    [
        {
            "uid": "User::\"alice\"",
            "attrs": {
                "hasTraining": true
            }
        },
        {
            "uid": "User::\"kate\"",
            "attrs": {
                "hasTraining": false
            }
        }
    ]`))

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
- [x] if-then-else ternary
- [x] Enforce `Action::` namespace for actions
- [x] `&&` and `||` short-circuiting
- [x] `if-then-else` short-circuiting
- [ ] Embedded `if-then-else`
- [ ] 4x limit on unary
- [ ] Syntactic constraint on multiply operator
- [ ] Anonymous records / sets
- [ ] `__entity` / `__extn` syntax in context / entities
- [ ] Policy templates

## License

This project is under MIT license. See the [LICENSE](LICENSE) file for the full license text.