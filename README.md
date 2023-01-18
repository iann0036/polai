<p align="center">
  <a href="https://godoc.org/github.com/iann0036/polai" title="GoDoc">
    <img src="https://godoc.org/github.com/iann0036/polai?status.svg">
  </a>
</p>

# polai

> A Cedar policy language lexer, parser & evaluator

## Installation

```sh
$ go get github.com/iann0036/polai
```

Please add `-u` flag to update in the future.

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
- [ ] Entity attributes evaluation
- [ ] IP and Decimal extensions
- [ ] `__expr` syntax in context
- [ ] Enforce `Action::` namespace for actions
- [ ] Context object
- [ ] Set operations

## License

This project is under MIT license. See the [LICENSE](LICENSE) file for the full license text.