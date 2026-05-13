# XSS Middleware

A [Gin](https://github.com/gin-gonic/gin) middleware that automatically sanitizes XSS from incoming HTTP requests before they reach your route handlers. Supports GET query params, JSON, form-encoded, and multipart form bodies.

XSS filtering is performed by [bluemonday](https://github.com/microcosm-cc/bluemonday). The default policy is `StrictPolicy`.

## Installation

```
go get github.com/codeskine/xss-middleware
go mod tidy
```

## Usage

### Defaults

Uses `StrictPolicy`. The `password` field is always skipped.

```go
package main

import (
    "github.com/gin-gonic/gin"
    xss "github.com/codeskine/xss-middleware"
)

func main() {
    r := gin.Default()
    r.Use(xss.New())

    r.GET("/ping", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "pong"})
    })
    r.Run()
}
```

### Custom policy and skip fields

```go
r.Use(xss.New(
    xss.WithUGCPolicy(),
    xss.SkipFields("token", "create_date"),
))
```

### Bring your own bluemonday policy

```go
p := bluemonday.NewPolicy()
p.AllowElements("b", "i", "em")

r.Use(xss.New(xss.WithPolicy(p)))
```

## Options

| Option | Description |
|--------|-------------|
| `WithStrictPolicy()` | Use `bluemonday.StrictPolicy` (default) |
| `WithUGCPolicy()` | Use `bluemonday.UGCPolicy` |
| `WithPolicy(p)` | Use a custom `*bluemonday.Policy` |
| `SkipFields(fields...)` | Skip sanitization for the named fields (`"password"` is always skipped) |

## What gets sanitized

| Request type | Content-Type |
|---|---|
| GET | query parameters |
| POST / PUT / PATCH | `application/json` |
| POST / PUT / PATCH | `application/x-www-form-urlencoded` |
| POST / PUT / PATCH | `multipart/form-data` (text fields only; file parts are passed through unchanged) |

All string values — including JSON object keys — are sanitized. Multi-value parameters are fully preserved.

## Contributing

- Open an issue before submitting a pull request.
- Add or update tests as appropriate.
- Run `gofmt -w .` before submitting.

## Acknowledgements

Forked from [dvwright/xss-mw](https://github.com/dvwright/xss-mw).  
XSS filtering by [microcosm-cc/bluemonday](https://github.com/microcosm-cc/bluemonday).
