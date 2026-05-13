# XSS Middleware

[![Go Version](https://img.shields.io/github/go-mod/go-version/codeskine/gin-gonic-xss-middleware)](https://go.dev/)
[![License](https://img.shields.io/github/license/codeskine/gin-gonic-xss-middleware)](./LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/codeskine/gin-gonic-xss-middleware/test.yml?branch=main)](https://github.com/codeskine/gin-gonic-xss-middleware/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/codeskine/gin-gonic-xss-middleware)](https://goreportcard.com/report/github.com/codeskine/gin-gonic-xss-middleware)
[![Go Reference](https://pkg.go.dev/badge/github.com/codeskine/xss-middleware.svg)](https://pkg.go.dev/github.com/codeskine/xss-middleware)

A [Gin](https://github.com/gin-gonic/gin) middleware that automatically sanitizes XSS payloads from incoming HTTP requests before they reach your route handlers. Supports GET query parameters, JSON, form-encoded, and multipart bodies.

XSS filtering is performed by [bluemonday](https://github.com/microcosm-cc/bluemonday). The default policy is `StrictPolicy` (strips all HTML).

## Demo

```
Input:  {"name": "<script>alert(1)</script>", "bio": "hello"}
Output: {"bio": "hello", "name": ""}
```

## Installation

```bash
go get github.com/codeskine/xss-middleware
go mod tidy
```

## Getting Started

```go
package main

import (
    "github.com/gin-gonic/gin"
    xss "github.com/codeskine/xss-middleware"
)

func main() {
    r := gin.Default()
    r.Use(xss.New()) // StrictPolicy · "password" field skipped · 1 MB body cap

    r.GET("/ping", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "pong"})
    })
    r.Run()
}
```

## Features

### What gets sanitized

| Request type | Content-Type |
|---|---|
| GET | query string keys and values |
| POST / PUT / PATCH | `application/json` — string values and object keys |
| POST / PUT / PATCH | `application/x-www-form-urlencoded` — keys and values |
| POST / PUT / PATCH | `multipart/form-data` — text field keys and values; binary parts (images, video, audio, archives) pass through unchanged |

Content-Type matching is case-insensitive. All other methods and content types pass through without modification.

### Configuration options

| Option | Description |
|---|---|
| `WithStrictPolicy()` | Use `bluemonday.StrictPolicy` — strips all HTML (default) |
| `WithUGCPolicy()` | Use `bluemonday.UGCPolicy` — keeps safe tags like `<b>`, `<i>`, `<a>` |
| `WithPolicy(p)` | Use a custom `*bluemonday.Policy` |
| `SkipFields(fields...)` | Skip value sanitization for named fields (`"password"` is always skipped) |
| `WithMaxBodySize(n)` | Cap JSON/form body; requests over the limit return 413 (default: 1 MB) |
| `WithMaxMultipartSize(n)` | Cap multipart body; requests over the limit return 413 (default: 32 MB) |

### Custom options

```go
r.Use(xss.New(
    xss.WithUGCPolicy(),
    xss.SkipFields("token", "create_date"),
    xss.WithMaxBodySize(512 * 1024),    // 512 KB for JSON / form
    xss.WithMaxMultipartSize(10 << 20), // 10 MB for multipart
))
```

### Bring your own bluemonday policy

```go
p := bluemonday.NewPolicy()
p.AllowElements("b", "i", "em")

r.Use(xss.New(xss.WithPolicy(p)))
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Acknowledgements

Forked from [dvwright/xss-mw](https://github.com/dvwright/xss-mw).  
XSS filtering by [microcosm-cc/bluemonday](https://github.com/microcosm-cc/bluemonday).

## License

[MIT](./LICENSE)
