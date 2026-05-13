# XSS Middleware — Security Fixes Design Spec

**Date:** 2026-05-13
**Scope:** Fix 5 security/correctness issues identified in post-rewrite audit
**Breaking changes:** No — additive API only (`WithMaxBodySize`, `WithMaxMultipartSize`)

---

## Background

A post-rewrite audit of `xss.go` identified 5 issues:

| # | Severity | Issue |
|---|----------|-------|
| 1 | HIGH | No body size limit — DoS via memory exhaustion |
| 2 | HIGH | Multipart XSS bypass via `filename` header on text fields |
| 3 | MEDIUM | `handleMultipart` panics on nil request body |
| 4 | MEDIUM | JSON key rename collision causes silent data loss |
| 5 | LOW | Unbounded recursion in `sanitizeValue` — stack overflow on crafted input |

---

## Goals

- Fix all 5 issues
- Make body size limits configurable via functional options
- Add regression tests for every fix

## Non-Goals

- Response-side filtering
- Per-field size limits
- Changing the JSON depth limit at runtime (compile-time constant is sufficient)

---

## API

### New options

```go
// WithMaxBodySize caps JSON and form-encoded request bodies.
// Requests exceeding the limit are rejected with 413 Request Entity Too Large.
// Default: 1 MB.
func WithMaxBodySize(n int64) Option

// WithMaxMultipartSize caps multipart/form-data request bodies.
// Requests exceeding the limit are rejected with 413 Request Entity Too Large.
// Default: 32 MB.
func WithMaxMultipartSize(n int64) Option
```

### Usage examples

```go
// Defaults: 1 MB for JSON/form, 32 MB for multipart
r.Use(xss.New())

// Custom limits
r.Use(xss.New(
    xss.WithMaxBodySize(512 * 1024),       // 512 KB
    xss.WithMaxMultipartSize(10 << 20),    // 10 MB
))
```

### config struct

```go
type config struct {
    policy           *bluemonday.Policy
    skipFields       map[string]bool
    maxBodySize      int64   // default: 1 << 20  (1 MB)
    maxMultipartSize int64   // default: 32 << 20 (32 MB)
}
```

`New()` sets the defaults before applying options:

```go
cfg := &config{
    skipFields:       map[string]bool{"password": true},
    maxBodySize:      1 << 20,
    maxMultipartSize: 32 << 20,
}
```

---

## Fix Details

### Fix 1 — Body size limits

**Sentinel error:**

```go
var errBodyTooLarge = errors.New("request body too large")
```

**`handleJSON` and `handleForm`:** Read the full body via `io.LimitReader(body, limit+1)`. If `len(data) > limit`, return `errBodyTooLarge`.

```go
limited := io.LimitReader(c.Request.Body, maxBodySize+1)
data, err := io.ReadAll(limited)
if err != nil {
    return err
}
if int64(len(data)) > maxBodySize {
    return errBodyTooLarge
}
```

**`handleMultipart`:** Wrap `c.Request.Body` with a counting reader that returns `errBodyTooLarge` the moment cumulative bytes cross `maxMultipartSize`. The error propagates naturally through `mr.NextPart()`.

```go
type countingReader struct {
    r     io.Reader
    n     int64
    limit int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
    n, err := cr.r.Read(p)
    cr.n += int64(n)
    if cr.n > cr.limit {
        return n, errBodyTooLarge
    }
    return n, err
}
```

**`New()` error dispatch:**

```go
if err != nil {
    status := http.StatusBadRequest
    if errors.Is(err, errBodyTooLarge) {
        status = http.StatusRequestEntityTooLarge
    }
    _ = c.AbortWithError(status, err)
    return
}
```

---

### Fix 2 — Multipart XSS bypass via `filename`

Replace the `part.FileName() != ""` guard with a Content-Type check. Binary parts (explicit non-text Content-Type) are copied verbatim. Text parts and parts without a Content-Type are always sanitized, regardless of filename.

```go
// Before
if part.FileName() != "" {
    io.Copy(fw, part)
    continue
}

// After
ct := part.Header.Get("Content-Type")
if ct != "" && !strings.HasPrefix(ct, "text/") {
    io.Copy(fw, part)
    continue
}
```

**Rationale:** A legitimate browser file upload (image, PDF) always carries a non-text Content-Type. An attacker adding `filename="x.txt"` to a text field will either have no Content-Type or `Content-Type: text/plain` — both go through sanitization.

---

### Fix 3 — Nil body guard in `handleMultipart`

Add the same nil check already present in `handleJSON` and `handleForm`:

```go
if c.Request.Body == nil {
    return nil
}
```

---

### Fix 4 — Key rename collision in `sanitizeValue`

When two JSON keys sanitize to the same string, the second rename currently overwrites the first silently. Fix: skip the rename if the target already exists; always delete the original key.

```go
// Before
for _, r := range renames {
    val[r.new] = val[r.old]
    delete(val, r.old)
}

// After
for _, r := range renames {
    if _, exists := val[r.new]; !exists {
        val[r.new] = val[r.old]
    }
    delete(val, r.old)
}
```

First-wins is deterministic enough for degenerate input. The original key is always removed.

---

### Fix 5 — Unbounded recursion in `sanitizeValue`

Add a `depth int` parameter. At `maxJSONDepth` (compile-time constant = 64), set the current node to `nil` and return. Nil-out is fail-safe: deeply crafted XSS payloads are wiped rather than passed through.

```go
const maxJSONDepth = 64

func sanitizeValue(v *any, p *bluemonday.Policy, skip map[string]bool, depth int) {
    if depth > maxJSONDepth {
        *v = nil
        return
    }
    // ... recurse with depth+1
}
```

`sanitizeJSON` calls `sanitizeValue(&v, p, skip, 0)`.

---

## Testing

| Test | Fix covered |
|------|-------------|
| `TestBodySizeLimitJSON` | POST JSON over 1 MB default → 413 |
| `TestBodySizeLimitForm` | POST form over 1 MB default → 413 |
| `TestBodySizeLimitMultipart` | POST multipart over 32 MB default → 413 |
| `TestBodySizeUnderLimitPasses` | POST just under limit → 200, sanitized |
| `TestMaxBodySizeConfigurable` | `WithMaxBodySize(100)` + 101-byte body → 413 |
| `TestMaxMultipartSizeConfigurable` | `WithMaxMultipartSize(100)` + 101-byte multipart → 413 |
| `TestMultipartFilenameBypassFixed` | Text field with `filename=` and no Content-Type → sanitized |
| `TestMultipartBinaryPartPreserved` | Part with `Content-Type: image/jpeg` → copied verbatim |
| `TestMultipartNilBody` | nil body → 200, no panic |
| `TestJsonKeyCollision` | Two keys sanitizing to same string → one survives, no crash |
| `TestJsonMaxDepth` | JSON nested 65 levels deep → deep values nil'd, no stack overflow |
