# Security Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 5 security/correctness issues in `xss.go`: DoS via unbounded body size, multipart XSS bypass, nil-body panic, JSON key rename collision, and unbounded recursion.

**Architecture:** All changes are confined to `xss.go` and `xss_test.go`. No new files. Two new `Option` functions (`WithMaxBodySize`, `WithMaxMultipartSize`) extend the existing functional-options API. Handler signatures gain a size-limit parameter passed from the `New()` closure. `sanitizeValue` gains a depth counter.

**Tech Stack:** Go, `github.com/gin-gonic/gin`, `github.com/microcosm-cc/bluemonday`, `github.com/stretchr/testify/assert`

---

## File Map

- Modify: `xss.go` — all implementation changes
- Modify: `xss_test.go` — all new regression tests

---

### Task 1: Body size options + JSON/form size limiting

**Files:**
- Modify: `xss.go`
- Modify: `xss_test.go`

- [ ] **Step 1: Write the failing tests**

Add these four tests to `xss_test.go` (after the last existing test):

```go
func TestMaxBodySizeConfigurable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithMaxBodySize(100))
	body := strings.NewReader(`{"name":"` + strings.Repeat("a", 100) + `"}`)
	req, _ := http.NewRequest("POST", "/echo", body)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.Code)
}

func TestBodySizeLimitJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithMaxBodySize(10))
	body := strings.NewReader(`{"name":"hello world this is too long"}`)
	req, _ := http.NewRequest("POST", "/echo", body)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.Code)
}

func TestBodySizeLimitForm(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithMaxBodySize(10))
	body := strings.NewReader("name=hello+world+this+is+too+long")
	req, _ := http.NewRequest("POST", "/echo_form", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.Code)
}

func TestBodySizeUnderLimitPasses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithMaxBodySize(100))
	body := strings.NewReader(`{"name":"hi"}`)
	req, _ := http.NewRequest("POST", "/echo", body)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.JSONEq(t, `{"name":"hi"}`, resp.Body.String())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test -run "TestMaxBodySizeConfigurable|TestBodySizeLimitJSON|TestBodySizeLimitForm|TestBodySizeUnderLimitPasses" ./...
```

Expected: FAIL — `WithMaxBodySize` is not defined yet.

- [ ] **Step 3: Implement**

Replace the top of `xss.go` (from `package xss` through the closing `}` of `New()`) with:

```go
// Copyright 2016 David Wright. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

// Package xss provides a Gin middleware that sanitizes XSS from incoming HTTP
// requests before they reach route handlers.
//
// It handles GET (query params), application/json, application/x-www-form-urlencoded,
// and multipart/form-data content types.
//
// XSS filtering is performed by the HTML sanitizer https://github.com/microcosm-cc/bluemonday.
// The default policy is StrictPolicy.
package xss

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"
)

const (
	defaultMaxBodySize      = 1 << 20        // 1 MB
	defaultMaxMultipartSize = 32 << 20       // 32 MB
)

var errBodyTooLarge = errors.New("request body too large")

// Option configures the XSS middleware.
type Option func(*config)

type config struct {
	policy           *bluemonday.Policy
	skipFields       map[string]bool
	maxBodySize      int64
	maxMultipartSize int64
}

// New returns a Gin middleware that sanitizes XSS from incoming requests.
// It is safe for concurrent use.
func New(opts ...Option) gin.HandlerFunc {
	cfg := &config{
		skipFields:       map[string]bool{"password": true},
		maxBodySize:      defaultMaxBodySize,
		maxMultipartSize: defaultMaxMultipartSize,
	}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.policy == nil {
		cfg.policy = bluemonday.StrictPolicy()
	}
	p := cfg.policy
	skip := cfg.skipFields
	maxBody := cfg.maxBodySize
	maxMultipart := cfg.maxMultipartSize

	return func(c *gin.Context) {
		method := c.Request.Method
		ct := c.Request.Header.Get("Content-Type")
		var err error
		switch method {
		case "POST", "PUT", "PATCH":
			switch {
			case strings.Contains(ct, "application/json"):
				err = handleJSON(c, p, skip, maxBody)
			case strings.Contains(ct, "application/x-www-form-urlencoded"):
				err = handleForm(c, p, skip, maxBody)
			case strings.Contains(ct, "multipart/form-data"):
				err = handleMultipart(c, p, skip, maxMultipart)
			}
		case "GET":
			err = handleGET(c, p, skip)
		}
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errBodyTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			_ = c.AbortWithError(status, err)
			return
		}
		c.Next()
	}
}
```

After the option functions (`WithPolicy`, `WithStrictPolicy`, `WithUGCPolicy`, `SkipFields`), add:

```go
// WithMaxBodySize caps JSON and form-encoded request bodies.
// Requests exceeding the limit are rejected with 413. Default: 1 MB.
func WithMaxBodySize(n int64) Option {
	return func(c *config) { c.maxBodySize = n }
}

// WithMaxMultipartSize caps multipart/form-data request bodies.
// Requests exceeding the limit are rejected with 413. Default: 32 MB.
func WithMaxMultipartSize(n int64) Option {
	return func(c *config) { c.maxMultipartSize = n }
}
```

Replace the `handleJSON` function with:

```go
func handleJSON(c *gin.Context, p *bluemonday.Policy, skip map[string]bool, maxBodySize int64) error {
	if c.Request.Body == nil {
		return nil
	}
	limited := io.LimitReader(c.Request.Body, maxBodySize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBodySize {
		return errBodyTooLarge
	}
	out, err := sanitizeJSON(bytes.NewReader(data), p, skip)
	if err != nil {
		return err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(out))
	return nil
}
```

Replace the `handleForm` function with:

```go
func handleForm(c *gin.Context, p *bluemonday.Policy, skip map[string]bool, maxBodySize int64) error {
	if c.Request.Body == nil {
		return nil
	}
	limited := io.LimitReader(c.Request.Body, maxBodySize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBodySize {
		return errBodyTooLarge
	}
	m, err := url.ParseQuery(string(data))
	if err != nil {
		return err
	}
	result := make(url.Values)
	for k, vals := range m {
		if skip[k] {
			result[k] = vals
			continue
		}
		sanitized := make([]string, len(vals))
		for i, v := range vals {
			sanitized[i] = p.Sanitize(v)
		}
		result[k] = sanitized
	}
	c.Request.Body = io.NopCloser(strings.NewReader(result.Encode()))
	return nil
}
```

The `handleMultipart` signature also needs updating (it will be fully implemented in Task 2, but the call site in `New()` already passes `maxMultipart`). Replace the `handleMultipart` function signature line only:

```go
func handleMultipart(c *gin.Context, p *bluemonday.Policy, skip map[string]bool, maxMultipartSize int64) error {
```

Keep the rest of the `handleMultipart` body unchanged for now.

- [ ] **Step 4: Run the tests**

```bash
go test -run "TestMaxBodySizeConfigurable|TestBodySizeLimitJSON|TestBodySizeLimitForm|TestBodySizeUnderLimitPasses" ./...
```

Expected: all 4 PASS.

- [ ] **Step 5: Run the full suite**

```bash
go test -race ./...
```

Expected: `ok github.com/codeskine/xss-middleware` — all tests pass.

- [ ] **Step 6: Commit**

```bash
git add xss.go xss_test.go
git commit -m "feat: add WithMaxBodySize/WithMaxMultipartSize options; enforce limits on JSON and form handlers"
```

---

### Task 2: Multipart size limiting + nil body guard

**Files:**
- Modify: `xss.go`
- Modify: `xss_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `xss_test.go`:

```go
func TestBodySizeLimitMultipart(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithMaxMultipartSize(100))
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("name", strings.Repeat("a", 200))
	writer.Close()
	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+writer.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.Code)
}

func TestMaxMultipartSizeConfigurable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithMaxMultipartSize(10 << 20))
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("name", "hello")
	writer.Close()
	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+writer.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestMultipartNilBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("POST", "/echo", nil)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=abc")
	resp := httptest.NewRecorder()
	assert.NotPanics(t, func() {
		s.ServeHTTP(resp, req)
	})
	assert.Equal(t, http.StatusOK, resp.Code)
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
go test -run "TestBodySizeLimitMultipart|TestMaxMultipartSizeConfigurable|TestMultipartNilBody" ./...
```

Expected: FAIL — `TestBodySizeLimitMultipart` gets 200 (no limit enforced), `TestMultipartNilBody` panics.

- [ ] **Step 3: Implement**

In `xss.go`, add `countingReader` after the `errBodyTooLarge` declaration:

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

Replace the entire `handleMultipart` function with:

```go
func handleMultipart(c *gin.Context, p *bluemonday.Policy, skip map[string]bool, maxMultipartSize int64) error {
	if c.Request.Body == nil {
		return nil
	}
	ctHdr := c.Request.Header.Get("Content-Type")
	_, params, err := mime.ParseMediaType(ctHdr)
	if err != nil || params["boundary"] == "" {
		return errors.New("invalid multipart content-type")
	}
	boundary := params["boundary"]

	cr := &countingReader{r: c.Request.Body, limit: maxMultipartSize}
	mr := multipart.NewReader(cr, boundary)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.SetBoundary(boundary); err != nil {
		return err
	}

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		fw, err := mw.CreatePart(part.Header)
		if err != nil {
			return err
		}

		fieldName := part.FormName()

		if part.FileName() != "" {
			if _, err := io.Copy(fw, part); err != nil {
				return err
			}
			continue
		}

		if skip[fieldName] {
			if _, err := io.Copy(fw, part); err != nil {
				return err
			}
			continue
		}

		fieldBytes, err := io.ReadAll(part)
		if err != nil {
			return err
		}
		sanitized := p.Sanitize(string(fieldBytes))
		if _, err := fw.Write([]byte(sanitized)); err != nil {
			return err
		}
	}

	if err := mw.Close(); err != nil {
		return err
	}
	c.Request.Body = io.NopCloser(&buf)
	return nil
}
```

Note: the `part.FileName() != ""` guard stays for now — it will be replaced in Task 3.

- [ ] **Step 4: Run the new tests**

```bash
go test -run "TestBodySizeLimitMultipart|TestMaxMultipartSizeConfigurable|TestMultipartNilBody" ./...
```

Expected: all 3 PASS.

- [ ] **Step 5: Run the full suite**

```bash
go test -race ./...
```

Expected: `ok github.com/codeskine/xss-middleware`.

- [ ] **Step 6: Commit**

```bash
git add xss.go xss_test.go
git commit -m "fix: enforce size limit on multipart bodies; guard against nil body panic"
```

---

### Task 3: Fix multipart XSS bypass via filename header

**Files:**
- Modify: `xss.go`
- Modify: `xss_test.go`

- [ ] **Step 1: Write the failing tests**

Add `"net/textproto"` to the imports in `xss_test.go`:

```go
import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)
```

Add these two tests to `xss_test.go`:

```go
// Security: text field with filename= but no Content-Type must still be sanitized
func TestMultipartFilenameBypassFixed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()

	body := new(bytes.Buffer)
	mw := multipart.NewWriter(body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="bio"; filename="x.txt"`)
	// No Content-Type header — old code skipped sanitization for any non-empty filename
	fw, _ := mw.CreatePart(h)
	fw.Write([]byte("<script>alert(1)</script>"))
	mw.Close()

	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.NotContains(t, resp.Body.String(), "<script>")
}

// Binary file parts with explicit non-text Content-Type must pass through verbatim
func TestMultipartBinaryPartPreserved(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()

	body := new(bytes.Buffer)
	mw := multipart.NewWriter(body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="avatar"; filename="photo.jpg"`)
	h.Set("Content-Type", "image/jpeg")
	fw, _ := mw.CreatePart(h)
	fw.Write([]byte{0xFF, 0xD8, 0xFF, 0xE0}) // JPEG magic bytes
	mw.Close()

	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	// Request must succeed — binary part is not corrupted by sanitization
	assert.Equal(t, http.StatusOK, resp.Code)
}
```

- [ ] **Step 2: Run to verify the bypass test fails**

```bash
go test -run "TestMultipartFilenameBypassFixed|TestMultipartBinaryPartPreserved" ./...
```

Expected: `TestMultipartFilenameBypassFixed` FAIL (XSS passes through), `TestMultipartBinaryPartPreserved` PASS (binary already works, just verifying no regression).

- [ ] **Step 3: Implement**

In `handleMultipart`, replace the `part.FileName() != ""` guard with a Content-Type check:

```go
// Before
if part.FileName() != "" {
    if _, err := io.Copy(fw, part); err != nil {
        return err
    }
    continue
}

// After
ct := part.Header.Get("Content-Type")
if ct != "" && !strings.HasPrefix(ct, "text/") {
    if _, err := io.Copy(fw, part); err != nil {
        return err
    }
    continue
}
```

The full updated `for` loop body in `handleMultipart` now reads:

```go
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		fw, err := mw.CreatePart(part.Header)
		if err != nil {
			return err
		}

		fieldName := part.FormName()

		ct := part.Header.Get("Content-Type")
		if ct != "" && !strings.HasPrefix(ct, "text/") {
			if _, err := io.Copy(fw, part); err != nil {
				return err
			}
			continue
		}

		if skip[fieldName] {
			if _, err := io.Copy(fw, part); err != nil {
				return err
			}
			continue
		}

		fieldBytes, err := io.ReadAll(part)
		if err != nil {
			return err
		}
		sanitized := p.Sanitize(string(fieldBytes))
		if _, err := fw.Write([]byte(sanitized)); err != nil {
			return err
		}
	}
```

- [ ] **Step 4: Run the new tests**

```bash
go test -run "TestMultipartFilenameBypassFixed|TestMultipartBinaryPartPreserved" ./...
```

Expected: both PASS.

- [ ] **Step 5: Run the full suite**

```bash
go test -race ./...
```

Expected: `ok github.com/codeskine/xss-middleware`.

- [ ] **Step 6: Commit**

```bash
git add xss.go xss_test.go
git commit -m "fix: check Content-Type instead of filename to detect binary multipart parts (XSS bypass)"
```

---

### Task 4: Fix `sanitizeValue` — key rename collision + unbounded recursion

**Files:**
- Modify: `xss.go`
- Modify: `xss_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `xss_test.go`:

```go
// Two JSON keys that both sanitize to the same string — one value must survive, no crash
func TestJsonKeyCollision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("POST", "/echo", strings.NewReader(`{"<b>x</b>":"v1","<i>x</i>":"v2"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	var result map[string]string
	assert.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	// Exactly one key "x" must survive with one of the two values
	assert.Contains(t, []string{"v1", "v2"}, result["x"])
	assert.Len(t, result, 1)
}

// JSON nested 65 levels deep must not stack overflow; deep values are nil'd
func TestJsonMaxDepth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	payload := strings.Repeat("[", 65) + `"<script>xss</script>"` + strings.Repeat("]", 65)
	req, _ := http.NewRequest("POST", "/echo", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	assert.NotPanics(t, func() {
		s.ServeHTTP(resp, req)
	})
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.NotContains(t, resp.Body.String(), "<script>")
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
go test -run "TestJsonKeyCollision|TestJsonMaxDepth" ./...
```

Expected: `TestJsonKeyCollision` FAIL (collision overwrites one value so `result` has the wrong count or the wrong key), `TestJsonMaxDepth` may pass accidentally for shallow nesting but should be verified to not stack overflow at 65 levels — run with `-race` to be sure.

- [ ] **Step 3: Implement**

In `xss.go`, add the `maxJSONDepth` constant to the `const` block:

```go
const (
	defaultMaxBodySize      = 1 << 20
	defaultMaxMultipartSize = 32 << 20
	maxJSONDepth            = 64
)
```

Update `sanitizeJSON` to pass initial depth `0`:

```go
func sanitizeJSON(body io.Reader, p *bluemonday.Policy, skip map[string]bool) ([]byte, error) {
	var v any
	d := json.NewDecoder(body)
	d.UseNumber() // preserves numeric precision (no float64 precision loss)
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	sanitizeValue(&v, p, skip, 0)
	return json.Marshal(v)
}
```

Replace the entire `sanitizeValue` function with:

```go
func sanitizeValue(v *any, p *bluemonday.Policy, skip map[string]bool, depth int) {
	if depth > maxJSONDepth {
		*v = nil
		return
	}
	switch val := (*v).(type) {
	case map[string]any:
		for k, child := range val {
			if skip[k] {
				continue
			}
			sanitizeValue(&child, p, skip, depth+1)
			val[k] = child
		}
		// collect key renames before applying — avoids map mutation during iteration
		type rename struct{ old, new string }
		var renames []rename
		for k := range val {
			if clean := p.Sanitize(k); clean != k {
				renames = append(renames, rename{k, clean})
			}
		}
		for _, r := range renames {
			if _, exists := val[r.new]; !exists {
				val[r.new] = val[r.old]
			}
			delete(val, r.old)
		}
	case []any:
		for i := range val {
			sanitizeValue(&val[i], p, skip, depth+1)
		}
	case string:
		*v = p.Sanitize(val)
		// json.Number, bool, nil: pass through unchanged
	}
}
```

- [ ] **Step 4: Run the new tests**

```bash
go test -run "TestJsonKeyCollision|TestJsonMaxDepth" ./...
```

Expected: both PASS.

- [ ] **Step 5: Run the full suite**

```bash
go test -race ./... -count=1
```

Expected: `ok github.com/codeskine/xss-middleware` — all tests pass, race detector clean.

- [ ] **Step 6: Format and vet**

```bash
gofmt -l . && go vet ./...
```

Expected: no output (clean).

- [ ] **Step 7: Commit**

```bash
git add xss.go xss_test.go
git commit -m "fix: prevent key rename collision and unbounded recursion in sanitizeValue"
```
