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
	defaultMaxBodySize      = 1 << 20  // 1 MB
	defaultMaxMultipartSize = 32 << 20 // 32 MB
	maxJSONDepth            = 64
)

var errBodyTooLarge = errors.New("request body too large")

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

// WithPolicy sets a custom bluemonday policy.
func WithPolicy(p *bluemonday.Policy) Option {
	return func(c *config) { c.policy = p }
}

// WithStrictPolicy uses bluemonday.StrictPolicy (the default).
func WithStrictPolicy() Option {
	return func(c *config) { c.policy = bluemonday.StrictPolicy() }
}

// WithUGCPolicy uses bluemonday.UGCPolicy.
func WithUGCPolicy() Option {
	return func(c *config) { c.policy = bluemonday.UGCPolicy() }
}

// SkipFields adds field names to exclude from sanitization.
// "password" is always skipped regardless of this option.
func SkipFields(fields ...string) Option {
	return func(c *config) {
		for _, f := range fields {
			c.skipFields[f] = true
		}
	}
}

// WithMaxBodySize caps JSON and form-encoded request bodies.
// Requests exceeding the limit are rejected with 413. Default: 1 MB.
// Values <= 0 are ignored and the default is used.
func WithMaxBodySize(n int64) Option {
	return func(c *config) {
		if n > 0 {
			c.maxBodySize = n
		}
	}
}

// WithMaxMultipartSize caps multipart/form-data request bodies.
// Requests exceeding the limit are rejected with 413. Default: 32 MB.
// Values <= 0 are ignored and the default is used.
func WithMaxMultipartSize(n int64) Option {
	return func(c *config) {
		if n > 0 {
			c.maxMultipartSize = n
		}
	}
}

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

func sanitizeValue(v *any, p *bluemonday.Policy, skip map[string]bool, depth int) {
	if depth > maxJSONDepth {
		*v = nil
		return
	}
	switch val := (*v).(type) {
	case map[string]any:
		sanitizeMap(val, p, skip, depth)
	case []any:
		for i := range val {
			sanitizeValue(&val[i], p, skip, depth+1)
		}
	case string:
		*v = p.Sanitize(val)
		// json.Number, bool, nil: pass through unchanged
	}
}

func sanitizeMap(val map[string]any, p *bluemonday.Policy, skip map[string]bool, depth int) {
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
		if _, exists := val[r.new]; !exists { // first rename wins on collision
			val[r.new] = val[r.old]
		}
		delete(val, r.old)
	}
}

func handleGET(c *gin.Context, p *bluemonday.Policy, skip map[string]bool) error {
	q := c.Request.URL.Query()
	result := make(url.Values)
	for key, items := range q {
		cleanKey := p.Sanitize(key)
		if skip[key] {
			if _, exists := result[cleanKey]; !exists {
				result[cleanKey] = items
			}
			continue
		}
		cleaned := make([]string, len(items))
		for i, v := range items {
			cleaned[i] = p.Sanitize(v)
		}
		if _, exists := result[cleanKey]; !exists {
			result[cleanKey] = cleaned
		}
	}
	c.Request.URL.RawQuery = result.Encode()
	return nil
}

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
		cleanKey := p.Sanitize(k)
		if skip[k] {
			if _, exists := result[cleanKey]; !exists {
				result[cleanKey] = vals
			}
			continue
		}
		sanitized := make([]string, len(vals))
		for i, v := range vals {
			sanitized[i] = p.Sanitize(v)
		}
		if _, exists := result[cleanKey]; !exists {
			result[cleanKey] = sanitized
		}
	}
	c.Request.Body = io.NopCloser(strings.NewReader(result.Encode()))
	return nil
}

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

	limited := io.LimitReader(c.Request.Body, maxMultipartSize+1)
	cr := &countingReader{r: limited, limit: maxMultipartSize}
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
		if err := sanitizePart(part, mw, p, skip); err != nil {
			return err
		}
	}

	if err := mw.Close(); err != nil {
		return err
	}
	c.Request.Body = io.NopCloser(&buf)
	return nil
}

// isBinaryContentType reports whether the media type is a known binary format
// that should be passed through without sanitization. Only explicitly binary
// types (images, video, audio, raw binary blobs) are allowed through; all
// others — including application/javascript, application/json, etc. — are sanitized.
func isBinaryContentType(ct string) bool {
	mediaType, _, _ := mime.ParseMediaType(ct)
	return strings.HasPrefix(mediaType, "image/") ||
		strings.HasPrefix(mediaType, "video/") ||
		strings.HasPrefix(mediaType, "audio/") ||
		mediaType == "application/octet-stream" ||
		mediaType == "application/pdf" ||
		mediaType == "application/zip" ||
		mediaType == "application/gzip" ||
		mediaType == "application/x-tar"
}

func sanitizePart(part *multipart.Part, mw *multipart.Writer, p *bluemonday.Policy, skip map[string]bool) error {
	fw, err := mw.CreatePart(part.Header)
	if err != nil {
		return err
	}
	ct := part.Header.Get("Content-Type")
	if ct != "" && isBinaryContentType(ct) {
		_, err = io.Copy(fw, part)
		return err
	}
	if skip[part.FormName()] {
		_, err = io.Copy(fw, part)
		return err
	}
	fieldBytes, err := io.ReadAll(part)
	if err != nil {
		return err
	}
	_, err = fw.Write([]byte(p.Sanitize(string(fieldBytes))))
	return err
}
