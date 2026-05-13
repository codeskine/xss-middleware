// Copyright 2016 David Wright. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package xss

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

// newServer builds a test Gin engine using the new New() middleware.
func newServer(opts ...Option) *gin.Engine {
	r := gin.Default()
	r.Use(New(opts...))

	r.GET("/user/:id", func(c *gin.Context) {
		c.String(200, "%v", c.Request.Body)
	})

	r.GET("/user", func(c *gin.Context) {
		c.JSON(201, gin.H{
			"id":    c.DefaultQuery("id", ""),
			"name":  c.DefaultQuery("name", ""),
			"email": c.DefaultQuery("email", ""),
		})
	})

	r.GET("/echo_query", func(c *gin.Context) {
		c.JSON(200, gin.H{"x": c.QueryArray("x")})
	})

	r.PUT("/user", func(c *gin.Context) {
		var user struct {
			Id       int     `json:"id" form:"id" binding:"required"`
			Flt      float64 `json:"flt" form:"flt"`
			User     string  `json:"user" form:"user"`
			Email    string  `json:"email" form:"email"`
			Password string  `json:"password" form:"password"`
			CreAt    int64   `json:"cre_at" form:"cre_at"`
			Comment  string  `json:"comment" form:"comment"`
		}
		if err := c.Bind(&user); err != nil {
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(200, user)
	})

	r.POST("/user", func(c *gin.Context) {
		var user struct {
			Id       int     `json:"id" form:"id" binding:"required"`
			Flt      float64 `json:"flt" form:"flt"`
			User     string  `json:"user" form:"user"`
			Email    string  `json:"email" form:"email"`
			Password string  `json:"password" form:"password"`
			CreAt    int64   `json:"cre_at" form:"cre_at"`
			Comment  string  `json:"comment" form:"comment"`
		}
		if err := c.Bind(&user); err != nil {
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, user)
	})

	r.POST("/user_post", func(c *gin.Context) {
		var user struct {
			Id       int     `json:"id" form:"id" binding:"required"`
			Flt      float64 `json:"flt" form:"flt"`
			User     string  `json:"user" form:"user"`
			Email    string  `json:"email" form:"email"`
			Password string  `json:"password" form:"password"`
			CreAt    int64   `json:"cre_at" form:"cre_at"`
			Comment  string  `json:"comment" form:"comment"`
		}
		if err := c.Bind(&user); err != nil {
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(200, user)
	})

	r.POST("/user_extended", func(c *gin.Context) {
		var u struct {
			Id       int     `json:"id" form:"id" binding:"required"`
			Flt      float64 `json:"flt" form:"flt"`
			User     string  `json:"user" form:"user"`
			Email    string  `json:"email" form:"email"`
			Password string  `json:"password" form:"password"`
			CreAt    int64   `json:"cre_at" form:"cre_at"`
			Comment  string  `json:"comment" form:"comment"`
			Users    []struct {
				Id       int     `json:"id" form:"id"`
				Flt      float64 `json:"flt" form:"flt"`
				User     string  `json:"user" form:"user"`
				Email    string  `json:"email" form:"email"`
				Password string  `json:"password" form:"password"`
				CreAt    int64   `json:"cre_at" form:"cre_at"`
				Comment  string  `json:"comment" form:"comment"`
			} `json:"users"`
			Ids []string `json:"ids"`
		}
		if err := c.Bind(&u); err != nil {
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, u)
	})

	r.POST("/user_post_nested_json", func(c *gin.Context) {
		var users struct {
			Id    int `json:"id" form:"id" binding:"required"`
			Users []struct {
				Id       int     `json:"id"`
				Flt      float64 `json:"flt"`
				User     string  `json:"user"`
				Email    string  `json:"email"`
				Password string  `json:"password"`
				CreAt    int64   `json:"cre_at"`
				Comment  string  `json:"comment"`
			} `json:"users"`
		}
		if err := c.Bind(&users); err != nil {
			c.JSON(404, gin.H{"msg": "Bind Failed."})
			return
		}
		c.JSON(201, users)
	})

	// echo routes for regression tests
	r.POST("/echo", func(c *gin.Context) {
		b, _ := readAll(c)
		c.Data(200, "application/json", b)
	})

	r.POST("/echo_form", func(c *gin.Context) {
		c.JSON(200, gin.H{"x": c.PostFormArray("x")})
	})

	r.POST("/echo_multipart", func(c *gin.Context) {
		if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		result := map[string]interface{}{}
		for k, vals := range c.Request.MultipartForm.Value {
			if len(vals) > 0 {
				result[k] = vals[0]
			}
		}
		// Also include file parts (they appear as empty files when they're text fields with filename=)
		for k, files := range c.Request.MultipartForm.File {
			if len(files) > 0 {
				fh := files[0]
				f, _ := fh.Open()
				data := make([]byte, fh.Size)
				f.Read(data)
				f.Close()
				result[k] = string(data)
			}
		}
		c.JSON(200, result)
	})

	return r
}

// readAll is a helper used by the /echo route.
func readAll(c *gin.Context) ([]byte, error) {
	if c.Request.Body == nil {
		return []byte("null"), nil
	}
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(c.Request.Body)
	return buf.Bytes(), err
}

// --- Regression tests for bugs fixed in the rewrite ---

// Bug #2: empty JSON object produced invalid output ("}")
func TestRegressionEmptyJsonObject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("POST", "/echo", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	assert.JSONEq(t, `{}`, resp.Body.String())
}

// Bug #2: empty JSON array produced invalid output ("]")
func TestRegressionEmptyJsonArray(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("POST", "/echo", strings.NewReader(`[]`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	assert.JSONEq(t, `[]`, resp.Body.String())
}

// Bug #1: panic on top-level scalar array due to unchecked type assertion
func TestRegressionScalarArrayNoPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("POST", "/echo", strings.NewReader(`[1, "a<script>alert(0)</script>", true]`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	assert.JSONEq(t, `[1, "a", true]`, resp.Body.String())
}

// Bug #5: JSON keys were not sanitized — XSS bypass via key name
func TestRegressionJsonKeySanitized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("POST", "/echo", strings.NewReader(`{"<script>xss</script>":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	assert.NotContains(t, resp.Body.String(), "<script>")
}

// Bug #2 / correctness: null, bool, number values must pass through unchanged
func TestRegressionJsonNullBoolPassthrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("POST", "/echo", strings.NewReader(`{"flag":true,"nothing":null,"count":42}`))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	assert.JSONEq(t, `{"flag":true,"nothing":null,"count":42}`, resp.Body.String())
}

// Bug #6: GET multi-value params — only last value was kept
func TestRegressionGetMultiValueParams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("GET", "/echo_query?x=a&x=b", nil)
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	var result map[string][]string
	assert.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.ElementsMatch(t, []string{"a", "b"}, result["x"])
}

// Bug #7: form-encoded multi-value — only first value was kept
func TestRegressionFormMultiValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()
	req, _ := http.NewRequest("POST", "/echo_form", strings.NewReader("x=a&x=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	var result map[string][]string
	assert.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.ElementsMatch(t, []string{"a", "b"}, result["x"])
}

// Bug #4: multipart FieldsToSkip was silently ignored
func TestRegressionMultipartSkipFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(SkipFields("token"))

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("token", "<script>evil</script>")
	_ = writer.WriteField("name", "<b>test</b>")
	writer.Close()

	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+writer.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)
	var result map[string]string
	assert.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Equal(t, "<script>evil</script>", result["token"]) // skipped: not sanitized
	assert.Equal(t, "test", result["name"])                   // sanitized: tags stripped
}

// Bug #8: empty multipart field incorrectly aborted the request
func TestRegressionMultipartEmptyField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("name", "")
	_ = writer.WriteField("value", "test")
	writer.Close()

	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+writer.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)
	var result map[string]string
	assert.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Equal(t, "", result["name"])
	assert.Equal(t, "test", result["value"])
}

// Bug #4: multipart BmPolicy was silently ignored (hardcoded StrictPolicy)
// UGC policy keeps safe img tags.
func TestRegressionMultipartUGCPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithUGCPolicy())

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("comment", `<img src="https://example.com/img.jpg" alt="test">`)
	writer.Close()

	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+writer.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)

	assert.Equal(t, 200, resp.Code)
	var result map[string]string
	assert.NoError(t, json.Unmarshal(resp.Body.Bytes(), &result))
	assert.Contains(t, result["comment"], "<img") // UGC policy keeps safe img tags
}

// New behavior: the new implementation always filters JSON, even without Content-Length.
func TestXssFiltersWithoutContentLength(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := newServer()
	payload := `{"name":"<script>alert(1)</script>"}`
	req, _ := http.NewRequest("POST", "/echo", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	// No Content-Length header set — new implementation filters anyway
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var got map[string]string
	json.Unmarshal(w.Body.Bytes(), &got)
	assert.Equal(t, "", got["name"])
}

// Bug #3: concurrent requests must not share policy state (race condition)
func TestRegressionConcurrentRequestsNoRace(t *testing.T) {
	r := newServer()
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			payload := `{"name":"<script>alert(1)</script>"}`
			req, _ := http.NewRequest("POST", "/echo", strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.ContentLength = int64(len(payload))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}()
	}
	wg.Wait()
}

// Bug #9: multipart boundary with extra MIME params (e.g. charset) must not corrupt the boundary
func TestRegressionMultipartBoundaryWithExtraParams(t *testing.T) {
	r := newServer()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, _ := mw.CreateFormField("name")
	fw.Write([]byte("<b>hello</b>"))
	mw.Close()

	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	// Set Content-Type with extra param after boundary — old string-split code would corrupt the boundary
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary()+"; charset=utf-8")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "hello")
	assert.NotContains(t, w.Body.String(), "<b>")
}

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

// Security: text field with filename= but no Content-Type must still be sanitized
func TestMultipartFilenameBypassFixed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()

	body := new(bytes.Buffer)
	mw := multipart.NewWriter(body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="bio"; filename="x.txt"`)
	// No Content-Type — old code skipped sanitization for any non-empty filename
	fw, _ := mw.CreatePart(h)
	fw.Write([]byte("<script>alert(1)</script>"))
	mw.Close()

	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	// Check for both literal and JSON-escaped versions (JSON encoder escapes < and >)
	assert.NotContains(t, resp.Body.String(), "<script>")
	assert.NotContains(t, resp.Body.String(), "\\u003cscript")
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
	assert.Equal(t, http.StatusOK, resp.Code)
}

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
	// Exactly one key "x" must survive with one of the two original values
	assert.Contains(t, []string{"v1", "v2"}, result["x"])
	assert.Len(t, result, 1)
}

// Security: multipart part with Content-Type: application/javascript must be sanitized (not passed through)
func TestMultipartJavascriptBypassFixed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer()

	body := new(bytes.Buffer)
	mw := multipart.NewWriter(body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="script"; filename="evil.js"`)
	h.Set("Content-Type", "application/javascript")
	fw, _ := mw.CreatePart(h)
	fw.Write([]byte("<script>alert(1)</script>"))
	mw.Close()

	req, _ := http.NewRequest("POST", "/echo_multipart", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.NotContains(t, resp.Body.String(), "<script>")
	assert.NotContains(t, resp.Body.String(), "\\u003cscript")
}

// GET query parameter keys with XSS must be sanitized
func TestGetKeysSanitized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(New())
	r.GET("/q", func(c *gin.Context) {
		c.String(200, c.Request.URL.RawQuery)
	})
	req, _ := http.NewRequest("GET", "/q?%3Cscript%3Exss%3C%2Fscript%3E=val", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	assert.NotContains(t, resp.Body.String(), "<script>")
	assert.NotContains(t, resp.Body.String(), "%3Cscript%3E")
}

// Form-encoded field keys with XSS must be sanitized
func TestFormKeysSanitized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(New())
	r.POST("/f", func(c *gin.Context) {
		b, _ := readAll(c)
		c.Data(200, "text/plain", b)
	})
	req, _ := http.NewRequest("POST", "/f", strings.NewReader("%3Cscript%3Exss%3C%2Fscript%3E=val"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	assert.NotContains(t, resp.Body.String(), "<script>")
	assert.NotContains(t, resp.Body.String(), "%3Cscript%3E")
}

// WithMaxBodySize(0) must fall back to default and not reject normal requests
func TestWithMaxBodySizeZeroUsesDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithMaxBodySize(0))
	body := strings.NewReader(`{"name":"hello"}`)
	req, _ := http.NewRequest("POST", "/echo", body)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
}

// WithMaxBodySize(-1) must fall back to default and not reject normal requests
func TestWithMaxBodySizeNegativeUsesDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServer(WithMaxBodySize(-1))
	body := strings.NewReader(`{"name":"hello"}`)
	req, _ := http.NewRequest("POST", "/echo", body)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
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
