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
	"strings"
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
		result := map[string]string{}
		for k, vals := range c.Request.MultipartForm.Value {
			if len(vals) > 0 {
				result[k] = vals[0]
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
