package xss_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"

	xss "github.com/codeskine/xss-middleware"
)

// ExampleNew shows basic JSON sanitization using the default StrictPolicy.
// All HTML tags and their content are stripped from string values and object keys.
func ExampleNew() {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(xss.New())
	r.POST("/", func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		fmt.Println(string(b))
	})

	req := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"name":"<script>alert(1)</script>"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)
	// Output:
	// {"name":""}
}

// ExampleNew_ugcPolicy demonstrates UGCPolicy, which keeps safe formatting tags
// (b, i, em, a, img, …) while still stripping scripts and dangerous attributes.
func ExampleNew_ugcPolicy() {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(xss.New(xss.WithUGCPolicy()))
	r.POST("/", func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		fmt.Println(string(b))
	})

	req := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"name":"hello <script>evil()</script>"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)
	// Output:
	// {"name":"hello "}
}

// ExampleSkipFields shows how to exclude sensitive fields from value sanitization.
// Keys are still sanitized; only values of the named fields are passed through unchanged.
func ExampleSkipFields() {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(xss.New(xss.SkipFields("token")))
	r.POST("/", func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		fmt.Println(string(b))
	})

	body := `{"token":"eyJhbGciOiJIUzI1NiJ9.payload.sig","name":"<script>xss</script>"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)
	// Output:
	// {"name":"","token":"eyJhbGciOiJIUzI1NiJ9.payload.sig"}
}

// ExampleWithPolicy demonstrates how to supply a fully custom bluemonday policy.
func ExampleWithPolicy() {
	gin.SetMode(gin.TestMode)
	p := bluemonday.NewPolicy()
	p.AllowElements("b", "i", "em")

	r := gin.New()
	r.Use(xss.New(xss.WithPolicy(p)))
	r.GET("/", func(c *gin.Context) {
		fmt.Println(c.Query("q"))
	})

	req := httptest.NewRequest(http.MethodGet, "/?q=<em>ok</em><script>bad</script>", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)
	// Output:
	// <em>ok</em>
}
