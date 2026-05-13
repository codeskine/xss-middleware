# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.0] — 2026-05-13

### Added
- `WithMaxBodySize(n)` option — caps JSON and form-encoded request bodies; requests over the limit return 413.
- `WithMaxMultipartSize(n)` option — caps multipart/form-data bodies; requests over the limit return 413.
- Body size options default to 1 MB (JSON/form) and 32 MB (multipart); values ≤ 0 are ignored.

### Fixed
- **Security:** `sanitizePart` now uses an explicit allowlist (`image/*`, `video/*`, `audio/*`, `application/octet-stream`, `application/pdf`, `application/zip`, `application/gzip`, `application/x-tar`) instead of `!strings.HasPrefix(ct, "text/")`, closing a bypass where `Content-Type: application/javascript` could skip sanitization.
- **Security:** GET query string keys and form-encoded field keys are now sanitized (previously only values were sanitized, inconsistent with JSON key handling).
- **Security:** `Content-Type` dispatch now uses `mime.ParseMediaType` instead of `strings.Contains`, making matching case-insensitive and exact (closes bypass via `APPLICATION/JSON`, `Multipart/Form-Data`, etc.).
- `WithMaxBodySize(0)` and `WithMaxBodySize(-1)` no longer silently reject all requests; invalid values fall back to the default.
- `sanitizeValue` now uses `errors.Is(err, io.EOF)` for multipart EOF detection.

### Changed
- `errInvalidMultipart` promoted from inline `errors.New` to a package-level sentinel.
- `var renames []rename` in `sanitizeMap` replaced with `make([]rename, 0, len(val))` (pre-allocated, never nil).

## [0.2.0] — 2026-05-13

### Added
- Functional options API (`New(opts ...Option)`): `WithPolicy`, `WithStrictPolicy`, `WithUGCPolicy`, `SkipFields`.
- `SkipFields` now applies consistently across JSON, form-encoded, and multipart handlers.
- Multipart handler respects the configured bluemonday policy (previously hardcoded to StrictPolicy).
- `sanitizeValue` recursion capped at depth 64; values deeper than the cap are set to nil rather than causing a stack overflow.
- JSON object keys sanitized in addition to values.
- First-rename-wins collision guard when two JSON keys sanitize to the same string.
- Depth-limited `sanitizeValue` for protection against deeply nested JSON.

### Fixed
- Empty JSON object `{}` no longer produces invalid output.
- Empty JSON array `[]` no longer produces invalid output.
- Panic on top-level scalar JSON arrays eliminated.
- GET multi-value parameters: all values now preserved (previously only the last value was kept).
- Form-encoded multi-value parameters: all values now preserved (previously only the first value was kept).
- Multipart binary parts detected by `Content-Type` header instead of `filename` parameter, closing a bypass via `filename=x.txt` without a Content-Type.
- Nil multipart body no longer causes a panic.
- Multipart `Content-Type` with extra parameters (e.g. `; charset=utf-8` after the boundary) no longer corrupts the boundary.
- Concurrent requests no longer share policy state (race condition).

### Removed
- Old `XssMw` struct-based API removed; replaced entirely by the functional options API.

## [0.1.0] — 2024-04-23

### Added
- Initial fork from [dvwright/xss-mw](https://github.com/dvwright/xss-mw).
- Basic Gin middleware wiring XSS sanitization to JSON, form-encoded, and multipart bodies.
