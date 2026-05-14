package raucle

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Canonicalize serialises v as canonical JSON per Raucle spec v1 §4.3.
//
// Requirements (must match Python's
// json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)):
//
//  1. Keys at every depth sorted lexicographically.
//  2. Separators "," and ":" with no whitespace.
//  3. UTF-8 output.
//  4. Non-ASCII strings NOT escaped — pass through as raw codepoints.
//  5. Numbers use the minimal lossless representation.
//
// Go's encoding/json does not meet these requirements out of the box: it
// does not sort map keys, and it escapes some HTML characters. This
// implementation handles both.
func Canonicalize(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := canonicalizeInto(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalizeInto(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, x)
	case int:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Errorf("canonical JSON cannot encode NaN or Infinity")
		}
		if x == math.Trunc(x) && math.Abs(x) < 1e16 {
			buf.WriteString(strconv.FormatInt(int64(x), 10))
		} else {
			buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
		}
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalizeInto(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		buf.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, s)
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if x[k] == nil && !mapContainsExplicitNil(x, k) {
				// shouldn't happen; just guard
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		first := true
		for _, k := range keys {
			val := x[k]
			// Skip undefined (Go has no undefined, treat absent as absent)
			// Note: explicit nil values ARE encoded as "null" (matching Python None)
			if !first {
				buf.WriteByte(',')
			}
			first = false
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := canonicalizeInto(buf, val); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON cannot encode value of type %T", v)
	}
	return nil
}

func mapContainsExplicitNil(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

// writeCanonicalString matches Python's ensure_ascii=False behaviour:
// pass non-ASCII codepoints through unescaped; escape only the JSON
// control characters required by RFC 8259.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				// Includes all printable ASCII and ALL non-ASCII codepoints.
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// Helper for tests
func canonicalizeString(v any) (string, error) {
	b, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	return strings.Clone(string(b)), nil
}
