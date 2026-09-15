package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// DecodeObject rejects duplicate members at every depth and invalid UTF-8.
func DecodeObject(data []byte, useNumber bool) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid or oversized JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if useNumber {
		d.UseNumber()
	}
	value, err := decodeValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON object required")
	}
	return obj, nil
}

func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("JSON nesting limit exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		obj := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("invalid member name")
			}
			if _, exists := obj[name]; exists {
				return nil, fmt.Errorf("duplicate JSON member %q", name)
			}
			value, err := decodeValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			obj[name] = value
		}
		_, err := d.Token()
		return obj, err
	case json.Delim('['):
		values := []any{}
		for d.More() {
			value, err := decodeValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		_, err := d.Token()
		return values, err
	default:
		return token, nil
	}
}
