// Package sfv provides bounded RFC 8941 parsing for HTTP signatures.
// Adapted from github.com/WebDecoy/web-bot-auth v0.4.1/httpsig/sfv.go.
// Copyright 2026 WebDecoy; Copyright 2025 Cloudflare, Inc.
// SPDX-License-Identifier: Apache-2.0
// Modified: complete parsing, finite limits, strict inner-list whitespace,
// compatible SDK types, and bounded canonical numeric serialization.
package sfv

import (
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"

	upstream "github.com/forcebit/http-message-signatures-rfc9421-go/pkg/sfv"
)

// Retain existing public bare-item types used by profile callers.
type Token = upstream.Token
type Item = upstream.Item
type Parameter = upstream.Parameter
type InnerList = upstream.InnerList
type Dictionary = upstream.Dictionary
type Limits = upstream.Limits

func DefaultLimits() Limits { return upstream.DefaultLimits() }

type Parser struct {
	s      string
	i      int
	limits Limits
}

func NewParser(s string, limits Limits) *Parser { return &Parser{s: s, limits: limits} }

func (p *Parser) ParseDictionary() (*Dictionary, error) {
	if len(p.s) > p.limits.MaxInputLength {
		return nil, fmt.Errorf("structured field exceeds input limit")
	}
	dict := &Dictionary{Values: map[string]interface{}{}}
	p.skipOWS()
	for !p.eof() {
		if len(dict.Keys) >= p.limits.MaxDictionaryMembers {
			return nil, fmt.Errorf("too many dictionary members")
		}
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		if _, exists := dict.Values[key]; exists {
			return nil, fmt.Errorf("duplicate dictionary key %q", key)
		}
		var value any
		if !p.eof() && p.peek() == '=' {
			p.i++
			if !p.eof() && p.peek() == '(' {
				value, err = p.parseInnerList()
			} else {
				value, err = p.parseItem()
			}
		} else {
			var params []Parameter
			params, err = p.parseParams()
			value = Item{Value: true, Parameters: params}
		}
		if err != nil {
			return nil, err
		}
		dict.Keys = append(dict.Keys, key)
		dict.Values[key] = value
		p.skipOWS()
		if p.eof() {
			break
		}
		if p.peek() != ',' {
			return nil, fmt.Errorf("expected comma at offset %d", p.i)
		}
		p.i++
		p.skipOWS()
		if p.eof() {
			return nil, fmt.Errorf("trailing dictionary comma")
		}
	}
	return dict, nil
}

func (p *Parser) ParseItem() (Item, error) {
	if len(p.s) > p.limits.MaxInputLength {
		return Item{}, fmt.Errorf("structured field exceeds input limit")
	}
	p.skipSP()
	item, err := p.parseItem()
	p.skipSP()
	if err == nil && !p.eof() {
		err = fmt.Errorf("trailing item input")
	}
	return item, err
}

func validKey(s string) bool {
	if s == "" || !isLCAlpha(s[0]) && s[0] != '*' {
		return false
	}
	for _, c := range []byte(s) {
		if !isLCAlpha(c) && !isDigit(c) && strings.IndexByte("_-.*", c) < 0 {
			return false
		}
	}
	return true
}

func SerializeDictionary(dict *Dictionary) (string, error) {
	var members []string
	seen := map[string]bool{}
	for _, key := range dict.Keys {
		if !validKey(key) || seen[key] {
			return "", fmt.Errorf("invalid or duplicate dictionary key")
		}
		seen[key] = true
		var wire string
		var err error
		switch member := dict.Values[key].(type) {
		case Item:
			if member.Value == true {
				wire, err = serializeParams(member.Parameters)
			} else {
				wire, err = SerializeItem(member)
				wire = "=" + wire
			}
		case InnerList:
			wire, err = SerializeInnerList(member)
			wire = "=" + wire
		default:
			return "", fmt.Errorf("unsupported dictionary member")
		}
		if err != nil {
			return "", err
		}
		members = append(members, key+wire)
	}
	return strings.Join(members, ", "), nil
}

func (p *Parser) eof() bool  { return p.i >= len(p.s) }
func (p *Parser) peek() byte { return p.s[p.i] }

func (p *Parser) skipOWS() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.i++
	}
}

func (p *Parser) skipSP() {
	for !p.eof() && p.peek() == ' ' {
		p.i++
	}
}

func isLCAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool   { return isLCAlpha(c) || (c >= 'A' && c <= 'Z') }

func (p *Parser) parseKey() (string, error) {
	if p.eof() || !isLCAlpha(p.peek()) && p.peek() != '*' {
		return "", fmt.Errorf("httpsig: invalid dictionary/parameter key at offset %d", p.i)
	}
	start := p.i
	for !p.eof() {
		c := p.peek()
		if isLCAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*' {
			p.i++
			continue
		}
		break
	}
	key := p.s[start:p.i]
	if len(key) > p.limits.MaxTokenLength {
		return "", fmt.Errorf("key exceeds limit")
	}
	return key, nil
}

func (p *Parser) parseItem() (Item, error) {
	v, err := p.parseBareItem()
	if err != nil {
		return Item{}, err
	}
	params, err := p.parseParams()
	if err != nil {
		return Item{}, err
	}
	return Item{Value: v, Parameters: params}, nil
}

func (p *Parser) parseInnerList() (InnerList, error) {
	if p.eof() || p.peek() != '(' {
		return InnerList{}, fmt.Errorf("httpsig: expected '(' at offset %d", p.i)
	}
	p.i++
	var list InnerList
	for {
		p.skipSP()
		if p.eof() {
			return InnerList{}, fmt.Errorf("httpsig: unterminated inner list")
		}
		if p.peek() == ')' {
			p.i++
			break
		}
		item, err := p.parseItem()
		if err != nil {
			return InnerList{}, err
		}
		if len(list.Items) >= p.limits.MaxInnerListMembers {
			return InnerList{}, fmt.Errorf("too many inner-list members")
		}
		list.Items = append(list.Items, item)
		if p.eof() {
			return InnerList{}, fmt.Errorf("httpsig: unterminated inner list")
		}
		if c := p.peek(); c != ' ' && c != ')' {
			return InnerList{}, fmt.Errorf("httpsig: expected space or ')' in inner list at offset %d", p.i)
		}
	}
	params, err := p.parseParams()
	if err != nil {
		return InnerList{}, err
	}
	list.Parameters = params
	return list, nil
}

func (p *Parser) parseParams() ([]Parameter, error) {
	var params []Parameter
	for !p.eof() && p.peek() == ';' {
		if len(params) >= p.limits.MaxParameters {
			return nil, fmt.Errorf("too many parameters")
		}
		p.i++
		p.skipSP()
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var val any = true
		if !p.eof() && p.peek() == '=' {
			p.i++
			val, err = p.parseBareItem()
			if err != nil {
				return nil, err
			}
		}
		params = append(params, Parameter{Key: key, Value: val})
	}
	return params, nil
}

func (p *Parser) parseBareItem() (any, error) {
	if p.eof() {
		return nil, fmt.Errorf("httpsig: expected bare item at end of input")
	}
	switch c := p.peek(); {
	case c == '"':
		return p.parseString()
	case c == ':':
		return p.parseByteSequence()
	case c == '?':
		return p.parseBoolean()
	case c == '-' || isDigit(c):
		return p.parseNumber()
	case isAlpha(c) || c == '*':
		return p.parseToken()
	default:
		return nil, fmt.Errorf("httpsig: invalid bare item at offset %d", p.i)
	}
}

func (p *Parser) parseString() (string, error) {
	p.i++ // opening DQUOTE
	var b strings.Builder
	for !p.eof() {
		c := p.peek()
		p.i++
		switch {
		case c == '"':
			if b.Len() > p.limits.MaxStringLength {
				return "", fmt.Errorf("string exceeds limit")
			}
			return b.String(), nil
		case c == '\\':
			if p.eof() {
				return "", fmt.Errorf("httpsig: unterminated escape in string")
			}
			e := p.peek()
			p.i++
			if e != '"' && e != '\\' {
				return "", fmt.Errorf("httpsig: invalid escape \\%c in string", e)
			}
			b.WriteByte(e)
		case c < 0x20 || c > 0x7e:
			return "", fmt.Errorf("httpsig: invalid character 0x%02x in string", c)
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("httpsig: unterminated string")
}

func (p *Parser) parseByteSequence() ([]byte, error) {
	p.i++ // opening ':'
	start := p.i
	for !p.eof() && p.peek() != ':' {
		p.i++
	}
	if p.eof() {
		return nil, fmt.Errorf("httpsig: unterminated byte sequence")
	}
	enc := p.s[start:p.i]
	if base64.StdEncoding.DecodedLen(len(enc)) > p.limits.MaxByteSequenceLength+2 {
		return nil, fmt.Errorf("byte sequence exceeds limit")
	}
	if strings.ContainsAny(enc, "\r\n") {
		return nil, fmt.Errorf("invalid byte sequence")
	}
	p.i++ // closing ':'
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(enc)
	}
	if err != nil {
		return nil, fmt.Errorf("httpsig: invalid base64 in byte sequence: %w", err)
	}
	if len(b) > p.limits.MaxByteSequenceLength {
		return nil, fmt.Errorf("byte sequence exceeds limit")
	}
	return b, nil
}

func (p *Parser) parseBoolean() (bool, error) {
	p.i++ // '?'
	if p.eof() {
		return false, fmt.Errorf("httpsig: unterminated boolean")
	}
	c := p.peek()
	p.i++
	switch c {
	case '1':
		return true, nil
	case '0':
		return false, nil
	default:
		return false, fmt.Errorf("httpsig: invalid boolean ?%c", c)
	}
}

func (p *Parser) parseNumber() (any, error) {
	start := p.i
	if p.peek() == '-' {
		p.i++
	}
	digits := 0
	for !p.eof() && isDigit(p.peek()) {
		p.i++
		digits++
	}
	if digits == 0 {
		return nil, fmt.Errorf("httpsig: invalid number at offset %d", start)
	}
	if !p.eof() && p.peek() == '.' {
		p.i++
		frac := 0
		for !p.eof() && isDigit(p.peek()) {
			p.i++
			frac++
		}
		if frac == 0 || frac > 3 || digits > 12 {
			return nil, fmt.Errorf("httpsig: invalid decimal at offset %d", start)
		}
		f, err := strconv.ParseFloat(p.s[start:p.i], 64)
		if err != nil {
			return nil, fmt.Errorf("httpsig: invalid decimal: %w", err)
		}
		return f, nil
	}
	if digits > 15 {
		return nil, fmt.Errorf("httpsig: integer too long at offset %d", start)
	}
	n, err := strconv.ParseInt(p.s[start:p.i], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("httpsig: invalid integer: %w", err)
	}
	return n, nil
}

func (p *Parser) parseToken() (Token, error) {
	start := p.i
	p.i++ // first char already validated
	for !p.eof() {
		c := p.peek()
		if isAlpha(c) || isDigit(c) || strings.IndexByte("!#$%&'*+-.^_`|~:/", c) >= 0 {
			p.i++
			continue
		}
		break
	}
	if p.i-start > p.limits.MaxTokenLength {
		return Token{}, fmt.Errorf("token exceeds limit")
	}
	return Token{Value: p.s[start:p.i]}, nil
}

// --- canonical serialization (RFC 8941 section 4) ---

func serializeBareItem(v any) (string, error) {
	switch t := v.(type) {
	case string:
		var b strings.Builder
		b.WriteByte('"')
		for i := 0; i < len(t); i++ {
			c := t[i]
			if c < 0x20 || c > 0x7e {
				return "", fmt.Errorf("httpsig: character 0x%02x not allowed in sf-string", c)
			}
			if c == '"' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		}
		b.WriteByte('"')
		return b.String(), nil
	case Token:
		if len(t.Value) == 0 || !isAlpha(t.Value[0]) && t.Value[0] != '*' {
			return "", fmt.Errorf("invalid token")
		}
		for _, c := range []byte(t.Value) {
			if !isAlpha(c) && !isDigit(c) && strings.IndexByte("!#$%&'*+-.^_`|~:/", c) < 0 {
				return "", fmt.Errorf("invalid token")
			}
		}
		return t.Value, nil
	case int:
		return serializeBareItem(int64(t))
	case int64:
		if t < -999999999999999 || t > 999999999999999 {
			return "", fmt.Errorf("integer out of range")
		}
		return strconv.FormatInt(t, 10), nil
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) || math.Abs(t) >= 1e12 {
			return "", fmt.Errorf("decimal out of range")
		}
		rounded := math.RoundToEven(t*1000) / 1000
		if math.Abs(rounded) >= 1e12 {
			return "", fmt.Errorf("decimal out of range")
		}
		if rounded == 0 {
			rounded = 0
		}
		s := strconv.FormatFloat(rounded, 'f', 3, 64)
		s = strings.TrimRight(s, "0")
		if strings.HasSuffix(s, ".") {
			s += "0"
		}
		return s, nil
	case bool:
		if t {
			return "?1", nil
		}
		return "?0", nil
	case []byte:
		return ":" + base64.StdEncoding.EncodeToString(t) + ":", nil
	default:
		return "", fmt.Errorf("httpsig: cannot serialize %T as bare item", v)
	}
}

func serializeParams(params []Parameter) (string, error) {
	var b strings.Builder
	for _, p := range params {
		if !validKey(p.Key) {
			return "", fmt.Errorf("invalid parameter key")
		}
		b.WriteByte(';')
		b.WriteString(p.Key)
		if v, ok := p.Value.(bool); ok && v {
			continue // boolean true parameters serialize as bare keys
		}
		s, err := serializeBareItem(p.Value)
		if err != nil {
			return "", err
		}
		b.WriteByte('=')
		b.WriteString(s)
	}
	return b.String(), nil
}

func SerializeItem(item Item) (string, error) {
	v, err := serializeBareItem(item.Value)
	if err != nil {
		return "", err
	}
	p, err := serializeParams(item.Parameters)
	if err != nil {
		return "", err
	}
	return v + p, nil
}

func SerializeInnerList(list InnerList) (string, error) {
	var b strings.Builder
	b.WriteByte('(')
	for i, item := range list.Items {
		if i > 0 {
			b.WriteByte(' ')
		}
		s, err := SerializeItem(item)
		if err != nil {
			return "", err
		}
		b.WriteString(s)
	}
	b.WriteByte(')')
	p, err := serializeParams(list.Parameters)
	if err != nil {
		return "", err
	}
	return b.String() + p, nil
}
