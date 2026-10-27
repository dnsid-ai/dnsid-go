package sfv

import (
	"math"
	"strings"
	"testing"
)

func TestDictionary_CompleteRFC8941RoundTrip(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{` sig1=("@status" "@method"; req=?1); created=1; extension=1.500 `, `sig1=("@status" "@method";req);created=1;extension=1.5`},
		{`a=?1;x=?1, b=:YQ:`, `a;x, b=:YQ==:`},
		{`a=(123 -0.0 token "a\\b\"c");x=-999999999999.999`, `a=(123 0.0 token "a\\b\"c");x=-999999999999.999`},
	} {
		t.Run(tc.input, func(t *testing.T) {
			dict, err := NewParser(tc.input, DefaultLimits()).ParseDictionary()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := SerializeDictionary(dict)
			if err != nil || wire != tc.want {
				t.Fatalf("got %q, %v; want %q", wire, err, tc.want)
			}
		})
	}
}

func TestDictionary_RejectsMalformedAndRFC9651OnlyValues(t *testing.T) {
	for _, input := range []string{`a=1 garbage`, `a=1.5 garbage`, `a=1,`, `a=1,a=2`, `A=1`, `a =1`, `a= 1`, `a=@123`, `a=%"display"`, `a=("x"`, "a=(\"x\"\t\"y\")", "a=(\t\"x\")", `a=1.1234`, `a=1234567890123.0`, `a=1234567890123456`, `a="bad\escape"`, `a=:YQ==`, `a=("x")more`, "a=:YQ\n==:"} {
		t.Run(input, func(t *testing.T) {
			if _, err := NewParser(input, DefaultLimits()).ParseDictionary(); err == nil {
				t.Fatal("accepted malformed or unsupported field")
			}
		})
	}
}

func TestParser_Bounds(t *testing.T) {
	for _, tc := range []struct {
		input  string
		limits Limits
	}{
		{strings.Repeat(" ", 65537), DefaultLimits()},
		{`a=1,b=2`, func() Limits { l := DefaultLimits(); l.MaxDictionaryMembers = 1; return l }()},
		{`a=(1 2)`, func() Limits { l := DefaultLimits(); l.MaxInnerListMembers = 1; return l }()},
		{`a=1;x;y`, func() Limits { l := DefaultLimits(); l.MaxParameters = 1; return l }()},
		{`a="too long"`, func() Limits { l := DefaultLimits(); l.MaxStringLength = 1; return l }()},
		{`long=1`, func() Limits { l := DefaultLimits(); l.MaxTokenLength = 1; return l }()},
		{`a=:YWJjZGVm:`, func() Limits { l := DefaultLimits(); l.MaxByteSequenceLength = 1; return l }()},
	} {
		if _, err := NewParser(tc.input, tc.limits).ParseDictionary(); err == nil {
			t.Fatalf("accepted over limit %q", tc.input)
		}
	}
}

func TestSerialization_NumericTypesAndBounds(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  string
	}{
		{int64(1), "1"}, {1.0, "1.0"}, {1.5, "1.5"}, {1.2345, "1.234"}, {1.2355, "1.236"}, {999999999999.999, "999999999999.999"},
	} {
		wire, err := SerializeItem(Item{Value: tc.value})
		if err != nil || wire != tc.want {
			t.Fatalf("%v serialized as %q, %v", tc.value, wire, err)
		}
	}
	for _, value := range []any{math.NaN(), math.Inf(1), 1e12, int64(1000000000000000), Token{Value: "bad token"}} {
		if _, err := SerializeItem(Item{Value: value}); err == nil {
			t.Fatalf("serialized invalid value %v", value)
		}
	}
	if _, err := NewParser(`"component" junk`, DefaultLimits()).ParseItem(); err == nil {
		t.Fatal("ignored trailing component input")
	}
}
