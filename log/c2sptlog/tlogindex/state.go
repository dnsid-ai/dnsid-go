package tlogindex

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// StateEntryHeader is the first line of an index state entry.
const StateEntryHeader = "dnsid.org/tlog-index-state@v1"

// maxStateEntryLen bounds parsing: the header, two decimal-free hash lines
// and a 20-digit size fit well inside it.
const maxStateEntryLen = 256

// StateEntry is an index state commitment appended to the indexed log. It
// commits the MPT root over the keys mapped from entries [0, InputSize) and
// the RFC 6962 root of the log at InputSize. Its exact text form is four
// newline-terminated lines:
//
//	dnsid.org/tlog-index-state@v1
//	input-size <decimal InputSize>
//	input-root <base64 InputRoot>
//	mpt-root <base64 MPTRoot>
//
// The decimal has no sign and no leading zeros ("0" for zero). The base64 is
// standard RFC 4648 Section 4 base64 with "=" padding, matching the
// tlog-vindex conventions; encoders produce canonical base64 and the parser
// rejects any non-canonical encoding. There is no carriage return, no
// trailing whitespace and nothing after the fourth newline. The index start
// is always 0, so unlike the tlog-vindex state entry there is no "from" line,
// and the input log origin is implied by the log the entry is in.
type StateEntry struct {
	InputSize uint64
	InputRoot Hash
	MPTRoot   Hash
}

// Marshal returns the canonical text form of s.
func (s StateEntry) Marshal() []byte {
	var b bytes.Buffer
	b.WriteString(StateEntryHeader + "\n")
	b.WriteString("input-size " + strconv.FormatUint(s.InputSize, 10) + "\n")
	b.WriteString("input-root " + base64.StdEncoding.EncodeToString(s.InputRoot[:]) + "\n")
	b.WriteString("mpt-root " + base64.StdEncoding.EncodeToString(s.MPTRoot[:]) + "\n")
	return b.Bytes()
}

// IsStateEntry reports whether entry starts with the state entry header
// line. It does not validate the rest of the entry.
func IsStateEntry(entry []byte) bool {
	return bytes.HasPrefix(entry, []byte(StateEntryHeader+"\n"))
}

// ParseStateEntry parses the exact text form documented on StateEntry and
// rejects anything else.
func ParseStateEntry(entry []byte) (StateEntry, error) {
	if len(entry) > maxStateEntryLen {
		return StateEntry{}, errors.New("tlogindex: state entry too long")
	}
	text := string(entry)
	if !strings.HasSuffix(text, "\n") {
		return StateEntry{}, errors.New("tlogindex: state entry must end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 4 {
		return StateEntry{}, fmt.Errorf("tlogindex: state entry has %d lines, want 4", len(lines))
	}
	if lines[0] != StateEntryHeader {
		return StateEntry{}, errors.New("tlogindex: state entry header mismatch")
	}
	var s StateEntry
	sizeText, ok := strings.CutPrefix(lines[1], "input-size ")
	if !ok {
		return StateEntry{}, errors.New("tlogindex: state entry missing input-size")
	}
	size, err := parseDecimal(sizeText)
	if err != nil {
		return StateEntry{}, err
	}
	s.InputSize = size
	if s.InputRoot, err = parseHashLine(lines[2], "input-root "); err != nil {
		return StateEntry{}, err
	}
	if s.MPTRoot, err = parseHashLine(lines[3], "mpt-root "); err != nil {
		return StateEntry{}, err
	}
	return s, nil
}

func parseDecimal(text string) (uint64, error) {
	if text == "" || len(text) > 20 || (len(text) > 1 && text[0] == '0') {
		return 0, fmt.Errorf("tlogindex: invalid decimal %q", text)
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, fmt.Errorf("tlogindex: invalid decimal %q", text)
		}
	}
	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("tlogindex: invalid decimal %q", text)
	}
	return v, nil
}

func parseHashLine(line, prefix string) (Hash, error) {
	text, ok := strings.CutPrefix(line, prefix)
	if !ok {
		return Hash{}, fmt.Errorf("tlogindex: state entry missing %q", strings.TrimSpace(prefix))
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) != HashSize || base64.StdEncoding.EncodeToString(decoded) != text {
		return Hash{}, fmt.Errorf("tlogindex: state entry %s must be canonical padded base64 of 32 bytes", strings.TrimSpace(prefix))
	}
	return Hash(decoded), nil
}
