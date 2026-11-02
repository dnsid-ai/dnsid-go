package c2sptlog

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// StreamHeadStatementType is the first line of a stream-head statement.
const StreamHeadStatementType = "dnsid-c2sp-stream-head@v1"

// StreamHead is the dnsid-c2sp-stream-head@v1 statement that a stream indexer
// signs as a C2SP signed note. It asserts that, in the tree with TreeSize and
// RootHash, the stream LR has a non-empty applied history with no
// authenticated conflict whose last applied logical event is HeadEventID.
type StreamHead struct {
	LR          string
	TreeSize    uint64
	RootHash    []byte
	HeadEventID string
	Expires     time.Time
}

// MarshalText returns the exact signed-note text of the statement. Expires is
// encoded in whole Unix seconds.
func (h StreamHead) MarshalText() ([]byte, error) {
	text := fmt.Appendf(nil, "%s\nlr %s\ncheckpoint %d %s\nhead %s\nexpires %d\n",
		StreamHeadStatementType, h.LR, h.TreeSize, base64.StdEncoding.EncodeToString(h.RootHash), h.HeadEventID, h.Expires.Unix())
	// Round-trip so producers cannot emit a statement that verifiers reject.
	if _, err := ParseStreamHead(text); err != nil {
		return nil, err
	}
	return text, nil
}

// ParseStreamHead strictly parses statement text: exact lines in order, one
// space between fields, a canonical lr, canonical decimal integers no larger
// than 2^53-1, a canonical 32-byte base64 root hash, and a logical event ID.
func ParseStreamHead(text []byte) (StreamHead, error) {
	invalid := func(reason string) (StreamHead, error) {
		return StreamHead{}, fmt.Errorf("dnsid: invalid c2sp stream-head statement: %s", reason)
	}
	lines := strings.Split(string(text), "\n")
	if len(lines) != 6 || lines[5] != "" {
		return invalid("want exactly five newline-terminated lines")
	}
	if lines[0] != StreamHeadStatementType {
		return invalid("unsupported statement type")
	}
	fields := func(line, keyword string, count int) ([]string, bool) {
		parts := strings.Split(line, " ")
		return parts[1:], len(parts) == count+1 && parts[0] == keyword
	}
	var head StreamHead
	lr, ok := fields(lines[1], "lr", 1)
	if !ok {
		return invalid("malformed lr line")
	}
	ref, err := ParseReference(lr[0])
	if err != nil || ref.String() != lr[0] {
		return invalid("lr is not a canonical c2sp-tlog reference")
	}
	head.LR = lr[0]
	checkpoint, ok := fields(lines[2], "checkpoint", 2)
	if !ok {
		return invalid("malformed checkpoint line")
	}
	if head.TreeSize, ok = parseStatementInteger(checkpoint[0]); !ok {
		return invalid("tree size is not a canonical integer")
	}
	if head.RootHash, ok = decodeCanonicalStdBase64(checkpoint[1]); !ok || len(head.RootHash) != 32 {
		return invalid("root hash is not canonical base64 of 32 bytes")
	}
	id, ok := fields(lines[3], "head", 1)
	if !ok || !validHash(id[0]) {
		return invalid("malformed head line")
	}
	head.HeadEventID = id[0]
	expires, ok := fields(lines[4], "expires", 1)
	if !ok {
		return invalid("malformed expires line")
	}
	seconds, ok := parseStatementInteger(expires[0])
	if !ok {
		return invalid("expires is not a canonical integer")
	}
	head.Expires = time.Unix(int64(seconds), 0).UTC()
	return head, nil
}

// OpenStreamHead verifies a signed stream-head note with the accepted
// stream-head verifiers and parses its statement. It returns the statement and
// the "<name>+<hash>" key ID of the first verified signature. Signatures by
// unknown keys are ignored, as signed-note specifies.
func OpenStreamHead(msg []byte, verifiers []note.Verifier) (StreamHead, string, error) {
	if len(verifiers) == 0 {
		return StreamHead{}, "", fmt.Errorf("dnsid: c2sp stream-head verifier is required")
	}
	if err := requireCanonicalNoteSignatures(msg); err != nil {
		return StreamHead{}, "", err
	}
	opened, err := note.Open(msg, note.VerifierList(verifiers...))
	if err != nil {
		var unverified *note.UnverifiedNoteError
		if errors.As(err, &unverified) {
			return StreamHead{}, "", fmt.Errorf("dnsid: c2sp stream-head signer is not accepted")
		}
		return StreamHead{}, "", fmt.Errorf("dnsid: c2sp stream-head signature verification failed: %w", err)
	}
	head, err := ParseStreamHead([]byte(opened.Text))
	if err != nil {
		return StreamHead{}, "", err
	}
	sig := opened.Sigs[0]
	return head, fmt.Sprintf("%s+%08x", sig.Name, sig.Hash), nil
}

// requireCanonicalNoteSignatures rejects non-canonical base64 in signature
// lines (signed-note v1.1.0); x/mod/sumdb/note decodes them leniently.
func requireCanonicalNoteSignatures(msg []byte) error {
	split := bytes.LastIndex(msg, []byte("\n\n"))
	if split < 0 {
		return nil // note.Open reports the malformed note.
	}
	for _, line := range strings.Split(string(msg[split+2:]), "\n") {
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			continue
		}
		_, signature, ok := strings.Cut(rest, " ")
		if ok {
			if _, canonical := decodeCanonicalStdBase64(signature); !canonical {
				return fmt.Errorf("dnsid: signed note signature is not canonical base64")
			}
		}
	}
	return nil
}

func decodeCanonicalStdBase64(value string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return decoded, err == nil && base64.StdEncoding.EncodeToString(decoded) == value
}

func parseStatementInteger(value string) (uint64, bool) {
	if !decimalDigits(value) || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil && parsed <= maxJSONInteger
}
