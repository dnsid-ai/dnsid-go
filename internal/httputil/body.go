// Package httputil contains HTTP content replay helpers.
package httputil

import (
	"bytes"
	"io"
)

type replayBody struct {
	io.Reader
	io.Closer
}

// ReplayBody preserves cleanup without retaining earlier buffered copies.
func ReplayBody(content []byte, original io.Closer) io.ReadCloser {
	if replay, ok := original.(*replayBody); ok {
		original = replay.Closer
	}
	return &replayBody{bytes.NewReader(content), original}
}
