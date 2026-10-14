package httputil

import (
	"errors"
	"io"
	"testing"
)

type testCloser struct {
	calls int
	err   error
}

func (c *testCloser) Close() error { c.calls++; return c.err }

func TestReplayBody_PreservesCleanupWithoutBufferChains(t *testing.T) {
	original := &testCloser{err: errors.New("close failed")}
	first := ReplayBody([]byte("first"), original)
	second := ReplayBody([]byte("second"), first)
	if second.(*replayBody).Closer != original {
		t.Fatal("retained earlier replay buffer")
	}
	body, err := io.ReadAll(second)
	if err != nil || string(body) != "second" {
		t.Fatalf("body=%q: %v", body, err)
	}
	if err := second.Close(); !errors.Is(err, original.err) || original.calls != 1 {
		t.Fatalf("cleanup calls=%d: %v", original.calls, err)
	}
}
