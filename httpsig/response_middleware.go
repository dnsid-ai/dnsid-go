package httpsig

import (
	"bytes"
	"io"
	"net/http"
)

// ResponseSigningMiddleware signs responses for requests that carry
// Accept-Signature. Requests without negotiation pass through unbuffered.
// Negotiated responses are buffered up to 8 MiB and signed with
// SignRequestedHTTPResponse before any header is sent. On a signing failure or
// an exceeded bound it sends a 500 without the handler's headers or content; it
// never sends the unsigned response. Place it after request verification and
// authorization, and after any middleware that changes the status, covered
// headers, or content coding. Buffered handlers cannot flush, hijack, or send
// informational responses.
func (p *Profile) ResponseSigningMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hasResponseHeader(r.Header, "Accept-Signature") {
			next.ServeHTTP(w, r)
			return
		}
		buffered := &bufferedResponseWriter{header: http.Header{}}
		next.ServeHTTP(buffered, r)
		if buffered.status == 0 {
			buffered.status = http.StatusOK
		}
		if buffered.overflow {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		res := &http.Response{
			StatusCode: buffered.status, Header: buffered.header, Request: r,
			Proto: r.Proto, ProtoMajor: r.ProtoMajor, ProtoMinor: r.ProtoMinor,
			Body: io.NopCloser(bytes.NewReader(buffered.body.Bytes())), ContentLength: int64(buffered.body.Len()),
		}
		signed, err := p.SignRequestedHTTPResponse(r, res)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer signed.Body.Close()
		for name, values := range signed.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(signed.StatusCode)
		if r.Method != http.MethodHead && !noResponseContent(signed.StatusCode) {
			_, _ = io.Copy(w, signed.Body)
		}
	})
}

func noResponseContent(status int) bool {
	return status == http.StatusNoContent || status == http.StatusResetContent || status == http.StatusNotModified
}

type bufferedResponseWriter struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	overflow bool
}

func (w *bufferedResponseWriter) Header() http.Header { return w.header }

func (w *bufferedResponseWriter) WriteHeader(status int) {
	// Informational responses cannot be signed and are not sent in buffered mode.
	if w.status == 0 && status >= 200 {
		w.status = status
	}
}

func (w *bufferedResponseWriter) Write(content []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	if w.body.Len()+len(content) > 8<<20 {
		w.overflow = true
		return 0, http.ErrContentLength
	}
	return w.body.Write(content)
}
