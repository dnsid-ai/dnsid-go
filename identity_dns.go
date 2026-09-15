package dnsid

import (
	"fmt"
	"io"
	"regexp"
)

// hostnameRegex matches RFC-1123 FQDNs (at least two labels, valid chars).
var hostnameRegex = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

func readLimited(r io.Reader, max int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, fmt.Errorf("response body exceeds %d bytes", max)
	}
	return data, nil
}
