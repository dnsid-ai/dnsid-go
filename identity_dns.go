package dnsid

import (
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
)

// isDNSNotFound recognizes both NXDOMAIN and NODATA from Go resolvers,
// including wrapped errors, without treating transport failures as absence.
func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound && !dnsErr.IsTimeout && !dnsErr.IsTemporary
}

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
