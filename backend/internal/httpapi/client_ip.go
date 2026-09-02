package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func directClientAddress(
	request *http.Request,
) (netip.Addr, error) {
	remoteAddress := strings.TrimSpace(request.RemoteAddr)

	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}

	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}

	return address.Unmap(), nil
}

func directClientIP(request *http.Request) (string, error) {
	address, err := directClientAddress(request)
	if err != nil {
		return "", err
	}

	return address.String(), nil
}
