package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientAddressContextKey struct{}

func resolveClientAddress(
	trustProxyHeaders bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			address, err := requestClientAddress(
				request,
				trustProxyHeaders,
			)
			if err != nil {
				writeError(
					writer,
					http.StatusBadRequest,
					"invalid client address",
				)
				return
			}

			ctx := context.WithValue(
				request.Context(),
				clientAddressContextKey{},
				address,
			)

			next.ServeHTTP(
				writer,
				request.WithContext(ctx),
			)
		})
	}
}

func requestClientAddress(
	request *http.Request,
	trustProxyHeaders bool,
) (netip.Addr, error) {
	if trustProxyHeaders {
		values := request.Header.Values(
			"X-Forwarded-For",
		)

		for valueIndex := len(values) - 1; valueIndex >= 0; valueIndex-- {
			parts := strings.Split(
				values[valueIndex],
				",",
			)

			for partIndex := len(parts) - 1; partIndex >= 0; partIndex-- {
				candidate := strings.TrimSpace(
					parts[partIndex],
				)
				if candidate == "" {
					continue
				}

				return parseClientAddress(candidate)
			}
		}
	}

	return parseClientAddress(request.RemoteAddr)
}

func parseClientAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)

	address, err := netip.ParseAddr(value)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(value)
		if splitErr != nil {
			return netip.Addr{}, err
		}

		address, err = netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, err
		}
	}

	if address.Zone() != "" {
		return netip.Addr{}, &net.AddrError{
			Err:  "IPv6 zones are not allowed",
			Addr: value,
		}
	}

	return address.Unmap(), nil
}

func directClientAddress(
	request *http.Request,
) (netip.Addr, error) {
	if address, ok := request.Context().Value(
		clientAddressContextKey{},
	).(netip.Addr); ok && address.IsValid() {
		return address, nil
	}

	return parseClientAddress(request.RemoteAddr)
}

func directClientIP(request *http.Request) (string, error) {
	address, err := directClientAddress(request)
	if err != nil {
		return "", err
	}

	return address.String(), nil
}
