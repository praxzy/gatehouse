package federation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidProviderRequest = errors.New(
		"invalid upstream provider request",
	)
	ErrUnsafeProviderURL = errors.New(
		"unsafe upstream provider URL",
	)
	ErrUnsafeProviderAddress = errors.New(
		"unsafe upstream provider address",
	)
)

type ProviderNetworkPolicy struct {
	AllowHTTP             bool
	AllowPrivateAddresses bool
}

type ProviderHTTPClient struct {
	httpClient *http.Client
	policy     ProviderNetworkPolicy
}

func NewProviderHTTPClient(
	policy ProviderNetworkPolicy,
) *ProviderHTTPClient {
	safeDialer := &providerDialer{
		policy:   policy,
		resolver: net.DefaultResolver,
		dialer: &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           safeDialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	return &ProviderHTTPClient{
		policy: policy,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(
				_ *http.Request,
				_ []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (client *ProviderHTTPClient) Do(
	request *http.Request,
) (*http.Response, error) {
	if client == nil ||
		client.httpClient == nil ||
		request == nil ||
		request.URL == nil {
		return nil, ErrInvalidProviderRequest
	}

	if err := validateProviderURL(
		request.URL,
		client.policy,
	); err != nil {
		return nil, err
	}

	return client.httpClient.Do(request)
}

func parseProviderURL(
	rawURL string,
	policy ProviderNetworkPolicy,
) (*url.URL, error) {
	if rawURL == "" ||
		rawURL != strings.TrimSpace(rawURL) {
		return nil, ErrUnsafeProviderURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, ErrUnsafeProviderURL
	}

	if err := validateProviderURL(
		parsed,
		policy,
	); err != nil {
		return nil, err
	}

	return parsed, nil
}

func validateProviderURL(
	target *url.URL,
	policy ProviderNetworkPolicy,
) error {
	if target == nil ||
		!target.IsAbs() ||
		target.Host == "" ||
		target.User != nil ||
		target.Fragment != "" {
		return ErrUnsafeProviderURL
	}

	switch target.Scheme {
	case "https":
	case "http":
		if !policy.AllowHTTP {
			return ErrUnsafeProviderURL
		}
	default:
		return ErrUnsafeProviderURL
	}

	hostname := strings.ToLower(target.Hostname())
	if hostname == "" ||
		hostname == "localhost" ||
		strings.HasSuffix(hostname, ".localhost") ||
		strings.Contains(hostname, "%") {
		if !policy.AllowPrivateAddresses {
			return ErrUnsafeProviderAddress
		}
	}

	if address, err := netip.ParseAddr(hostname); err == nil {
		if unsafeProviderAddress(address) &&
			!policy.AllowPrivateAddresses {
			return ErrUnsafeProviderAddress
		}
	}

	return nil
}

type providerDialer struct {
	policy   ProviderNetworkPolicy
	resolver *net.Resolver
	dialer   *net.Dialer
}

func (dialer *providerDialer) DialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	if dialer == nil ||
		dialer.resolver == nil ||
		dialer.dialer == nil {
		return nil, ErrInvalidProviderRequest
	}

	if dialer.policy.AllowPrivateAddresses {
		return dialer.dialer.DialContext(
			ctx,
			network,
			address,
		)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrUnsafeProviderAddress,
			err,
		)
	}

	if strings.Contains(host, "%") {
		return nil, ErrUnsafeProviderAddress
	}

	if parsed, err := netip.ParseAddr(host); err == nil {
		if unsafeProviderAddress(parsed) {
			return nil, ErrUnsafeProviderAddress
		}

		return dialer.dialer.DialContext(
			ctx,
			network,
			address,
		)
	}

	resolved, err := dialer.resolver.LookupNetIP(
		ctx,
		"ip",
		host,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve upstream provider: %w",
			err,
		)
	}
	if len(resolved) == 0 {
		return nil, ErrUnsafeProviderAddress
	}

	for _, resolvedAddress := range resolved {
		if unsafeProviderAddress(resolvedAddress) {
			return nil, ErrUnsafeProviderAddress
		}
	}

	var lastErr error
	for _, resolvedAddress := range resolved {
		connection, err := dialer.dialer.DialContext(
			ctx,
			network,
			net.JoinHostPort(
				resolvedAddress.String(),
				port,
			),
		)
		if err == nil {
			return connection, nil
		}

		lastErr = err
	}

	return nil, fmt.Errorf(
		"dial upstream provider: %w",
		lastErr,
	)
}

func unsafeProviderAddress(address netip.Addr) bool {
	if !address.IsValid() {
		return true
	}

	address = address.Unmap()

	if !address.IsGlobalUnicast() ||
		address.IsPrivate() ||
		address.IsLoopback() ||
		address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() ||
		address.IsMulticast() ||
		address.IsUnspecified() {
		return true
	}

	carrierGradeNAT := netip.MustParsePrefix(
		"100.64.0.0/10",
	)

	return carrierGradeNAT.Contains(address)
}
