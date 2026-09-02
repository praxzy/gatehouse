package audit

import (
	"context"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const (
	maxRequestIDBytes = 100
	maxUserAgentBytes = 512
)

type RequestDetails struct {
	RequestID string
	SourceIP  *netip.Addr
	UserAgent string
}

type requestDetailsContextKey struct{}

func NewRequestDetails(
	requestID string,
	sourceIP *netip.Addr,
	userAgent string,
) RequestDetails {
	requestID = truncateUTF8(
		strings.TrimSpace(requestID),
		maxRequestIDBytes,
	)

	userAgent = truncateUTF8(
		strings.TrimSpace(userAgent),
		maxUserAgentBytes,
	)

	if sourceIP != nil && !sourceIP.IsValid() {
		sourceIP = nil
	}

	return RequestDetails{
		RequestID: requestID,
		SourceIP:  sourceIP,
		UserAgent: userAgent,
	}
}

func WithRequestDetails(
	ctx context.Context,
	details RequestDetails,
) context.Context {
	return context.WithValue(
		ctx,
		requestDetailsContextKey{},
		details,
	)
}

func RequestDetailsFromContext(
	ctx context.Context,
) (RequestDetails, bool) {
	details, ok := ctx.Value(
		requestDetailsContextKey{},
	).(RequestDetails)

	return details, ok
}

func EnrichFromContext(
	ctx context.Context,
	event Event,
) Event {
	details, ok := RequestDetailsFromContext(ctx)
	if !ok {
		return event
	}

	if event.RequestID == "" {
		event.RequestID = details.RequestID
	}

	if event.SourceIP == nil && details.SourceIP != nil {
		sourceIP := *details.SourceIP
		event.SourceIP = &sourceIP
	}

	if event.UserAgent == "" {
		event.UserAgent = details.UserAgent
	}

	return event
}

func truncateUTF8(value string, maximumBytes int) string {
	if len(value) <= maximumBytes {
		return value
	}

	value = value[:maximumBytes]

	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}

	return value
}
