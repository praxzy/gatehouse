package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

const (
	discoveryCacheControl = "public, max-age=3600"
	jwksCacheControl      = "public, max-age=300, stale-while-revalidate=60"
)

type OIDCMetadataService interface {
	DiscoveryDocument() oidc.DiscoveryDocument
	JSONWebKeySet() oidc.JSONWebKeySet
}

type oidcHandler struct {
	metadata OIDCMetadataService
}

func (handler oidcHandler) discovery(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writePublicJSON(
		writer,
		http.StatusOK,
		discoveryCacheControl,
		handler.metadata.DiscoveryDocument(),
	)
}

func (handler oidcHandler) jwks(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writePublicJSON(
		writer,
		http.StatusOK,
		jwksCacheControl,
		handler.metadata.JSONWebKeySet(),
	)
}

func writePublicJSON(
	writer http.ResponseWriter,
	status int,
	cacheControl string,
	value any,
) {
	writer.Header().Set(
		"Content-Type",
		"application/json",
	)
	writer.Header().Set(
		"Cache-Control",
		cacheControl,
	)
	writer.WriteHeader(status)

	_ = json.NewEncoder(writer).Encode(value)
}
