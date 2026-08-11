package httpapi

import (
	"errors"
	"net/http"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type mfaCodeRequest struct {
	Code string `json:"code"`
}

type recoveryCodeRequest struct {
	RecoveryCode string `json:"recovery_code"`
}

type totpEnrollmentResponse struct {
	ProvisioningURI string `json:"provisioning_uri"`
	ManualKey       string `json:"manual_key"`
}

type mfaConfirmationResponse struct {
	AuthenticationLevel string   `json:"authentication_level"`
	RecoveryCodes       []string `json:"recovery_codes"`
}

type mfaChallengeResponse struct {
	AuthenticationLevel string `json:"authentication_level"`
	ExpiresAt           string `json:"expires_at"`
}

func (handler authHandler) beginTOTPEnrollment(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	result, err := handler.authentication.BeginTOTPEnrollment(
		request.Context(),
		session,
	)
	if err != nil {
		writeMFAError(writer, err)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		totpEnrollmentResponse{
			ProvisioningURI: result.ProvisioningURI,
			ManualKey:       result.ManualKey,
		},
	)
}

func (handler authHandler) confirmTOTPEnrollment(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	var body mfaCodeRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request")
		return
	}

	result, err := handler.authentication.ConfirmTOTPEnrollment(
		request.Context(),
		session,
		body.Code,
	)
	if err != nil {
		writeMFAError(writer, err)
		return
	}

	handler.sessionCookie.Set(
		writer,
		result.Session.Token,
		result.Session.ExpiresAt,
	)

	writeJSON(
		writer,
		http.StatusOK,
		mfaConfirmationResponse{
			AuthenticationLevel: "mfa",
			RecoveryCodes:       result.RecoveryCodes,
		},
	)
}

func (handler authHandler) completeTOTPChallenge(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	var body mfaCodeRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request")
		return
	}

	result, err := handler.authentication.CompleteMFAWithTOTP(
		request.Context(),
		session,
		body.Code,
	)
	if err != nil {
		writeMFAError(writer, err)
		return
	}

	writeMFAChallengeSuccess(writer, handler, result)
}

func (handler authHandler) completeRecoveryChallenge(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	var body recoveryCodeRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request")
		return
	}

	result, err := handler.authentication.CompleteMFAWithRecoveryCode(
		request.Context(),
		session,
		body.RecoveryCode,
	)
	if err != nil {
		writeMFAError(writer, err)
		return
	}

	writeMFAChallengeSuccess(writer, handler, result)
}

func writeMFAChallengeSuccess(
	writer http.ResponseWriter,
	handler authHandler,
	result auth.MFAChallengeResult,
) {
	handler.sessionCookie.Set(
		writer,
		result.Session.Token,
		result.Session.ExpiresAt,
	)

	writeJSON(
		writer,
		http.StatusOK,
		mfaChallengeResponse{
			AuthenticationLevel: "mfa",
			ExpiresAt: result.Session.ExpiresAt.UTC().Format(
				timeFormat,
			),
		},
	)
}

func writeMFAError(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(err, auth.ErrInvalidMFAChallenge):
		writeError(
			writer,
			http.StatusUnauthorized,
			"invalid MFA challenge",
		)

	case errors.Is(err, auth.ErrInvalidSession):
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)

	case errors.Is(err, auth.ErrMFAAlreadyEnrolled):
		writeError(
			writer,
			http.StatusConflict,
			"MFA is already enrolled",
		)

	case errors.Is(err, auth.ErrMFAEnrollmentNotFound):
		writeError(
			writer,
			http.StatusConflict,
			"pending MFA enrollment not found",
		)

	case errors.Is(err, auth.ErrMFAAlreadySatisfied):
		writeError(
			writer,
			http.StatusConflict,
			"MFA is already satisfied",
		)

	case errors.Is(err, auth.ErrMFAUnavailable):
		writeError(
			writer,
			http.StatusServiceUnavailable,
			"MFA is unavailable",
		)

	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
	}
}
