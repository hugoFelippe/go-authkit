package contracts

import "errors"

// Error codes para identificação específica de erros
const (
	ErrCodeInvalidToken       = "INVALID_TOKEN"
	ErrCodeExpiredToken       = "EXPIRED_TOKEN"
	ErrCodeTokenNotFound      = "TOKEN_NOT_FOUND"
	ErrCodeTokenRevoked       = "TOKEN_REVOKED"
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeUserNotFound       = "USER_NOT_FOUND"
	ErrCodeUserInactive       = "USER_INACTIVE"
	ErrCodeUserEmailExists    = "USER_EMAIL_EXISTS"
	ErrCodeUserUsernameExists = "USER_USERNAME_EXISTS"
	ErrCodeInvalidUserID      = "INVALID_USER_ID"
	ErrCodeSessionNotFound    = "SESSION_NOT_FOUND"
	ErrCodeSessionExpired     = "SESSION_EXPIRED"
	ErrCodeInvalidSession     = "INVALID_SESSION"
	ErrCodeInvalidSessionID   = "INVALID_SESSION_ID"
	ErrCodeConfigNotFound     = "CONFIG_NOT_FOUND"
	ErrCodeCacheKeyNotFound   = "CACHE_KEY_NOT_FOUND"
	ErrCodeInsufficientScope  = "INSUFFICIENT_SCOPE"
	ErrCodeInsufficientRole   = "INSUFFICIENT_ROLE"
	ErrCodePermissionDenied   = "PERMISSION_DENIED"
	ErrCodeInvalidAPIKey      = "INVALID_API_KEY"
	ErrCodeAPIKeyExpired      = "API_KEY_EXPIRED"
	ErrCodeInvalidSignature   = "INVALID_SIGNATURE"
	ErrCodeInvalidIssuer      = "INVALID_ISSUER"
	ErrCodeInvalidAudience    = "INVALID_AUDIENCE"
	ErrCodeStorageError       = "STORAGE_ERROR"
	ErrCodeConfigurationError = "CONFIGURATION_ERROR"
	ErrCodeProviderError      = "PROVIDER_ERROR"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeRateLimitExceeded  = "RATE_LIMIT_EXCEEDED"
)

// AuthError representa um erro de autenticação com código específico.
type AuthError struct {
	Code    string
	Message string
	Cause   error
}

func (e *AuthError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *AuthError) Unwrap() error {
	return e.Cause
}

// NewAuthError cria um novo erro de autenticação.
func NewAuthError(code, message string, cause error) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Erros predefinidos
var (
	ErrInvalidToken       = NewAuthError(ErrCodeInvalidToken, "invalid token", nil)
	ErrExpiredToken       = NewAuthError(ErrCodeExpiredToken, "token expired", nil)
	ErrTokenNotFound      = NewAuthError(ErrCodeTokenNotFound, "token not found", nil)
	ErrTokenRevoked       = NewAuthError(ErrCodeTokenRevoked, "token revoked", nil)
	ErrInvalidCredentials = NewAuthError(ErrCodeInvalidCredentials, "invalid credentials", nil)
	ErrUserNotFound       = NewAuthError(ErrCodeUserNotFound, "user not found", nil)
	ErrUserInactive       = NewAuthError(ErrCodeUserInactive, "user inactive", nil)
	ErrUserEmailExists    = NewAuthError(ErrCodeUserEmailExists, "user email already exists", nil)
	ErrUserUsernameExists = NewAuthError(ErrCodeUserUsernameExists, "username already exists", nil)
	ErrInvalidUserID      = NewAuthError(ErrCodeInvalidUserID, "invalid user ID", nil)
	ErrSessionNotFound    = NewAuthError(ErrCodeSessionNotFound, "session not found", nil)
	ErrSessionExpired     = NewAuthError(ErrCodeSessionExpired, "session expired", nil)
	ErrInvalidSession     = NewAuthError(ErrCodeInvalidSession, "invalid session", nil)
	ErrInvalidSessionID   = NewAuthError(ErrCodeInvalidSessionID, "invalid session ID", nil)
	ErrConfigNotFound     = NewAuthError(ErrCodeConfigNotFound, "configuration not found", nil)
	ErrCacheKeyNotFound   = NewAuthError(ErrCodeCacheKeyNotFound, "cache key not found", nil)
	ErrInsufficientScope  = NewAuthError(ErrCodeInsufficientScope, "insufficient scope", nil)
	ErrInsufficientRole   = NewAuthError(ErrCodeInsufficientRole, "insufficient role", nil)
	ErrPermissionDenied   = NewAuthError(ErrCodePermissionDenied, "permission denied", nil)
	ErrInvalidAPIKey      = NewAuthError(ErrCodeInvalidAPIKey, "invalid API key", nil)
	ErrAPIKeyExpired      = NewAuthError(ErrCodeAPIKeyExpired, "API key expired", nil)
	ErrInvalidSignature   = NewAuthError(ErrCodeInvalidSignature, "invalid signature", nil)
	ErrInvalidIssuer      = NewAuthError(ErrCodeInvalidIssuer, "invalid issuer", nil)
	ErrInvalidAudience    = NewAuthError(ErrCodeInvalidAudience, "invalid audience", nil)
	ErrStorageError       = NewAuthError(ErrCodeStorageError, "storage error", nil)
	ErrConfigurationError = NewAuthError(ErrCodeConfigurationError, "configuration error", nil)
	ErrProviderError      = NewAuthError(ErrCodeProviderError, "provider error", nil)
	ErrUnauthorized       = NewAuthError(ErrCodeUnauthorized, "unauthorized", nil)
	ErrForbidden          = NewAuthError(ErrCodeForbidden, "forbidden", nil)
	ErrRateLimitExceeded  = NewAuthError(ErrCodeRateLimitExceeded, "rate limit exceeded", nil)
)

// IsAuthError verifica se um erro é do tipo AuthError.
func IsAuthError(err error) bool {
	var authErr *AuthError
	return errors.As(err, &authErr)
}

// GetErrorCode extrai o código de erro de um AuthError.
func GetErrorCode(err error) string {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Code
	}
	return ""
}

// WrapError encapsula um erro em um AuthError.
func WrapError(code, message string, cause error) error {
	return NewAuthError(code, message, cause)
}
