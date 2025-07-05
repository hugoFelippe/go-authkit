package authkit

import (
	"errors"
	"fmt"
)

// Error codes para diferentes tipos de erros de autenticação
const (
	ErrCodeInvalidToken       = "INVALID_TOKEN"
	ErrCodeExpiredToken       = "EXPIRED_TOKEN"
	ErrCodeInsufficientScope  = "INSUFFICIENT_SCOPE"
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeInvalidSignature   = "INVALID_SIGNATURE"
	ErrCodeTokenNotFound      = "TOKEN_NOT_FOUND"
	ErrCodeUserNotFound       = "USER_NOT_FOUND"
	ErrCodeInvalidConfig      = "INVALID_CONFIG"
	ErrCodeProviderError      = "PROVIDER_ERROR"
	ErrCodeInvalidGrant       = "INVALID_GRANT"
	ErrCodeInvalidClient      = "INVALID_CLIENT"
	ErrCodeInvalidScope       = "INVALID_SCOPE"
	ErrCodeServerError        = "SERVER_ERROR"
)

// AuthError representa um erro de autenticação com informações contextuais.
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	Cause   error  `json:"-"`
}

// Error implementa a interface error.
func (e *AuthError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap retorna o erro original.
func (e *AuthError) Unwrap() error {
	return e.Cause
}

// Is verifica se o erro é do tipo especificado.
func (e *AuthError) Is(target error) bool {
	if target == nil {
		return false
	}

	if ae, ok := target.(*AuthError); ok {
		return e.Code == ae.Code
	}

	return errors.Is(e.Cause, target)
}

// NewAuthError cria um novo erro de autenticação.
func NewAuthError(code, message string) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
	}
}

// NewAuthErrorWithDetails cria um novo erro de autenticação com detalhes.
func NewAuthErrorWithDetails(code, message, details string) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// NewAuthErrorWithCause cria um novo erro de autenticação com causa.
func NewAuthErrorWithCause(code, message string, cause error) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Erros pré-definidos mais comuns
var (
	// ErrInvalidToken indica que o token fornecido é inválido
	ErrInvalidToken = NewAuthError(ErrCodeInvalidToken, "Invalid token")

	// ErrExpiredToken indica que o token expirou
	ErrExpiredToken = NewAuthError(ErrCodeExpiredToken, "Token has expired")

	// ErrInsufficientScope indica que o token não possui escopo suficiente
	ErrInsufficientScope = NewAuthError(ErrCodeInsufficientScope, "Insufficient scope")

	// ErrInvalidCredentials indica que as credenciais são inválidas
	ErrInvalidCredentials = NewAuthError(ErrCodeInvalidCredentials, "Invalid credentials")

	// ErrUnauthorized indica que a requisição não está autorizada
	ErrUnauthorized = NewAuthError(ErrCodeUnauthorized, "Unauthorized")

	// ErrForbidden indica que o acesso é proibido
	ErrForbidden = NewAuthError(ErrCodeForbidden, "Forbidden")

	// ErrInvalidSignature indica que a assinatura do token é inválida
	ErrInvalidSignature = NewAuthError(ErrCodeInvalidSignature, "Invalid token signature")

	// ErrTokenNotFound indica que o token não foi encontrado
	ErrTokenNotFound = NewAuthError(ErrCodeTokenNotFound, "Token not found")

	// ErrUserNotFound indica que o usuário não foi encontrado
	ErrUserNotFound = NewAuthError(ErrCodeUserNotFound, "User not found")

	// ErrInvalidConfig indica que a configuração é inválida
	ErrInvalidConfig = NewAuthError(ErrCodeInvalidConfig, "Invalid configuration")

	// ErrProviderError indica um erro do provedor de autenticação
	ErrProviderError = NewAuthError(ErrCodeProviderError, "Authentication provider error")

	// ErrInvalidGrant indica que o grant OAuth2 é inválido
	ErrInvalidGrant = NewAuthError(ErrCodeInvalidGrant, "Invalid grant")

	// ErrInvalidClient indica que o cliente OAuth2 é inválido
	ErrInvalidClient = NewAuthError(ErrCodeInvalidClient, "Invalid client")

	// ErrInvalidScope indica que o escopo OAuth2 é inválido
	ErrInvalidScope = NewAuthError(ErrCodeInvalidScope, "Invalid scope")

	// ErrServerError indica um erro interno do servidor
	ErrServerError = NewAuthError(ErrCodeServerError, "Internal server error")
)

// Helper functions para criar erros específicos com contexto

// ErrInvalidTokenWithDetails cria um erro de token inválido com detalhes.
func ErrInvalidTokenWithDetails(details string) *AuthError {
	return NewAuthErrorWithDetails(ErrCodeInvalidToken, "Invalid token", details)
}

// ErrInvalidTokenWithCause cria um erro de token inválido com causa.
func ErrInvalidTokenWithCause(cause error) *AuthError {
	return NewAuthErrorWithCause(ErrCodeInvalidToken, "Invalid token", cause)
}

// ErrExpiredTokenWithDetails cria um erro de token expirado com detalhes.
func ErrExpiredTokenWithDetails(details string) *AuthError {
	return NewAuthErrorWithDetails(ErrCodeExpiredToken, "Token has expired", details)
}

// ErrInsufficientScopeWithDetails cria um erro de escopo insuficiente com detalhes.
func ErrInsufficientScopeWithDetails(required, actual []string) *AuthError {
	details := fmt.Sprintf("required: %v, actual: %v", required, actual)
	return NewAuthErrorWithDetails(ErrCodeInsufficientScope, "Insufficient scope", details)
}

// ErrUnauthorizedWithDetails cria um erro de não autorizado com detalhes.
func ErrUnauthorizedWithDetails(details string) *AuthError {
	return NewAuthErrorWithDetails(ErrCodeUnauthorized, "Unauthorized", details)
}

// ErrForbiddenWithDetails cria um erro de proibido com detalhes.
func ErrForbiddenWithDetails(details string) *AuthError {
	return NewAuthErrorWithDetails(ErrCodeForbidden, "Forbidden", details)
}

// ErrProviderErrorWithCause cria um erro de provedor com causa.
func ErrProviderErrorWithCause(provider string, cause error) *AuthError {
	details := fmt.Sprintf("provider: %s", provider)
	return &AuthError{
		Code:    ErrCodeProviderError,
		Message: "Authentication provider error",
		Details: details,
		Cause:   cause,
	}
}

// ErrInvalidConfigWithDetails cria um erro de configuração inválida com detalhes.
func ErrInvalidConfigWithDetails(field, reason string) *AuthError {
	details := fmt.Sprintf("field: %s, reason: %s", field, reason)
	return NewAuthErrorWithDetails(ErrCodeInvalidConfig, "Invalid configuration", details)
}

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

// IsTokenError verifica se um erro é relacionado a token.
func IsTokenError(err error) bool {
	code := GetErrorCode(err)
	return code == ErrCodeInvalidToken ||
		code == ErrCodeExpiredToken ||
		code == ErrCodeInvalidSignature ||
		code == ErrCodeTokenNotFound
}

// IsAuthorizationError verifica se um erro é relacionado a autorização.
func IsAuthorizationError(err error) bool {
	code := GetErrorCode(err)
	return code == ErrCodeUnauthorized ||
		code == ErrCodeForbidden ||
		code == ErrCodeInsufficientScope
}
