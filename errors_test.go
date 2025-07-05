package authkit_test

import (
	"testing"

	"github.com/hugoFelippe/go-authkit"
)

func TestAuthErrors_Basic(t *testing.T) {
	err := authkit.ErrInvalidToken
	expectedMsg := "INVALID_TOKEN: Invalid token"
	if err.Error() != expectedMsg {
		t.Errorf("Expected '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestAuthErrors_WithDetails(t *testing.T) {
	err := authkit.ErrInvalidTokenWithDetails("token format is invalid")
	expectedMsg := "INVALID_TOKEN: Invalid token (token format is invalid)"
	if err.Error() != expectedMsg {
		t.Errorf("Expected '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestAuthErrors_TypeChecking(t *testing.T) {
	err := authkit.ErrInvalidToken

	if !authkit.IsAuthError(err) {
		t.Error("Should be AuthError")
	}
	if authkit.GetErrorCode(err) != "INVALID_TOKEN" {
		t.Errorf("Expected error code 'INVALID_TOKEN', got '%s'", authkit.GetErrorCode(err))
	}
	if !authkit.IsTokenError(err) {
		t.Error("Should be token error")
	}
}

func TestAuthErrors_Classification(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		isAuthError bool
		isTokenErr  bool
		code        string
	}{
		{
			name:        "invalid token",
			err:         authkit.ErrInvalidToken,
			isAuthError: true,
			isTokenErr:  true,
			code:        "INVALID_TOKEN",
		},
		{
			name:        "expired token",
			err:         authkit.ErrExpiredToken,
			isAuthError: true,
			isTokenErr:  true,
			code:        "EXPIRED_TOKEN",
		},
		{
			name:        "unauthorized",
			err:         authkit.ErrUnauthorized,
			isAuthError: true,
			isTokenErr:  false,
			code:        "UNAUTHORIZED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if authkit.IsAuthError(tt.err) != tt.isAuthError {
				t.Errorf("IsAuthError expected %v, got %v", tt.isAuthError, authkit.IsAuthError(tt.err))
			}
			if authkit.IsTokenError(tt.err) != tt.isTokenErr {
				t.Errorf("IsTokenError expected %v, got %v", tt.isTokenErr, authkit.IsTokenError(tt.err))
			}
			if authkit.GetErrorCode(tt.err) != tt.code {
				t.Errorf("GetErrorCode expected %s, got %s", tt.code, authkit.GetErrorCode(tt.err))
			}
		})
	}
}
