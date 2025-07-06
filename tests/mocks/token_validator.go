package mocks

import (
	"context"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/mock"
)

// MockTokenValidator is a mock implementation of contracts.TokenValidator
type MockTokenValidator struct {
	mock.Mock
}

// ValidateToken implements contracts.TokenValidator
func (m *MockTokenValidator) ValidateToken(ctx context.Context, token string) (*contracts.Claims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*contracts.Claims), args.Error(1)
}

// ValidateTokenWithType implements contracts.TokenValidator
func (m *MockTokenValidator) ValidateTokenWithType(ctx context.Context, token string, tokenType contracts.TokenType) (*contracts.Claims, error) {
	args := m.Called(ctx, token, tokenType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*contracts.Claims), args.Error(1)
}

// NewMockTokenValidator creates a new mock token validator
func NewMockTokenValidator() *MockTokenValidator {
	return &MockTokenValidator{}
}
