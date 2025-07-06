package mocks

import (
	"context"
	"time"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/mock"
)

// MockTokenGenerator is a mock implementation of contracts.TokenGenerator
type MockTokenGenerator struct {
	mock.Mock
}

// GenerateToken implements contracts.TokenGenerator
func (m *MockTokenGenerator) GenerateToken(ctx context.Context, claims *contracts.Claims) (string, error) {
	args := m.Called(ctx, claims)
	return args.String(0), args.Error(1)
}

// GenerateTokenWithExpiry implements contracts.TokenGenerator
func (m *MockTokenGenerator) GenerateTokenWithExpiry(ctx context.Context, claims *contracts.Claims, expiry time.Duration) (string, error) {
	args := m.Called(ctx, claims, expiry)
	return args.String(0), args.Error(1)
}

// GenerateRefreshToken implements contracts.TokenGenerator
func (m *MockTokenGenerator) GenerateRefreshToken(ctx context.Context, user *contracts.User) (string, error) {
	args := m.Called(ctx, user)
	return args.String(0), args.Error(1)
}

// NewMockTokenGenerator creates a new mock token generator
func NewMockTokenGenerator() *MockTokenGenerator {
	return &MockTokenGenerator{}
}
