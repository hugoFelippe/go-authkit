package mocks

import (
	"context"

	"github.com/hugoFelippe/go-authkit/contracts"
	"github.com/stretchr/testify/mock"
)

// MockUserProvider is a mock implementation of contracts.UserProvider
type MockUserProvider struct {
	mock.Mock
}

// GetUser implements contracts.UserProvider
func (m *MockUserProvider) GetUser(ctx context.Context, userID string) (*contracts.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*contracts.User), args.Error(1)
}

// GetUserByEmail implements contracts.UserProvider
func (m *MockUserProvider) GetUserByEmail(ctx context.Context, email string) (*contracts.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*contracts.User), args.Error(1)
}

// GetUserByUsername implements contracts.UserProvider
func (m *MockUserProvider) GetUserByUsername(ctx context.Context, username string) (*contracts.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*contracts.User), args.Error(1)
}

// CreateUser implements contracts.UserProvider
func (m *MockUserProvider) CreateUser(ctx context.Context, user *contracts.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// UpdateUser implements contracts.UserProvider
func (m *MockUserProvider) UpdateUser(ctx context.Context, user *contracts.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// DeleteUser implements contracts.UserProvider
func (m *MockUserProvider) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// ValidateCredentials implements contracts.UserProvider
func (m *MockUserProvider) ValidateCredentials(ctx context.Context, identifier, password string) (*contracts.User, error) {
	args := m.Called(ctx, identifier, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*contracts.User), args.Error(1)
}

// NewMockUserProvider creates a new mock user provider
func NewMockUserProvider() *MockUserProvider {
	return &MockUserProvider{}
}
