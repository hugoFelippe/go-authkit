---
description: GitHub Copilot Instructions for project
applyTo: '**'
---

# Project-specific instructions

## Project Overview

go-authkit is a lightweight and flexible Go library that provides a unified abstraction layer over popular authentication and authorization libraries. The project acts as an adapter and configurator for:

- Existing OAuth2 and OpenID Connect libraries
- Popular JWT libraries
- API Key integration
- Token validation and middlewares
- SSO (Single Sign-On) providers
- Permission validation via RBAC/ABAC

The main philosophy is **not to reinvent** existing systems, but **to provide an abstraction layer** over them, allowing developers to use mature libraries with simplified and unified configuration.

## Core Principles

- **Do not reinvent**: Leverage already mature existing libraries
- **Lightweight abstraction**: Provide unified interfaces without unnecessary overhead
- **Simple configuration**: Simple API to configure complex features
- **Extensibility**: Clear interfaces for custom implementations
- **Compatibility**: Works with any web framework or storage system

## Architecture

The project is organized into the following main components:

- **contracts/**: Shared interfaces, types, and errors
- **adapter/**: Adapters for external libraries (OAuth2, OIDC, JWT, API Keys, SSO)
- **middleware/**: Framework-agnostic web middlewares for token validation
- **permissions/**: Adapters for access control systems (RBAC, ABAC, scopes)
- **storage/**: Concrete implementations of storage interfaces defined in `contracts/` (e.g., in-memory, Redis, relational databases, etc.)
- **token/**: Simplified wrappers for token handling (JWT, opaque tokens, API Keys)
- **authkit.go**: Main entry point for the library
- **config.go**: Unified configuration

**SPECIAL ATTENTION**: To avoid cyclic dependencies, **ALL interfaces must be defined in `contracts/`**. If you encounter a cyclic import error, first identify the cause — it's usually an interface defined outside of `contracts/`.

**MANDATORY Rules**:
1. **ALL** interfaces must be in `contracts/` – NO EXCEPTIONS
2. Other packages may only contain concrete implementations of these interfaces
3. All other packages can import `contracts/`, but `contracts/` must not import any internal packages
4. If there is a cyclic dependency, the cause is always an interface or type defined outside of `contracts/`

### Contracts Package

- **contracts/interfaces.go**: **ALL** system interfaces (TokenValidator, TokenGenerator, UserProvider, etc.)
- **contracts/types.go**: **ALL** shared data types (Claims, User, TokenInfo, etc.)
- **contracts/errors.go**: **ALL** specific errors with identifier codes

### Test Organization

The project follows a structured testing strategy:

```
tests/
├── integration/    # Integration tests
│   ├── jwt/        # JWT-specific tests
│   ├── oauth2/     # OAuth2-specific tests
│   └── middleware/ # Middleware tests
├── testdata/       # Test data (certificates, keys, etc)
├── testutils/      # Test utilities
├── mocks/          # Shared mocks across packages (avoids cyclic imports)
└── examples/       # Example tests
```

#### 1. Unit Tests (`*_test.go`)
- Test isolated components
- Located alongside the source code
- Use mocks for external dependencies:
    - Mocks should be centralized in `tests/mocks/`, making them easy to share across packages and avoiding duplication.
    - If you encounter cyclic import errors, check if any interface or type is defined outside the correct package (`contracts/`). Identify and move it to `contracts/` to resolve the issue.

#### 2. Integration Tests (`tests/integration/`)
- Test integration between components
- Use real libraries whenever possible
- Simulate complete usage scenarios

#### 3. Example Tests (`tests/examples/`)
- Validate that examples work correctly
- Serve as executable documentation

## Development Guidelines

### Coding Conventions

1. **Interfaces First**: Design clear interfaces before implementations (define them in `contracts/`)
2. **Lightweight and Minimal**: Avoid unnecessary dependencies
3. **Adapters Over Implementations**: Create adapters for existing libraries instead of reimplementing
4. **Error Handling**: Use specific errors defined in `contracts/errors.go`
5. **Examples**: Provide clear usage examples in `examples/`
6. **Testing**: All functionality must have unit tests using **testify**

### Testify Guidelines
The project uses **testify** as the standard testing library. All new features must follow the established patterns:

#### Testify Libraries Used:
- `github.com/stretchr/testify/assert` – Assertions that allow the test to continue
- `github.com/stretchr/testify/require` – Assertions that stop the test if they fail
- `github.com/stretchr/testify/mock` – Complete mocking system
- `github.com/stretchr/testify/suite` – Organized test suites

#### Usage Patterns:

**Use `require` when**:
- The test cannot continue if the assertion fails
- Checking if an error is nil before using the result
- Checking if pointers are not nil before accessing them

**Use `assert` when**:
- The test can continue even if the assertion fails
- Comparing expected vs actual values
- Checking multiple conditions in the same test

#### Practical Example:
```go
func TestTokenGeneration(t *testing.T) {
    auth := testutils.SetupTestAuth(t)
    user := testutils.TestUser("123")
    
    // Use require para condições críticas
    token, err := auth.GenerateToken(context.Background(), user)
    require.NoError(t, err)        // Se falhar, para o teste
    require.NotEmpty(t, token)     // Se falhar, para o teste
    
    // Use assert para validações adicionais
    assert.Contains(t, token, ".")  // JWT tem pontos
    assert.True(t, len(token) > 50) // Token tem tamanho mínimo
}
```

## Common Patterns

### Adapter Pattern

```go
import "github.com/hugoFelippe/go-authkit/contracts"

// Adapter para biblioteca externa
type GoJWTAdapter struct {
    config *Config
}

func NewGoJWTAdapter(config *Config) *GoJWTAdapter {
    return &GoJWTAdapter{
        config: config,
    }
}

// Implementa a interface TokenValidator do contracts
func (a *GoJWTAdapter) ValidateToken(ctx context.Context, tokenString string) (*contracts.Claims, error) {
    // Usa biblioteca externa para validar o token
    // ...
}
```

### Configuration

```go
func WithIssuer(issuer string) Option {
    return func(c *Config) {
        c.Issuer = issuer
    }
}

// Uso:
auth := authkit.New(
    authkit.WithIssuer("my-api"),
    authkit.WithTokenExpiry(30 * time.Minute),
)
```

### Framework Wrappers

```go
import (
    "github.com/hugoFelippe/go-authkit/contracts"
    "github.com/hugoFelippe/go-authkit/token"
)

// Wrapper agnóstico de framework
func AuthMiddleware(validator contracts.TokenValidator) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Validação de token
            // ...
        })
    }
}

// Adaptador para Gin
func GinAuthMiddleware(auth *AuthKit) gin.HandlerFunc {
    validator := auth.TokenValidator()
    return func(c *gin.Context) {
        // Adaptação para Gin
        // ...
    }
}
```

#### Example of a Mock:
```go
// tests/mocks/mock_token_validator.go
package mocks

import (
    "context"
    "github.com/hugoFelippe/go-authkit/contracts"
    "github.com/stretchr/testify/mock"
)

type MockTokenValidator struct {
    mock.Mock
}

func NewMockTokenValidator() *MockTokenValidator {
    return &MockTokenValidator{}
}

func (m *MockTokenValidator) ValidateToken(ctx context.Context, token string) (*contracts.Claims, error) {
    args := m.Called(ctx, token)
    
    if claims := args.Get(0); claims != nil {
        return claims.(*contracts.Claims), args.Error(1)
    }
    return nil, args.Error(1)
}
```


#### Uso de Mocks nos Testes:
```go
import (
    "github.com/hugoFelippe/go-authkit/tests/mocks"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"
)

func TestWithMock(t *testing.T) {
    mockValidator := mocks.NewMockTokenValidator()
    
    expectedClaims := &contracts.Claims{Subject: "test"}
    mockValidator.On("ValidateToken", mock.Anything, "valid-token").Return(expectedClaims, nil)
    mockValidator.On("ValidateToken", mock.Anything, "invalid-token").Return(nil, contracts.ErrInvalidToken)
    
    // Teste com token válido
    claims, err := mockValidator.ValidateToken(context.Background(), "valid-token")
    require.NoError(t, err)
    assert.Equal(t, "test", claims.Subject)
    
    // Teste com token inválido
    _, err = mockValidator.ValidateToken(context.Background(), "invalid-token")
    assert.Error(t, err)
    assert.Equal(t, contracts.ErrInvalidToken, err)
    
    // Verifica se todas as expectativas foram atendidas
    mockValidator.AssertExpectations(t)
}
```

### Testing Patterns

#### Unit Test Pattern
```go
import (
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/hugoFelippe/go-authkit/tests/testutils"
    "github.com/hugoFelippe/go-authkit/contracts"
)

func TestTokenValidation(t *testing.T) {
    tests := []struct {
        name        string
        token       string
        wantErr     bool
        errorCode   string
    }{
        {
            name:      "valid token",
            token:     "valid.jwt.token",
            wantErr:   false,
        },
        {
            name:      "invalid token",
            token:     "invalid",
            wantErr:   true,
            errorCode: "INVALID_TOKEN",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            auth := testutils.SetupTestAuth(t)
            
            claims, err := auth.ValidateToken(context.Background(), tt.token)
            
            if tt.wantErr {
                require.Error(t, err)
                assert.Equal(t, tt.errorCode, contracts.GetErrorCode(err))
                assert.Nil(t, claims)
            } else {
                require.NoError(t, err)
                assert.NotNil(t, claims)
            }
        })
    }
}
```

#### Integration Test Pattern
```go
import (
    "github.com/hugoFelippe/go-authkit"
    "github.com/hugoFelippe/go-authkit/contracts"
    "github.com/hugoFelippe/go-authkit/adapter"
    "github.com/hugoFelippe/go-authkit/tests/testutils"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
)

type JWTIntegrationSuite struct {
    suite.Suite
    auth *authkit.AuthKit
}

func (suite *JWTIntegrationSuite) SetupTest() {
    // Setup real JWT adapter
    suite.auth = authkit.New(
        authkit.WithJWTAdapter(adapter.NewGoJWTAdapter()),
        authkit.WithIssuer("test"),
        authkit.WithJWTSecret([]byte("secret")),
    )
}

func (suite *JWTIntegrationSuite) TestJWTFullPipeline() {
    // Generate real token using helper
    user := testutils.TestUser("123")
    token := testutils.AssertTokenGeneration(suite.T(), suite.auth, user)
    
    // Validate token through full pipeline using helper
    claims := testutils.AssertValidToken(suite.T(), suite.auth, token, "123")
    assert.Equal(suite.T(), user.ID, claims.Subject)
    assert.Equal(suite.T(), user.Email, claims.Email)
}

func (suite *JWTIntegrationSuite) TestInvalidToken() {
    testutils.AssertInvalidToken(suite.T(), suite.auth, "invalid-token", "INVALID_TOKEN")
}

func TestJWTIntegrationSuite(t *testing.T) {
    suite.Run(t, new(JWTIntegrationSuite))
}
```

#### Test Helpers
```go
// testutils/setup.go
import (
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/hugoFelippe/go-authkit"
    "github.com/hugoFelippe/go-authkit/contracts"
)

func SetupTestAuth(t *testing.T, opts ...authkit.Option) *authkit.AuthKit {
    defaultOpts := []authkit.Option{
        authkit.WithIssuer("test"),
        authkit.WithJWTSecret([]byte("test-secret-key-for-testing-purposes")),
        authkit.WithDebug(true),
    }
    
    opts = append(defaultOpts, opts...)
    auth := authkit.New(opts...)
    
    t.Cleanup(func() {
        auth.Close()
    })
    
    return auth
}

// Helper para gerar e validar tokens
func AssertTokenGeneration(t *testing.T, auth *authkit.AuthKit, user *contracts.User) string {
    token, err := auth.GenerateToken(context.Background(), user)
    require.NoError(t, err)
    assert.NotEmpty(t, token)
    return token
}

// Helper para validar tokens
func AssertValidToken(t *testing.T, auth *authkit.AuthKit, token, expectedSubject string) *contracts.Claims {
    claims, err := auth.ValidateToken(context.Background(), token)
    require.NoError(t, err)
    require.NotNil(t, claims)
    assert.Equal(t, expectedSubject, claims.Subject)
    return claims
}

// Helper para validar tokens inválidos
func AssertInvalidToken(t *testing.T, auth *authkit.AuthKit, token, expectedErrorCode string) {
    claims, err := auth.ValidateToken(context.Background(), token)
    require.Error(t, err)
    assert.Nil(t, claims)
    assert.Equal(t, expectedErrorCode, contracts.GetErrorCode(err))
}

// Helper para criar usuário de teste
func TestUser(id string) *contracts.User {
    return &contracts.User{
        ID:    id,
        Email: id + "@test.com",
        Name:  "Test User " + id,
    }
}
```

## Libraries to Consider

When implementing adapters, consider these mature libraries:

- JWT: [golang-jwt/jwt](https://github.com/golang-jwt/jwt), [go-jose](https://github.com/go-jose/go-jose)
- OAuth2: [golang.org/x/oauth2](https://golang.org/x/oauth2), [go-oauth2/oauth2](https://github.com/go-oauth2/oauth2)
- OIDC: [coreos/go-oidc](https://github.com/coreos/go-oidc)

## Key Resources

- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [JWT RFC](https://datatracker.ietf.org/doc/html/rfc7519)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)