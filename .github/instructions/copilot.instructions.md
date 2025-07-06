---
applyTo: '**'
---

# GitHub Copilot Instructions for go-authkit

## Project Overview

go-authkit é uma biblioteca Go leve e flexível que fornece uma camada de abstração unificada sobre bibliotecas populares de autenticação e autorização. O projeto funciona como um adaptador e configurador para:

- Bibliotecas OAuth2 e OpenID Connect existentes
- Bibliotecas JWT populares
- Integração com API Keys
- Validação de tokens e middlewares
- Provedores SSO (Single Sign-On)
- Validação de permissões via RBAC/ABAC

A filosofia principal é **não reinventar** sistemas existentes, mas **prover uma camada de abstração** sobre eles, permitindo aos desenvolvedores utilizarem bibliotecas maduras com uma configuração simplificada e unificada.

## Core Principles

- **Não reinventar**: Aproveitar bibliotecas maduras já existentes
- **Abstração leve**: Fornecer interfaces unificadas sem overhead desnecessário
- **Configuração simples**: API simples para configurar recursos complexos
- **Extensibilidade**: Interfaces claras para implementações personalizadas
- **Compatibilidade**: Funciona com qualquer framework web ou sistema de armazenamento

## Architecture

⚠️ **ATENÇÃO ESPECIAL**: Para evitar dependências cíclicas, TODAS as interfaces devem estar obrigatoriamente em `contracts/`. Se encontrar erro de importação cíclica, identifique primeiro por que existe - geralmente é uma interface definida fora do `contracts/`.

O projeto está organizado nos seguintes componentes principais:

- **contracts/**: Interfaces, tipos e erros compartilhados (resolve importações cíclicas)
- **adapter/**: Adaptadores para bibliotecas externas (OAuth2, OIDC, JWT, API Keys, SSO)
- **middleware/**: Middlewares agnósticos de framework web para validação de tokens
- **permissions/**: Adaptadores para sistemas de controle de acesso (RBAC, ABAC, scopes)
- **storage/**: Interfaces para armazenamento e implementação mínima em memória
- **token/**: Wrappers simplificados para manipulação de tokens (JWT, opacos, API Keys)

### Contracts Package

O pacote `contracts/` é **OBRIGATÓRIO** para evitar importações cíclicas e centralizar definições compartilhadas:

- **contracts/interfaces.go**: **TODAS** as interfaces do sistema (TokenValidator, TokenGenerator, UserProvider, etc.)
- **contracts/types.go**: **TODOS** os tipos de dados compartilhados (Claims, User, TokenInfo, etc.)
- **contracts/errors.go**: **TODOS** os erros específicos com códigos identificadores

**Regras OBRIGATÓRIAS**:
1. **TODAS** as interfaces devem estar em `contracts/` - SEM EXCEÇÕES
2. Outros pacotes só podem conter implementações concretas dessas interfaces
3. Todos os outros pacotes podem importar `contracts/`, mas `contracts/` não deve importar outros pacotes internos
4. Se há dependência cíclica, a causa é sempre interface ou tipo fora do `contracts/`

## Development Guidelines

### Coding Conventions

1. **Interfaces First**: Desenhar interfaces claras antes de implementações (defina em `contracts/`)
2. **Adapters Over Implementations**: Criar adaptadores para bibliotecas existentes em vez de reimplementar
3. **Error Handling**: Erros específicos definidos em `contracts/errors.go` devem ser usados
4. **Examples**: Fornecer exemplos claros de uso em `examples/`
5. **Testes**: Toda funcionalidade deve ter testes unitários usando **testify**
6. **Mocks**: 
   - Mocks compartilhados entre pacotes devem estar centralizados em `tests/mocks/`
   - Use o padrão `Mock{InterfaceName}` para nomenclatura
   - Use `github.com/stretchr/testify/mock` para mocks avançados
7. **Leve e Minimalista**: Evitar dependências desnecessárias
8. **ZERO Importações Cíclicas**: 
   - **TODAS** as interfaces devem estar obrigatoriamente em `contracts/`
   - Outros pacotes só podem conter implementações concretas dessas interfaces
   - Se encontrar dependência cíclica, identifique primeiro **POR QUE** existe - geralmente é interface fora do `contracts/`

### Adding New Features

Ao adicionar novas funcionalidades:

1. Considere se já existe uma biblioteca madura que resolve o problema
2. **SEMPRE** defina interfaces em `contracts/interfaces.go` primeiro
3. **SEMPRE** adicione tipos compartilhados em `contracts/types.go`
4. Crie implementações concretas nos pacotes específicos
5. **VERIFIQUE** se não há dependências cíclicas: `go list -test ./...`
6. Adicione configuração minimalista ao `config.go`
7. Forneça um exemplo de uso

### Integration Guidelines

Ao integrar com bibliotecas externas:

1. Use interfaces para desacoplar a implementação específica
2. Forneça configurações sensatas por padrão
3. Permita substituição completa ou parcial dos componentes
4. Documente as bibliotecas suportadas e suas versões

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

## Development Workflow

### Makefile Commands

O projeto usa um Makefile para padronizar comandos de desenvolvimento:

```bash
# Comandos principais
make test          # Executa todos os testes
make test-unit     # Executa apenas testes unitários
make test-integration # Executa apenas testes de integração
make test-coverage # Executa testes com coverage
make test-race     # Executa testes com detector de race conditions

# Qualidade de código
make lint          # Executa linters
make fmt           # Formata código
make vet           # Executa go vet
make check         # Executa fmt, vet e lint

# Build e install
make build         # Compila exemplos
make install       # Instala dependências
make clean         # Limpa arquivos temporários

# Desenvolvimento
make watch         # Executa testes automaticamente ao salvar
make examples      # Executa exemplos
make deps          # Atualiza dependências
```

### Testing Strategy

O projeto segue uma estratégia de testes estruturada:

#### 1. Testes Unitários (`*_test.go`)
- Testam componentes isolados
- Usam mocks para dependências externas:
  - Mocks compartilhados entre pacotes: centralizados em `tests/mocks/`
  - Mocks específicos de um pacote: podem ficar nos arquivos `*_test.go` para evitar importações cíclicas
- Localização: junto com o código fonte

#### 2. Testes de Integração (`tests/integration/`)
- Testam integração entre componentes
- Usam bibliotecas reais quando possível
- Simulam cenários completos de uso

#### 3. Testes de Exemplo (`tests/examples/`)
- Validam que exemplos funcionam corretamente
- Servem como documentação executável

#### 4. Benchmarks (`*_bench_test.go`)
- Medem performance de operações críticas
- Validam que não há regressões de performance

### Test Organization

```
tests/
├── integration/    # Testes de integração
│   ├── jwt/        # Testes específicos de JWT
│   ├── oauth2/     # Testes específicos de OAuth2
│   └── middleware/ # Testes de middleware
├── testdata/       # Dados de teste (certificados, keys, etc)
├── testutils/      # Utilitários de teste
├── mocks/          # Mocks compartilhados entre pacotes (evita importações cíclicas)
└── examples/       # Testes dos exemplos
```

### Mock Management

**Estratégia de Organização**:

1. **Mocks Compartilhados**: Em `tests/mocks/` para interfaces que são usadas por vários pacotes
2. **Mocks Específicos**: Nos arquivos `*_test.go` de cada pacote para evitar importações cíclicas

#### Padrões para Mocks:

**Mocks Compartilhados** (`tests/mocks/`):
- Para interfaces definidas em `contracts/`
- Usados em testes de integração
- Nomenclatura: `Mock{InterfaceName}` (ex: `MockTokenValidator`)
- Package: `package mocks`

**Mocks Específicos** (arquivos `*_test.go`):
- Para interfaces específicas do pacote
- Evitam importações cíclicas
- Nomenclatura: `mock{InterfaceName}` ou `Mock{InterfaceName}` conforme convenção do arquivo
- Package: mesmo do arquivo de teste (ex: `package token`)

#### Exemplo de Mock Compartilhado:
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

#### Exemplo de Mock Específico:
```go
// token/apikey_test.go
package token

// MockAPIKeyStorage implementa a interface APIKeyStorage para testes locais
type MockAPIKeyStorage struct {
    data map[string]*APIKeyData
    // ...
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

Ao implementar adaptadores, considere estas bibliotecas maduras:

- JWT: [golang-jwt/jwt](https://github.com/golang-jwt/jwt), [go-jose](https://github.com/go-jose/go-jose)
- OAuth2: [golang.org/x/oauth2](https://golang.org/x/oauth2), [go-oauth2/oauth2](https://github.com/go-oauth2/oauth2)
- OIDC: [coreos/go-oidc](https://github.com/coreos/go-oidc)

## Key Resources

- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [JWT RFC](https://datatracker.ietf.org/doc/html/rfc7519)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

### Prevenção de Dependências Cíclicas

**REGRA FUNDAMENTAL**: TODAS as interfaces devem estar em `contracts/`. Outros pacotes só podem conter implementações concretas.

#### Identificando Dependências Cíclicas

Se encontrar erro de importação cíclica, identifique a causa raiz:

1. **Interface fora do `contracts/`**: A causa mais comum
   - ❌ `token/interfaces.go` com interface `TokenManager`
   - ✅ `contracts/interfaces.go` com interface `TokenManager`

2. **Tipos compartilhados fora do `contracts/`**: 
   - ❌ `token/types.go` com struct `TokenInfo` usada em outros pacotes
   - ✅ `contracts/types.go` com struct `TokenInfo`

3. **Implementações referenciando outras implementações diretamente**:
   - ❌ `token/manager.go` importando `middleware/auth.go`
   - ✅ Ambos dependem apenas de interfaces de `contracts/`

#### Estrutura Correta dos Pacotes

```
contracts/           # APENAS interfaces, tipos e erros compartilhados
├── interfaces.go    # TODAS as interfaces do sistema
├── types.go         # TODOS os tipos compartilhados
└── errors.go        # TODOS os erros específicos

token/              # APENAS implementações concretas
├── manager.go      # implements contracts.TokenManager
├── jwt.go          # implements contracts.TokenValidator
└── apikey.go       # implements contracts.APIKeyValidator

middleware/         # APENAS implementações concretas
├── auth.go         # usa contracts.TokenValidator (interface)
└── cors.go         # implementação de middleware

adapter/            # APENAS adaptadores para bibliotecas externas
├── jwt_adapter.go  # implements contracts.TokenValidator
└── oauth_adapter.go # implements contracts.OAuthProvider
```

#### Exemplo de Refatoração

**❌ ANTES (com dependência cíclica):**
```go
// token/interfaces.go
type TokenManager interface {
    ValidateToken(token string) error
}

// middleware/auth.go
import "myproject/token" // ❌ Importa outro pacote interno

func AuthMiddleware(tm token.TokenManager) {}

// token/manager.go
import "myproject/middleware" // ❌ Dependência cíclica!
```

**✅ DEPOIS (sem dependência cíclica):**
```go
// contracts/interfaces.go
type TokenManager interface {
    ValidateToken(token string) error
}

// middleware/auth.go
import "myproject/contracts" // ✅ Só importa contracts

func AuthMiddleware(tm contracts.TokenManager) {}

// token/manager.go
import "myproject/contracts" // ✅ Só importa contracts

type Manager struct{}
func (m *Manager) ValidateToken(token string) error { /* impl */ }
```

#### Checklist Anti-Dependência Cíclica

Antes de criar qualquer arquivo novo:

- [ ] Todas as interfaces estão em `contracts/interfaces.go`?
- [ ] Todos os tipos compartilhados estão em `contracts/types.go`?
- [ ] O pacote só importa `contracts/` e bibliotecas externas?
- [ ] Não há importação direta entre pacotes internos (exceto `contracts/`)?
- [ ] As implementações dependem apenas de interfaces, não de outras implementações?

#### Comando para Verificar Dependências

```bash
# Verificar dependências cíclicas
go list -f '{{.ImportPath}} {{.Imports}}' ./... | grep -E "token|middleware|adapter" | sort

# Se encontrar ciclo, usar go mod graph para identificar a cadeia
go mod graph | grep "myproject/"
```

### Testify Guidelines

O projeto usa **testify** como biblioteca padrão para testes. Todas as novas funcionalidades devem seguir os padrões estabelecidos:

#### Bibliotecas Testify Utilizadas:
- `github.com/stretchr/testify/assert` - Asserções que continuam o teste
- `github.com/stretchr/testify/require` - Asserções que param o teste se falharem  
- `github.com/stretchr/testify/mock` - Sistema completo de mocks
- `github.com/stretchr/testify/suite` - Test suites organizadas

#### Padrões de Uso:

**Use `require` quando**:
- O teste não pode continuar se a asserção falhar
- Verificando se erro é nil antes de usar o resultado
- Verificando se ponteiros não são nil antes de acessar

**Use `assert` quando**:
- O teste pode continuar mesmo se a asserção falhar
- Comparando valores esperados vs atuais
- Verificando múltiplas condições no mesmo teste

#### Exemplo Prático:
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
