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

O projeto está organizado nos seguintes componentes principais:

- **adapter/**: Adaptadores para bibliotecas externas (OAuth2, OIDC, JWT, API Keys, SSO)
- **middleware/**: Middlewares agnósticos de framework web para validação de tokens
- **permissions/**: Adaptadores para sistemas de controle de acesso (RBAC, ABAC, scopes)
- **storage/**: Interfaces para armazenamento e implementação mínima em memória
- **token/**: Wrappers simplificados para manipulação de tokens (JWT, opacos, API Keys)

## Development Guidelines

### Coding Conventions

1. **Interfaces First**: Desenhar interfaces claras antes de implementações
2. **Adapters Over Implementations**: Criar adaptadores para bibliotecas existentes em vez de reimplementar
3. **Error Handling**: Erros específicos definidos em `errors.go` devem ser usados
4. **Testes**: Toda funcionalidade deve ter testes unitários
5. **Leve e Minimalista**: Evitar dependências desnecessárias

### Adding New Features

Ao adicionar novas funcionalidades:

1. Considere se já existe uma biblioteca madura que resolve o problema
2. Defina uma interface clara para o recurso
3. Crie um adaptador para a biblioteca existente
4. Adicione configuração minimalista ao `config.go`
5. Forneça um exemplo de uso

### Integration Guidelines

Ao integrar com bibliotecas externas:

1. Use interfaces para desacoplar a implementação específica
2. Forneça configurações sensatas por padrão
3. Permita substituição completa ou parcial dos componentes
4. Documente as bibliotecas suportadas e suas versões

## Common Patterns

### Adapter Pattern

```go
// Adapter para biblioteca externa
type GoJWTAdapter struct {
    config *Config
}

func NewGoJWTAdapter(config *Config) *GoJWTAdapter {
    return &GoJWTAdapter{
        config: config,
    }
}

// Implementa a interface TokenValidator do authkit
func (a *GoJWTAdapter) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
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
// Wrapper agnóstico de framework
func AuthMiddleware(validator token.Validator) Middleware {
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

## Testing

Use testes focados na integração entre componentes:

```go
func TestTokenValidation(t *testing.T) {
    // Configurar AuthKit
    auth := authkit.New(
        authkit.WithIssuer("test"),
        authkit.WithJWTSigningMethod("HS256"),
        authkit.WithSecret([]byte("secret")),
    )
    
    // Gerar token para teste
    token, err := auth.GenerateToken(...)
    
    // Validar token
    claims, err := auth.ValidateToken(token)
    
    // Verificar resultado
    // ...
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
