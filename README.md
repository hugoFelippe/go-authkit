# 🔐 AuthKit

**AuthKit** é um pacote leve e flexível de integração para autenticação e autorização em Go, que fornece uma camada de abstração uniforme sobre bibliotecas populares de OAuth2, OpenID Connect e JWT.

## 🚀 Introdução

Este pacote foi criado para facilitar a integração de autenticação e autorização em aplicações Go, evitando reimplementar componentes e aproveitando bibliotecas maduras existentes. Com uma configuração simples e unificada, você pode iniciar rapidamente um sistema de autenticação seguro e adaptar conforme suas necessidades.

### ✅ Recursos principais

* **Interface unificada** sobre bibliotecas populares de autenticação
* Wrapper simplificado para **OAuth2** e **OpenID Connect**
* Integração flexível com **API Keys**
* Suporte simplificado a **JWT** com configuração minimalista
* Interfaces padronizadas para **armazenamento** de tokens e dados de autenticação
* **Middlewares agnósticos** de framework para validação de tokens
* Extensibilidade através de interfaces bem definidas

## 👥 Principais usos

* **Aplicações web** que precisam de autenticação de usuários
* **APIs** que requerem proteção com OAuth2 ou API Keys
* **Microserviços** que precisam validar tokens
* **Projetos** que desejam uma abstração unificada sobre diferentes métodos de autenticação
* **Soluções** que buscam flexibilidade para trocar implementações subjacentes

## 🔒 Características

* **Minimalista**: Fornece apenas o essencial, sem código desnecessário
* **Extensível**: Fácil de estender com suas próprias implementações
* **Interoperável**: Integra-se com bibliotecas populares do ecossistema Go
* **Não opinativo**: Não impõe um sistema de armazenamento ou framework web específico
* **Interfaces claras**: Permite implementar seus próprios adaptadores de armazenamento
* **Sem importações cíclicas**: Arquitetura com pacote `contracts/` evita problemas de dependência circular

## 🏗️ Arquitetura de Contracts

O projeto utiliza uma arquitetura especial com o pacote `contracts/` para resolver problemas de importação cíclica comuns em projetos Go:

### 📋 Pacote Contracts (`contracts/`)
- **Centraliza** todas as interfaces, tipos e erros compartilhados
- **Elimina** importações cíclicas entre pacotes
- **Facilita** a implementação de adaptadores personalizados
- **Padroniza** tipos de dados em todo o ecossistema

### 🔄 Fluxo de Dependências
```
adapter/ ──┐
           ├─→ contracts/ ←── authkit.go
token/   ──┤
           ├─→ contracts/ ←── middleware/
storage/ ──┘
```

**Regra fundamental**: Todos os pacotes podem importar `contracts/`, mas `contracts/` não importa nenhum pacote interno.

## 💡 Filosofia do projeto

* Não reinventar bibliotecas existentes de OAuth2, OIDC ou JWT
* Fornecer uma camada unificada e simples de configuração
* Permitir que desenvolvedores implementem apenas as interfaces necessárias
* Separar o núcleo da autenticação da implementação de armazenamento e rotas
* Facilitar a troca de componentes subjacentes sem reescrever o código de autenticação

## 📁 Estrutura do Projeto

```
/authkit/
├── authkit.go               # Ponto de entrada principal para a biblioteca
├── config.go                # Configurações unificadas
│
├── contracts/               # Interfaces, tipos e erros compartilhados (evita importação cíclica)
│   ├── interfaces.go        # Todas as interfaces do sistema
│   ├── types.go             # Tipos de dados compartilhados
│   └── errors.go            # Erros específicos com códigos identificadores
│
├── adapter/                 # Adaptadores para bibliotecas externas
│   ├── oauth2.go            # Adaptador para bibliotecas OAuth2
│   ├── oidc.go              # Adaptador para bibliotecas OIDC
│   ├── jwt.go               # Adaptador para bibliotecas JWT
│   ├── apikey.go            # Adaptador para API Keys
│   └── sso.go               # Adaptador para provedores SSO
│
├── middleware/              # Middlewares agnósticos de framework
│   ├── auth.go              # Middleware básico de autenticação
│   ├── scope.go             # Verificação de escopos
│   └── wrapper.go           # Wrapper para integração com diferentes frameworks
│
├── permissions/             # Adaptadores para sistemas de permissões
│   ├── rbac.go              # Adaptadores para Role-Based Access Control
│   ├── abac.go              # Adaptadores para Attribute-Based Access Control
│   └── scope.go             # Utilitários para verificação de escopos
│
├── storage/                 # Interfaces de armazenamento
│   └── memory.go            # Implementação mínima em memória para testes
│
└── token/                   # Manipulação simplificada de tokens
    ├── manager.go           # Interface unificada para gerenciamento de tokens
    ├── validator.go         # Interface para validação de tokens
    ├── jwt.go               # Wrapper para manipulação de JWT
    └── apikey.go            # Wrapper para manipulação de API Keys
```

## 📦 Exemplos de uso

### Configuração básica

```go
import (
    "github.com/hugoFelippe/go-authkit"
    "github.com/hugoFelippe/go-authkit/contracts"
)

// Criar configuração com valores padrão
config := authkit.DefaultConfig()

// Configurar com opções funcionais
auth := authkit.New(
    authkit.WithIssuer("my-app"),
    authkit.WithTokenExpiry(time.Hour),
    authkit.WithJWTSigningMethod("RS256"),
)

// Utilizar armazenamento personalizado
auth.UseStorage(myCustomStorage)
```

### Validação de token em um middleware

```go
import (
    "github.com/hugoFelippe/go-authkit"
    "github.com/hugoFelippe/go-authkit/contracts"
)

// Framework-agnóstico
validator := auth.TokenValidator()

// Exemplo com net/http
http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
    token := authkit.ExtractTokenFromRequest(r)
    
    claims, err := validator.ValidateToken(r.Context(), token)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    // Access granted - usar claims do tipo contracts.Claims
    userID := claims.Subject
    // ...
})

// Ou usar o middleware incluído
protectedHandler := authkit.AuthMiddleware(auth).Wrap(myHandler)
```

### Adaptadores para frameworks web populares

```go
// Gin
r := gin.Default()
r.Use(authkit.GinMiddleware(auth))

// Echo
e := echo.New()
e.Use(authkit.EchoMiddleware(auth))

// Fiber
app := fiber.New()
app.Use(authkit.FiberMiddleware(auth))
```

### Validação de escopos e permissões

```go
import (
    "github.com/hugoFelippe/go-authkit"
    "github.com/hugoFelippe/go-authkit/contracts"
)

// RBAC - Verificação de papéis
rbacChecker := authkit.RBACMiddleware(auth, []string{"admin", "editor"})
protectedHandler := rbacChecker.Wrap(myHandler)

// ABAC - Verificação baseada em atributos
abacPolicy := authkit.NewPolicy(func(claims *contracts.Claims) bool {
    return claims.Department == "IT" && claims.Level >= 3
})
protectedHandler := authkit.ABACMiddleware(auth, abacPolicy).Wrap(myHandler)

// Verificação de escopos OAuth2
scopeChecker := authkit.ScopeMiddleware(auth, []string{"read:users", "write:users"})
protectedHandler := scopeChecker.Wrap(myHandler)
```

### Integração com API Keys

```go
import (
    "github.com/hugoFelippe/go-authkit"
    "github.com/hugoFelippe/go-authkit/contracts"
)

// Configurar validador de API Keys
apiConfig := authkit.WithAPIKeyConfig(
    authkit.WithAPIKeyPrefix("api-"),
    authkit.WithAPIKeyLocation("header"),
    authkit.WithAPIKeyHeader("X-API-Key"),
)
auth := authkit.New(apiConfig)

// Validar API Key
key := "api-1234567890"
apiKey, err := auth.ValidateAPIKey(r.Context(), key)
if err != nil {
    // Tratar erro usando contracts.AuthError
    if contracts.GetErrorCode(err) == contracts.ErrCodeInvalidAPIKey {
        // API Key inválida
    }
}
```

### Integração com SSO 

```go
import (
    "github.com/hugoFelippe/go-authkit"
    "github.com/hugoFelippe/go-authkit/contracts"
)

// Configurar provedor SSO
ssoConfig := authkit.WithSSOProvider(
    authkit.WithOIDCProvider("https://accounts.google.com"),
    authkit.WithClientCredentials("client-id", "client-secret"),
    authkit.WithRedirectURL("https://myapp.com/callback"),
)
auth := authkit.New(ssoConfig)

// Obter URL de login
loginURL := auth.GetLoginURL(state)

// Processar callback
tokens, err := auth.HandleCallback(r.Context(), r.URL.Query())
if err != nil {
    // Usar sistema de erros do contracts
    if contracts.IsAuthError(err) {
        code := contracts.GetErrorCode(err)
        // Tratar erro específico...
    }
}
```

### Implementação de Adaptador Personalizado

```go
package myadapter

import (
    "context"
    "github.com/hugoFelippe/go-authkit/contracts"
)

// Implementar interface TokenValidator do contracts
type CustomTokenValidator struct {
    secret []byte
}

func NewCustomValidator(secret []byte) contracts.TokenValidator {
    return &CustomTokenValidator{secret: secret}
}

func (v *CustomTokenValidator) ValidateToken(ctx context.Context, token string) (*contracts.Claims, error) {
    // Sua lógica de validação personalizada
    if token == "" {
        return nil, contracts.ErrInvalidToken
    }
    
    // Retornar claims padronizadas
    return &contracts.Claims{
        Subject: "user123",
        Email:   "user@example.com",
        Roles:   []string{"user"},
    }, nil
}

func (v *CustomTokenValidator) ValidateTokenWithType(ctx context.Context, token string, tokenType contracts.TokenType) (*contracts.Claims, error) {
    // Implementação específica por tipo
    switch tokenType {
    case contracts.TokenTypeJWT:
        return v.validateJWT(token)
    case contracts.TokenTypeAPIKey:
        return v.validateAPIKey(token)
    default:
        return nil, contracts.ErrInvalidToken
    }
}

// Uso do adaptador personalizado
func main() {
    customValidator := NewCustomValidator([]byte("my-secret"))
    
    auth := authkit.New(
        authkit.WithTokenValidator(customValidator),
        authkit.WithIssuer("my-app"),
    )
    
    // Usar normalmente...
}
```

### Tratamento de Erros com Codes

```go
import "github.com/hugoFelippe/go-authkit/contracts"

func handleAuthError(err error) {
    if contracts.IsAuthError(err) {
        switch contracts.GetErrorCode(err) {
        case contracts.ErrCodeInvalidToken:
            log.Println("Token inválido")
        case contracts.ErrCodeExpiredToken:
            log.Println("Token expirado")
        case contracts.ErrCodeUserNotFound:
            log.Println("Usuário não encontrado")
        case contracts.ErrCodePermissionDenied:
            log.Println("Permissão negada")
        default:
            log.Printf("Erro de autenticação: %s", err.Error())
        }
    }
}
```

### Estrutura de Pacotes
- `contracts/` - Interfaces, tipos e erros (público e extensível)
- `adapter/` - Implementações para bibliotecas externas
- `middleware/` - Middlewares agnósticos de framework
- `token/` - Manipuladores de token específicos
- `storage/` - Adaptadores de armazenamento

Mais exemplos em [./examples](./examples)
