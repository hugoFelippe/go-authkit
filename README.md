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
├── errors.go                # Definições de erros específicos
├── interfaces.go            # Interfaces comuns e extensíveis
├── types.go                 # Tipos e estruturas de dados compartilhados
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
│   ├── interfaces.go        # Definição de interfaces para armazenamento
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
import "github.com/hugoFelippe/go-authkit"

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
    
    // Access granted
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
// RBAC - Verificação de papéis
rbacChecker := authkit.RBACMiddleware(auth, []string{"admin", "editor"})
protectedHandler := rbacChecker.Wrap(myHandler)

// ABAC - Verificação baseada em atributos
abacPolicy := authkit.NewPolicy(func(claims *authkit.Claims) bool {
    return claims.Department == "IT" && claims.Level >= 3
})
protectedHandler := authkit.ABACMiddleware(auth, abacPolicy).Wrap(myHandler)

// Verificação de escopos OAuth2
scopeChecker := authkit.ScopeMiddleware(auth, []string{"read:users", "write:users"})
protectedHandler := scopeChecker.Wrap(myHandler)
```

### Integração com API Keys

```go
// Configurar validador de API Keys
apiConfig := authkit.WithAPIKeyConfig(
    authkit.WithAPIKeyPrefix("api-"),
    authkit.WithAPIKeyLocation("header"),
    authkit.WithAPIKeyHeader("X-API-Key"),
)
auth := authkit.New(apiConfig)

// Validar API Key
key := "api-1234567890"
claims, err := auth.ValidateAPIKey(r.Context(), key)
```

### Integração com SSO 

```go
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
```

Mais exemplos em [./examples](./examples)
