# Storage Package

O pacote `storage` fornece implementações de armazenamento para o go-authkit, seguindo as interfaces definidas em `contracts/interfaces.go`.

## Interfaces Implementadas

O pacote implementa as seguintes interfaces de storage:

### TokenStorage
Gerenciamento específico de tokens JWT e outros tipos de tokens.

```go
type TokenStorage interface {
    StoreToken(ctx context.Context, token string, claims *Claims, expiry time.Duration) error
    GetToken(ctx context.Context, token string) (*Claims, error)
    DeleteToken(ctx context.Context, token string) error
    DeleteAllTokens(ctx context.Context, userID string) error
    IsRevoked(ctx context.Context, token string) (bool, error)
    RevokeToken(ctx context.Context, token string) error
    RevokeAllTokens(ctx context.Context, userID string) error
    Cleanup(ctx context.Context) error
}
```

### UserStorage
Armazenamento e recuperação de dados de usuários.

```go
type UserStorage interface {
    StoreUser(ctx context.Context, user *User) error
    GetUser(ctx context.Context, userID string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    GetUserByUsername(ctx context.Context, username string) (*User, error)
    UpdateUser(ctx context.Context, user *User) error
    DeleteUser(ctx context.Context, userID string) error
    ListUsers(ctx context.Context, offset, limit int) ([]*User, error)
    CountUsers(ctx context.Context) (int64, error)
}
```

### SessionStorage
Gerenciamento de sessões de usuário.

```go
type SessionStorage interface {
    StoreSession(ctx context.Context, session *Session) error
    GetSession(ctx context.Context, sessionID string) (*Session, error)
    DeleteSession(ctx context.Context, sessionID string) error
    DeleteAllSessions(ctx context.Context, userID string) error
    GetUserSessions(ctx context.Context, userID string) ([]*Session, error)
    Cleanup(ctx context.Context) error
}
```

### ConfigStorage
Armazenamento de configurações da aplicação.

```go
type ConfigStorage interface {
    Set(ctx context.Context, key string, value interface{}, expiry time.Duration) error
    Get(ctx context.Context, key string) (interface{}, error)
    Delete(ctx context.Context, key string) error
    Exists(ctx context.Context, key string) (bool, error)
    GetAll(ctx context.Context) (map[string]interface{}, error)
    Clear(ctx context.Context) error
}
```

### CacheStorage
Cache genérico com suporte a TTL.

```go
type CacheStorage interface {
    SetCache(ctx context.Context, key string, value interface{}, ttl time.Duration) error
    GetCache(ctx context.Context, key string) (interface{}, error)
    DeleteCache(ctx context.Context, key string) error
    ExistsCache(ctx context.Context, key string) (bool, error)
    TTL(ctx context.Context, key string) (time.Duration, error)
    Expire(ctx context.Context, key string, ttl time.Duration) error
    Keys(ctx context.Context, pattern string) ([]string, error)
    ClearCache(ctx context.Context) error
    Size(ctx context.Context) (int64, error)
}
```

## MemoryStorage

A implementação em memória (`MemoryStorage`) é uma implementação thread-safe que combina todas as interfaces de storage em uma única estrutura.

### Características

- **Thread-Safe**: Usa `sync.RWMutex` para operações concorrentes seguras
- **TTL Automático**: Suporte a expiração automática de dados
- **Cleanup Automático**: Worker em background que limpa dados expirados a cada 5 minutos
- **Zero Dependências**: Não requer banco de dados ou serviços externos
- **Alto Performance**: Operações em memória com complexidade O(1) para a maioria das operações

### Uso Básico

```go
package main

import (
    "context"
    "time"
    
    "github.com/hugoFelippe/go-authkit/contracts"
    "github.com/hugoFelippe/go-authkit/storage"
)

func main() {
    // Criar instância do storage
    store := storage.NewMemoryStorage()
    defer store.Close()

    ctx := context.Background()

    // Armazenar usuário
    user := &contracts.User{
        ID:       "user123",
        Username: "johndoe",
        Email:    "john@example.com",
        Name:     "John Doe",
        Active:   true,
    }

    err := store.StoreUser(ctx, user)
    if err != nil {
        // handle error
    }

    // Recuperar usuário
    retrievedUser, err := store.GetUser(ctx, "user123")
    if err != nil {
        // handle error
    }

    // Armazenar token
    claims := &contracts.Claims{
        Subject: user.ID,
        Email:   user.Email,
        Name:    user.Name,
    }

    token := "jwt.token.here"
    err = store.StoreToken(ctx, token, claims, time.Hour)
    if err != nil {
        // handle error
    }

    // Cache com TTL
    err = store.SetCache(ctx, "user:profile:123", userProfile, 30*time.Minute)
    if err != nil {
        // handle error
    }
}
```

### Integração com AuthKit

```go
package main

import (
    "github.com/hugoFelippe/go-authkit"
    "github.com/hugoFelippe/go-authkit/storage"
)

func main() {
    // Criar storage personalizado
    customStorage := storage.NewMemoryStorage()
    defer customStorage.Close()

    // Configurar AuthKit
    auth := authkit.New(
        authkit.WithIssuer("my-app"),
        authkit.WithJWTSecret([]byte("secret")),
    )
    defer auth.Close()

    // Usar storage para operações customizadas
    // Enquanto AuthKit gerencia JWT, você pode usar
    // o storage para sessões, cache, etc.
}
```

## Operações Avançadas

### Pattern Matching em Cache

```go
// Armazenar diferentes tipos de dados
store.SetCache(ctx, "user:profile:123", profile, time.Hour)
store.SetCache(ctx, "user:settings:123", settings, time.Hour)
store.SetCache(ctx, "api:rate_limit:user123", limit, time.Minute)

// Buscar por padrão
userKeys, _ := store.Keys(ctx, "user:*")        // ["user:profile:123", "user:settings:123"]
profileKeys, _ := store.Keys(ctx, "*:profile:*") // ["user:profile:123"]
```

### Gerenciamento de Sessões

```go
// Criar sessão
session := &contracts.Session{
    ID:        "session-abc123",
    UserID:    "user123",
    Token:     "session-token",
    ExpiresAt: time.Now().Add(2 * time.Hour),
    Active:    true,
}

store.StoreSession(ctx, session)

// Listar sessões ativas do usuário
userSessions, _ := store.GetUserSessions(ctx, "user123")

// Revogar todas as sessões
store.DeleteAllSessions(ctx, "user123")
```

### Revogação de Tokens

```go
// Revogar token específico
store.RevokeToken(ctx, "specific-token")

// Revogar todos os tokens de um usuário
store.RevokeAllTokens(ctx, "user123")

// Verificar se token foi revogado
isRevoked, _ := store.IsRevoked(ctx, "token")
```

### Limpeza e Manutenção

```go
// Limpeza manual
store.Cleanup(ctx)

// Verificar saúde
err := store.Ping(ctx)

// Obter estatísticas
stats, _ := store.Stats(ctx)
fmt.Printf("Tokens ativos: %v\n", stats["tokens_active"])
fmt.Printf("Usuários total: %v\n", stats["users_total"])
```

## Tratamento de Erros

O storage utiliza os erros padronizados definidos em `contracts/errors.go`:

```go
// Verificar tipo de erro
_, err := store.GetUser(ctx, "nonexistent")
if err != nil {
    if contracts.GetErrorCode(err) == contracts.ErrCodeUserNotFound {
        // usuário não encontrado
    }
}

// Tratar diferentes tipos de erro
switch contracts.GetErrorCode(err) {
case contracts.ErrCodeTokenExpired:
    // token expirado
case contracts.ErrCodeTokenRevoked:
    // token revogado
case contracts.ErrCodeUserNotFound:
    // usuário não encontrado
}
```

## Performance e Escalabilidade

### Considerações de Performance

- **Operações O(1)**: Get, Set, Delete são O(1) em média
- **Operações O(n)**: List, Keys, Cleanup são O(n) onde n é o número de items
- **Memória**: Todos os dados são mantidos em memória
- **Concorrência**: Thread-safe com locks de leitura/escrita

### Limitações

- **Persistência**: Dados são perdidos quando a aplicação é reiniciada
- **Memória**: Limitado pela memória disponível do sistema
- **Escalabilidade**: Não escala horizontalmente (single instance)

### Recomendações

- **Desenvolvimento**: Ideal para desenvolvimento e testes
- **Produção**: Para produção, considere implementações persistentes (Redis, SQL, etc.)
- **Cache**: Excelente para cache temporário e dados voláteis
- **Microserviços**: Adequado para serviços stateless com dados temporários

## Extending Storage

Para criar sua própria implementação de storage:

1. Implemente as interfaces definidas em `contracts/interfaces.go`
2. Siga os padrões de erro estabelecidos
3. Considere thread-safety se necessário
4. Implemente testes unitários

```go
type CustomStorage struct {
    // sua implementação
}

func (c *CustomStorage) StoreUser(ctx context.Context, user *contracts.User) error {
    // implementação personalizada
}

// ... implementar todas as interfaces necessárias
```

## Testes

Execute os testes do storage:

```bash
go test ./storage/ -v
```

Para testes com coverage:

```bash
go test ./storage/ -cover
```

## Próximos Passos

- Implementações para Redis
- Implementações para SQL (PostgreSQL, MySQL)
- Implementações para NoSQL (MongoDB, DynamoDB)
- Configuração automática baseada em ambiente
- Métricas e observabilidade integrada
