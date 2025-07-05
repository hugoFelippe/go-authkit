# 📋 Plano de Implementação - go-authkit

Este documento detalha o plano completo de implementação do go-authkit, seguindo os princípios de abstração leve e integração com bibliotecas maduras existentes.

## 🎯 Objetivo Principal

Criar uma camada de abstração unificada sobre bibliotecas populares de autenticação e autorização, sem reinventar implementações existentes, mas fornecendo uma API simples e configuração unificada.

## 📦 Fases de Implementação

### 🔥 **Fase 1: Core Foundation (Prioridade Alta)**

#### 1.1 Estruturas Base
- [x] **types.go** - Tipos e estruturas compartilhadas
  - [x] Claims (JWT/OAuth2/API Key)
  - [x] User/Principal
  - [x] TokenInfo
  - [x] AuthContext
  - [x] Scope/Permission structs

- [x] **errors.go** - Definições de erros específicos
  - [x] ErrInvalidToken
  - [x] ErrExpiredToken
  - [x] ErrInsufficientScope
  - [x] ErrInvalidCredentials
  - [x] ErrUnauthorized
  - [x] ErrForbidden

- [x] **interfaces.go** - Interfaces principais
  - [x] TokenValidator
  - [x] TokenGenerator
  - [x] UserProvider
  - [x] PermissionChecker
  - [x] Storage interfaces

#### 1.2 Configuração e Ponto de Entrada
- [x] **config.go** - Sistema de configuração com opções funcionais
  - [x] Config struct base
  - [x] DefaultConfig()
  - [x] Opções funcionais (WithIssuer, WithTokenExpiry, etc.)
  - [x] Validação de configuração

- [x] **auth.go** - Ponto de entrada principal
  - [x] AuthKit struct principal
  - [x] New() constructor com options pattern
  - [x] Métodos principais (TokenValidator, GenerateToken, etc.)
  - [x] Integração com storage

### 🚀 **Fase 2: Token Management (Prioridade Alta)**

#### 2.1 JWT Support
- [ ] **token/jwt.go** - Adaptador para golang-jwt/jwt
  - [ ] JWTManager struct
  - [ ] Suporte a diferentes signing methods (HS256, RS256, ES256)
  - [ ] GenerateToken com claims customizáveis
  - [ ] ValidateToken com verificação de exp, iat, iss
  - [ ] Refresh token support

- [ ] **token/validator.go** - Interface unificada de validação
  - [ ] Validator interface
  - [ ] Implementação base
  - [ ] Chain of validators
  - [ ] Context-aware validation

- [ ] **token/manager.go** - Gerenciamento unificado
  - [ ] TokenManager interface
  - [ ] Implementação que combina diferentes tipos
  - [ ] Token introspection
  - [ ] Token revocation

#### 2.2 API Keys Support
- [ ] **token/apikey.go** - Gerenciamento de API Keys
  - [ ] APIKeyManager struct
  - [ ] Geração de chaves com prefixos
  - [ ] Validação e lookup
  - [ ] Suporte a diferentes formatos (header, query, body)

### 🔐 **Fase 3: Storage Abstraction (Prioridade Media)**

#### 3.1 Storage Interfaces
- [ ] **storage/interfaces.go** - Definições de interfaces
  - [ ] TokenStorage interface
  - [ ] UserStorage interface
  - [ ] SessionStorage interface
  - [ ] ConfigStorage interface

- [ ] **storage/memory.go** - Implementação em memória
  - [ ] MemoryStorage struct
  - [ ] Thread-safe operations
  - [ ] TTL support para tokens
  - [ ] Cleanup de tokens expirados

### 🛡️ **Fase 4: Middleware Layer (Prioridade Media)**

#### 4.1 Core Middleware
- [ ] **middleware/auth.go** - Middleware básico framework-agnóstico
  - [ ] AuthMiddleware struct
  - [ ] HTTP Handler wrapper
  - [ ] Token extraction (Bearer, header, query, cookie)
  - [ ] Context injection de claims

- [ ] **middleware/scope.go** - Verificação de escopos
  - [ ] ScopeMiddleware
  - [ ] RequiredScopes validation
  - [ ] OAuth2 scope format support

#### 4.2 Framework Wrappers
- [ ] **middleware/wrapper.go** - Adaptadores para frameworks
  - [ ] GinMiddleware para Gin
  - [ ] EchoMiddleware para Echo
  - [ ] FiberMiddleware para Fiber
  - [ ] ChiMiddleware para Chi
  - [ ] Generic HTTP middleware

### 🔌 **Fase 5: External Adapters (Prioridade Media)**

#### 5.1 OAuth2 Integration
- [ ] **adapter/oauth2.go** - Adaptador para golang.org/x/oauth2
  - [ ] OAuth2Adapter struct
  - [ ] Authorization URL generation
  - [ ] Token exchange
  - [ ] Token refresh
  - [ ] Multi-provider support

#### 5.2 OIDC Integration
- [ ] **adapter/oidc.go** - Adaptador para coreos/go-oidc
  - [ ] OIDCAdapter struct
  - [ ] Discovery document handling
  - [ ] ID Token validation
  - [ ] UserInfo endpoint integration
  - [ ] JWKS handling

#### 5.3 SSO Providers
- [ ] **adapter/sso.go** - Adaptadores para provedores SSO
  - [ ] Google OAuth2/OIDC
  - [ ] Microsoft Azure AD
  - [ ] GitHub OAuth2
  - [ ] Generic OIDC provider
  - [ ] SAML adapter (future)

### 🔒 **Fase 6: Permissions & Authorization (Prioridade Baixa)**

#### 6.1 RBAC Support
- [ ] **permissions/rbac.go** - Role-Based Access Control
  - [ ] Role/Permission definitions
  - [ ] RBACChecker interface
  - [ ] Role hierarchy support
  - [ ] Role assignment/validation

#### 6.2 ABAC Support
- [ ] **permissions/abac.go** - Attribute-Based Access Control
  - [ ] Policy engine interface
  - [ ] Attribute evaluation
  - [ ] Rule-based permissions
  - [ ] Context-aware decisions

#### 6.3 Scope Utilities
- [ ] **permissions/scope.go** - Utilitários para escopos
  - [ ] Scope parsing e validation
  - [ ] Hierarchical scopes
  - [ ] Scope intersection/union
  - [ ] OAuth2 scope compliance

### 📚 **Fase 7: Examples & Documentation (Prioridade Baixa)**

#### 7.1 Basic Examples
- [ ] **examples/basic/** - Exemplo básico com JWT
  - [ ] Simple HTTP server
  - [ ] Token generation/validation
  - [ ] Protected endpoints

- [ ] **examples/gin/** - Integração com Gin
  - [ ] Gin app completa
  - [ ] Login/logout endpoints
  - [ ] Protected routes

- [ ] **examples/oauth2/** - OAuth2 flow completo
  - [ ] Authorization code flow
  - [ ] Google OAuth2 integration
  - [ ] Token refresh

#### 7.2 Advanced Examples
- [ ] **examples/microservices/** - Setup para microserviços
  - [ ] Token validation entre serviços
  - [ ] API Gateway integration
  - [ ] Service-to-service auth

- [ ] **examples/rbac/** - Sistema completo com RBAC
  - [ ] User management
  - [ ] Role assignment
  - [ ] Permission checking

### 🧪 **Fase 8: Testing & Quality (Contínuo)**

#### 8.1 Unit Tests
- [ ] Testes para todos os componentes core
- [ ] Mocks para interfaces externas
- [ ] Coverage > 80%

#### 8.2 Integration Tests
- [ ] Testes de integração com bibliotecas reais
- [ ] End-to-end flow testing
- [ ] Performance benchmarks

#### 8.3 Documentation
- [ ] GoDoc completo
- [ ] Tutorial de getting started
- [ ] Migration guides
- [ ] Best practices guide

## 🛠️ Dependências Externas

### Core Dependencies (Já Incluídas)
- [x] `github.com/golang-jwt/jwt/v5` - JWT handling

### Planned Dependencies
- [ ] `golang.org/x/oauth2` - OAuth2 client
- [ ] `github.com/coreos/go-oidc/v3` - OIDC support
- [ ] `golang.org/x/crypto` - Cryptographic utilities (se necessário)

### Framework Adapters (Optional)
- [ ] `github.com/gin-gonic/gin` - Para Gin middleware
- [ ] `github.com/labstack/echo/v4` - Para Echo middleware
- [ ] `github.com/gofiber/fiber/v2` - Para Fiber middleware
- [ ] `github.com/go-chi/chi/v5` - Para Chi middleware

## 📋 Critérios de Aceitação

### ✅ Funcionalidades Mínimas (MVP)
1. ✅ Geração e validação de JWT tokens
2. ✅ Middleware básico para net/http
3. ✅ Configuração via options pattern
4. ✅ Storage em memória funcional
5. ✅ Exemplo básico funcionando

### 🎯 Funcionalidades Avançadas
1. OAuth2/OIDC integration completa
2. Suporte a múltiplos frameworks web
3. Sistema de permissões (RBAC/ABAC)
4. API Key management
5. SSO provider adapters

## 🚦 Marcos de Entrega

### 🏁 Milestone 1: Core Foundation (Semana 1)
- Implementação completa das Fases 1 e 2
- Testes unitários básicos
- Exemplo mínimo funcionando

### 🏁 Milestone 2: Middleware & Storage (Semana 2)
- Implementação das Fases 3 e 4
- Framework adapters principais
- Exemplos com frameworks populares

### 🏁 Milestone 3: External Integration (Semana 3)
- Implementação da Fase 5
- OAuth2/OIDC adapters
- SSO provider examples

### 🏁 Milestone 4: Advanced Features (Semana 4)
- Implementação da Fase 6
- Sistema de permissões
- Documentação completa

### 🏁 Milestone 5: Production Ready (Semana 5)
- Testes de integração completos
- Performance optimization
- Security audit
- Release v1.0.0

## 📝 Notas de Implementação

### Princípios de Design
1. **Interfaces First**: Definir interfaces antes de implementações
2. **Adapter Pattern**: Usar adaptadores para bibliotecas externas
3. **Options Pattern**: Configuração flexível via opções funcionais
4. **Minimal Dependencies**: Adicionar dependências apenas quando necessário
5. **Backward Compatibility**: Manter compatibilidade entre versões

### Convenções de Código
1. Seguir Go conventions (gofmt, golint, go vet)
2. Documentação completa com exemplos
3. Error handling explícito e específico
4. Context-aware operations
5. Thread-safe implementations quando aplicável

### Considerações de Performance
1. Lazy loading de componentes pesados
2. Connection pooling para external services
3. Caching de tokens e configurações
4. Minimal allocations em hot paths
5. Benchmarks para operações críticas
