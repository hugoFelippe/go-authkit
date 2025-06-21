# go-authkit: Plano de Implementação

Este documento descreve o plano de implementação para o projeto go-authkit, definindo as tarefas necessárias para desenvolver uma camada de abstração leve sobre bibliotecas de autenticação e autorização existentes em Go.

## Visão e Objetivos

go-authkit é uma **camada de abstração leve** projetada para:

1. Fornecer uma interface unificada e consistente sobre as principais bibliotecas de autenticação em Go
2. Simplificar a configuração e implementação de sistemas de autenticação em projetos Go
3. Permitir que desenvolvedores evitem reimplementar lógicas de autenticação comuns
4. Facilitar a troca de bibliotecas subjacentes sem alterar o código de negócio

**O que go-authkit NÃO é**:
- Não é uma reimplementação completa de protocolos OAuth2/OIDC
- Não é um framework web ou de rotas
- Não é uma solução de banco de dados ou persistência

## Prioridades de Desenvolvimento

1. **Fundação (P0)**: Interfaces básicas e sistema de configuração unificado
2. **Adaptadores (P1)**: Wrappers para bibliotecas populares (OAuth2, OIDC, JWT)
3. **Middlewares (P1)**: Middlewares agnósticos de framework para validação
4. **Armazenamento (P2)**: Interfaces de armazenamento e implementação mínima em memória
5. **Exemplos (P2)**: Exemplos completos de integração com frameworks populares

## Tarefas por Módulo

### 1. Core (`/`)

- [ ] **auth.go**: 
  - [ ] Definir estrutura principal `AuthKit`
  - [ ] Implementar construtores e métodos de inicialização
  - [ ] Implementar métodos de factory para adaptadores

- [ ] **config.go**:
  - [ ] Implementar estrutura `Config` minimalista
  - [ ] Criar funções Options para configuração funcional
  - [ ] Implementar validação de configuração

- [ ] **errors.go**:
  - [ ] Definir erros específicos da biblioteca
  - [ ] Implementar helpers para wrap de erros
  - [ ] Criar constantes para códigos de erro

- [ ] **interfaces.go**:
  - [ ] Definir interfaces base: `TokenValidator`, `TokenGenerator`
  - [ ] Interfaces para adaptadores de biblioteca
  - [ ] Interfaces para armazenamento

- [ ] **types.go**:
  - [ ] Definir estruturas de dados comuns: `Token`, `Claims`
  - [ ] Definir enums para tipos de autenticação
  - [ ] Manter estruturas simples e interoperáveis

### 2. Adapter (`/adapter`)

- [ ] **oauth2.go**:
  - [ ] Implementar adaptadores para bibliotecas OAuth2 populares (go-oauth2, oauth2)
  - [ ] Configuração simplificada para fluxos Authorization Code, Client Credentials, Password, Refresh Token
  - [ ] Mapeamento para interfaces do authkit

- [ ] **oidc.go**:
  - [ ] Implementar adaptadores para bibliotecas OIDC populares (go-oidc)
  - [ ] Gerenciamento de descoberta e validação
  - [ ] Parsing e validação de ID tokens
  - [ ] Mapeamento de claims e userinfo

- [ ] **jwt.go**:
  - [ ] Implementar adaptadores para bibliotecas JWT (jwt-go, go-jose)
  - [ ] Configuração simplificada de assinaturas e validação
  - [ ] Suporte para RS256, HS256, ES256

- [ ] **apikey.go**:
  - [ ] Implementar adaptadores para validação e geração de API Keys
  - [ ] Estratégias flexíveis para armazenamento e validação
  - [ ] Suporte para metadados e escopos em API Keys

- [ ] **sso.go**:
  - [ ] Interfaces abstratas para provedores SSO
  - [ ] Adaptadores para OAuth2/OIDC como SSO
  - [ ] Abstração de processos de mapeamento de identidade

### 3. Middleware (`/middleware`)

- [ ] **auth.go**:
  - [ ] Implementar middleware base agnóstico de framework
  - [ ] Extração de tokens de várias fontes (header, cookie, query)
  - [ ] Validação e processamento de tokens

- [ ] **scope.go**:
  - [ ] Middleware para validação de escopos
  - [ ] Extração e comparação de claims
  - [ ] Gestão de permissões baseadas em escopos

- [ ] **wrapper.go**:
  - [ ] Implementar wrappers para frameworks populares (standard HTTP, Gin, Echo, Fiber)
  - [ ] Adaptação de middleware agnóstico para frameworks específicos
  - [ ] Helpers para passagem de contexto

### 4. Token (`/token`)

- [ ] **manager.go**:
  - [ ] Interface unificada para gerenciamento de tokens
  - [ ] Métodos para validação, geração e revogação
  - [ ] Abstração sobre diferentes tipos de tokens

- [ ] **jwt.go**:
  - [ ] Configuração simplificada para JWT
  - [ ] Adaptadores para bibliotecas JWT populares
  - [ ] Helpers para manipulação de claims

- [ ] **validator.go**:
  - [ ] Validadores genéricos de tokens
  - [ ] Verificações de expiração, emissor, audiência
  - [ ] Interface para validação customizada

### 5. Storage (`/storage`)

- [ ] **interfaces.go**:
  - [ ] Definir interfaces mínimas de armazenamento
  - [ ] Métodos para tokens, sessões
  - [ ] Design para extensibilidade

- [ ] **memory.go**:
  - [ ] Implementar armazenamento em memória básico
  - [ ] Para testes e protótipos rápidos
  - [ ] Gestão de expiração simples

### 6. Permissions (`/permissions`)

- [ ] **rbac.go**:
  - [ ] Adaptadores para bibliotecas RBAC existentes
  - [ ] Interface simples para verificação de papéis
  - [ ] Integração com claims de tokens

- [ ] **abac.go**:
  - [ ] Adaptadores para sistemas ABAC
  - [ ] Avaliação de políticas baseadas em atributos
  - [ ] Configuração simplificada de políticas

- [ ] **scope.go**:
  - [ ] Utilitários para validação e verificação de escopos
  - [ ] Mapeamento de escopos para permissões
  - [ ] Integração com validação de tokens

## Plano de Fases

### Fase 1: Fundação e Abstração
- Core + Interfaces + Configuração
- Adaptador JWT básico 
- Armazenamento em memória para exemplos
- Documentação de visão e arquitetura

### Fase 2: Adaptadores Básicos e Middlewares
- Adaptadores para JWT e OAuth2 (fluxo Authorization Code)
- Adaptador simples para API Keys
- Middlewares agnósticos de framework
- Wrappers para frameworks web populares
- Exemplos básicos de uso

### Fase 3: Adaptadores Completos
- Todos os fluxos OAuth2 e OIDC
- Integração SSO
- Sistema básico de RBAC/ABAC
- Validação e verificação de escopos
- Exemplos para cada adaptador

### Fase 4: Extensão e Documentação
- Exemplos completos de integração
- Documentação detalhada de uso
- Guias de migração e extensibilidade
- Exemplos de implementações de storage personalizadas

## Métricas de Progresso

- **Cobertura de testes**: Meta de 85%+ para todos os pacotes
- **Documentação**: Todas as funções exportadas devem ter comentários godoc
- **Exemplos funcionais**: Exemplos completos para cada adaptador e caso de uso comum

## Considerações de Design

- **Minimalista**: Fornecer apenas o essencial para conectar bibliotecas existentes
- **Composable**: Componentes devem funcionar bem juntos, mas ser utilizáveis separadamente
- **Não-opinativo**: Não forçar escolhas de frameworks ou armazenamento
- **Extensível**: Fácil de estender para casos de uso específicos
- **Focado**: Fazer uma coisa bem - ser uma camada de configuração/abstração, não reimplementar
