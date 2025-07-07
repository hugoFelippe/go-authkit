# Contracts Package

Este pacote contém todas as interfaces, tipos e erros compartilhados do go-authkit. Foi criado para resolver problemas de importação cíclica e centralizar definições fundamentais do sistema.

## Estrutura

### `interfaces.go`
Define todas as interfaces do sistema:
- **TokenValidator**: Interface para validação de tokens
- **TokenGenerator**: Interface para geração de tokens  
- **TokenManager**: Interface que combina validação e geração
- **UserProvider**: Interface para provedores de usuário
- **PermissionProvider**: Interface para provedores de permissão
- **StorageProvider**: Interface para armazenamento de dados
- **OAuth2Provider**: Interface para provedores OAuth2
- **JWTProvider**: Interface para provedores JWT
- **APIKeyProvider**: Interface para provedores de API Key
- **Middleware**: Interface para middlewares de autenticação
- **EventHandler**: Interface para manipulação de eventos
- **ConfigProvider**: Interface para provedores de configuração

### `types.go`
Define todos os tipos de dados compartilhados:
- **Claims**: Informações contidas em tokens de autenticação
- **User**: Representa um usuário no sistema
- **TokenType**: Enum para tipos de token suportados
- **TokenInfo**: Informações sobre um token
- **APIKey**: Representa uma chave de API
- **OAuth2Token**: Representa um token OAuth2
- **Session**: Representa uma sessão de usuário
- **Permission**: Representa uma permissão no sistema
- **Role**: Representa um papel/função no sistema
- **AuthContext**: Contexto de autenticação

### `errors.go`
Define erros específicos com códigos identificadores:
- **AuthError**: Estrutura de erro com código específico
- Constantes de códigos de erro (ErrCodeInvalidToken, etc.)
- Erros predefinidos para casos comuns
- Funções utilitárias para trabalhar com erros

## Regras de Importação

### ✅ Permitido
- Qualquer pacote do projeto pode importar `contracts/`
- `contracts/` pode importar apenas pacotes da biblioteca padrão do Go
- `contracts/` pode importar bibliotecas externas quando necessário para definições de tipos

### ❌ Não Permitido
- `contracts/` não deve importar outros pacotes internos do projeto
- Importações cíclicas entre qualquer pacote e `contracts/`
