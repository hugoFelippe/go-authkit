# Estrutura de Testes - go-authkit

## Estrutura Organizada

O projeto agora conta com uma estrutura de testes bem organizada e um Makefile para automatizar as tarefas de desenvolvimento.

```
go-authkit/
├── Makefile                    # Comandos de desenvolvimento e CI/CD
├── *_test.go                  # Testes unitários no pacote principal
├── tests/
│   ├── integration/           # Testes de integração
│   │   └── authkit_integration_test.go
│   ├── examples/              # Testes dos exemplos
│   │   └── examples_test.go
│   ├── testdata/              # Dados de teste
│   │   ├── README.md
│   │   └── data.go
│   └── testutils/             # Utilitários de teste
│       └── setup.go
└── examples/
    └── basic/
        └── basic_example.go
```

## Comandos de Desenvolvimento

### Testes
```bash
make test              # Executa todos os testes
make test-unit         # Executa apenas testes unitários
make test-integration  # Executa apenas testes de integração
make test-coverage     # Executa testes com coverage
make test-race         # Executa testes com detector de race conditions
make test-bench        # Executa benchmarks
```

### Qualidade de Código
```bash
make fmt               # Formata código
make vet               # Executa go vet
make lint              # Executa linters
make check             # Executa fmt, vet e lint
make staticcheck       # Executa staticcheck
```

### Build e Desenvolvimento
```bash
make build             # Compila exemplos
make build-keep        # Compila exemplos e mantém binários
make install           # Instala dependências
make install-tools     # Instala ferramentas de desenvolvimento
make deps              # Atualiza dependências
make examples          # Executa exemplos
make watch             # Executa testes automaticamente ao salvar
```

### CI/CD
```bash
make ci                # Pipeline completo de CI
make pre-commit        # Verificações antes de commit
```

### Limpeza
```bash
make clean             # Limpa arquivos temporários
make clean-deps        # Limpa cache de dependências
```

### Ajuda
```bash
make help              # Mostra todos os comandos disponíveis
```

## Tipos de Teste

### 1. Testes Unitários
- **Localização**: `*_test.go` no pacote principal
- **Propósito**: Testar componentes isolados
- **Padrão**: Testes focados usando table-driven tests

**Exemplo**:
```go
func TestConfig_Validation(t *testing.T) {
    tests := []struct {
        name      string
        setupFn   func() *authkit.Config
        wantErr   bool
        errorCode string
    }{
        // casos de teste...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // teste...
        })
    }
}
```

### 2. Testes de Integração
- **Localização**: `tests/integration/`
- **Propósito**: Testar integração entre componentes
- **Padrão**: Cenários completos de uso

### 3. Testes de Exemplo
- **Localização**: `tests/examples/`
- **Propósito**: Validar que exemplos funcionam
- **Padrão**: Build e execução dos exemplos

### 4. Utilitários de Teste
- **Localização**: `tests/testutils/`
- **Propósito**: Helpers reutilizáveis para testes
- **Padrão**: Funções de setup e assertion

## Status dos Testes

✅ **Funcionando**:
- Testes unitários do pacote principal
- Testes de integração básicos  
- Testes dos exemplos
- Estrutura de utilitários de teste

🚧 **Pendente**:
- Benchmarks
- Testes com bibliotecas JWT reais
- Testes de middleware
- Testes de performance

## Ferramentas Recomendadas

### Instalação Automática
```bash
make install-tools
```

### Manual
```bash
# Linter
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Static analysis
go install honnef.co/go/tools/cmd/staticcheck@latest

# Watch mode (Linux)
sudo apt-get install inotify-tools

# Watch mode (macOS)
brew install fswatch
```

## Coverage

Para gerar relatório de coverage:
```bash
make test-coverage
```

O relatório HTML será gerado em `coverage.html`.

## Integração com CI/CD

O Makefile inclui comandos específicos para CI/CD:

```yaml
# GitHub Actions exemplo
- name: Run CI Pipeline
  run: make ci
```

## Próximos Passos

1. **Fase 2**: Implementar adaptadores JWT reais
2. **Middleware**: Criar middlewares para frameworks web
3. **Storage**: Implementar storage em memória e persistente
4. **Performance**: Adicionar benchmarks e otimizações
5. **Documentação**: Expandir exemplos e guias
