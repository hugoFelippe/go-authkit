# Test Data

Este diretório contém dados de teste utilizados pelos testes do go-authkit.

## Estrutura

- `keys/` - Chaves de teste para JWT e criptografia
- `certs/` - Certificados de teste para validação SSL/TLS
- `tokens/` - Tokens de exemplo para testes
- `configs/` - Arquivos de configuração de teste

## Uso

Os arquivos neste diretório são utilizados pelos testes de integração e exemplos.
Não devem ser utilizados em produção.

## Geração de Dados de Teste

Para gerar novos dados de teste, utilize os helpers em `testutils/`.
