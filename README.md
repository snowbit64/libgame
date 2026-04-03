# Decompilation Workflow para Bibliotecas Dinâmicas Stripadas

Workflow automático do GitHub Actions para decompilar e analisar bibliotecas dinâmicas stripadas (`.so`) independentemente de símbolos não serem identificáveis.

## 📋 Características

- ✅ **Decompilação automática** com Ghidra
- ✅ **Análise fallback** com Radare2
- ✅ **Extração de símbolos** mesmo sem debug info
- ✅ **Análise de strings** e cross-references
- ✅ **Geração de relatórios** estruturados
- ✅ **Outputs em JSON** para processamento posterior
- ✅ **CI/CD integrado** com GitHub Actions

## 🚀 Setup Rápido

### 1. Estrutura de Diretórios

```
seu-repositorio/
├── .github/
│   └── workflows/
│       └── decompile-workflow.yml     # Workflow do GitHub Actions
├── libgame.so                          # Seu arquivo binário
├── analyze_binary.py                   # Script de análise complementar
└── README.md
```

### 2. Copiar Arquivos

```bash
# Clone seu repositório
git clone https://github.com/seu-usuario/seu-repo
cd seu-repo

# Crie a estrutura de diretórios
mkdir -p .github/workflows

# Copie os arquivos do workflow
cp decompile-workflow.yml .github/workflows/
cp analyze_binary.py .

# Adicione sua biblioteca
cp /caminho/para/libgame.so .

# Commit e push
git add .
git commit -m "Add decompilation workflow"
git push origin main
```

### 3. Executar Manualmente

Vá para: **GitHub → seu-repo → Actions → Decompile Stripped Library → Run workflow**

## 📊 Saídas Geradas

### Diretório: `decompiled_functions/`
Arquivo C para cada função encontrada
```
0x1000__main.c
0x1234__parse_config.c
0x5678__unknown_function_1.c
```

### Arquivo: `functions_list.json`
Inventário estruturado de todas as funções
```json
[
  {
    "name": "main",
    "address": "0x1000",
    "size": 512,
    "return_type": "void",
    "parameters": 2
  }
]
```

### Diretório: `radare2_analysis/`
Análise alternativa e validação
- `functions.json` - Lista de funções em JSON
- `functions_detailed.txt` - Desassembly completo
- `strings.txt` - Strings extraídas

### Diretório: `analysis_report/`
Relatórios de análise binária
- `binary_info.txt` - Informações estruturais
- `DECOMPILATION_SUMMARY.md` - Resumo executivo

## 🔧 Personalização

### Modificar Versão do Ghidra

No arquivo `decompile-workflow.yml`, procure por:

```yaml
GHIDRA_VERSION="11.0.3"
```

Altere para a versão desejada de: https://github.com/NationalSecurityAgency/ghidra/releases

### Adicionar Análise Customizada

Edite `decompile_script.py` dentro do workflow:

```python
def custom_analysis(func):
    """Sua análise customizada aqui"""
    if func.getBody().getNumAddresses() > 1000:
        return analyze_large_function(func)
    return None
```

### Incluir Múltiplas Bibliotecas

```yaml
strategy:
  matrix:
    library: ['libgame.so', 'libengine.so', 'libui.so']

steps:
  - name: Decompile library
    run: |
      cp ${{ matrix.library }} current_lib.so
      # ... resto do workflow ...
```

## 📝 Script de Análise Local

Para análise fora do GitHub Actions:

```bash
# Instalar dependências
sudo apt-get install -y radare2 ghidra binutils

# Executar análise
python3 analyze_binary.py libgame.so -o results/

# Resultados em: analysis_results/
```

### Saídas do Script Python

- `analysis_report.json` - Relatório completo
- `functions_summary.json` - Resumo de funções
- `strings_extracted.txt` - Strings encontradas
- `symbols_extracted.json` - Símbolos extraídos

## 🎯 Casos de Uso

### 1. Análise de Comportamento Suspeito
```bash
# Extrair e analisar strings
grep -r "http" decompilation_output/strings*.txt

# Encontrar XREFs
grep -r "xref" decompilation_output/radare2_analysis/
```

### 2. Recuperação de Símbolos Perdidos
```bash
# Usar file heuristics
python3 -c "
import json
with open('functions_list.json') as f:
    funcs = json.load(f)
    for f in funcs:
        if 'main' in f['address']:
            print(f)
"
```

### 3. Integração com IDA Pro

1. Exporte para arquivo IDC:
```python
# Em Ghidra Script Console
for func in currentProgram.getFunctionManager().getFunctions(True):
    print(f"idc.set_name({func.getEntryPoint()}, '{func.getName()}')")
```

2. Execute em IDA:
```
idaq -S script.idc libgame.so
```

## ⚠️ Limitações

| Limitação | Workaround |
|-----------|-----------|
| Sem símbolos debug | Use heuristics + pattern matching |
| Code obfuscation | Análise manual de seções críticas |
| Stripped completamente | Radare2 + entropy analysis |
| Muito grande (>100MB) | Dividir por seções |

## 🔍 Troubleshooting

### Ghidra falha silenciosamente
```bash
# Ver logs
export _JAVA_OPTIONS="-Xmx4g"
# Aumentar memória
```

### Não encontra funções
```bash
# Verificar se é library válida
file libgame.so
# Deve ser: ELF 64-bit LSB shared object

# Se falhar, tentar Radare2 direto
r2 -A libgame.so
```

### Radare2 está lento
```bash
# Usar análise rápida
r2 -A -e bin.maxstringlen=256 libgame.so
```

## 📚 Referências

- **Ghidra Documentation**: https://ghidra-sre.org/
- **Radare2 Book**: https://book.rada.re/
- **ELF Specification**: https://refspecs.linuxfoundation.org/elf/elf.pdf
- **Reverse Engineering Guide**: https://www.begin.re/

## 🛠️ Ferramentas Alternativas

```bash
# Disassembly puro
objdump -d libgame.so | less

# Análise de seções
readelf -S libgame.so

# Buscar strings específicas
strings libgame.so | grep -i "version"

# Dynamic analysis
ltrace ./app
strace ./app
```

## 📊 Exemplo de Workflow Customizado

Para análise contínua a cada push:

```yaml
on:
  push:
    paths:
      - 'libgame.so'
  schedule:
    - cron: '0 0 * * 0'  # Toda segunda-feira

jobs:
  decompile:
    # ... jobs ...
```

## 📦 Integração com Pipeline CI/CD

```yaml
# Em seu workflow existente
- name: Download latest decompilation
  uses: dawidd6/action-download-artifact@v2
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    workflow: decompile-workflow.yml
    name: decompiled-libgame-so
    path: ./analysis/
```

## 🔐 Segurança

- ✅ Workflow runs in isolated GitHub container
- ✅ Nenhuma chave sensível exposta
- ✅ Artifacts encriptados em repouso
- ✅ 90 dias de retenção (configurável)

## 📄 Licença

Este workflow usa:
- **Ghidra** - Custom License (NSA)
- **Radare2** - LGPLv3
- **GNU Binutils** - GPLv3

## ⭐ Dicas de Sucesso

1. **Sempre manter versão do Ghidra atualizada**
2. **Validar resultados com múltiplas ferramentas**
3. **Documentar anomalias encontradas**
4. **Manter histórico de análises**
5. **Usar junto com testes dinâmicos**

## 🤝 Contribuições

Melhorias sugeridas:
- IDA Pro integration
- Yara rule matching
- Malware signature detection
- Performance benchmarking

## 📞 Suporte

Para problemas:
1. Verificar os logs do GitHub Actions
2. Testar ferramentas localmente
3. Reportar em Issues do repositório

---

**Última atualização**: 2024
**Mantido por**: Seu Time de Segurança
