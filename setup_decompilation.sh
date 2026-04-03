#!/bin/bash
# Setup script para ambiente local de decompilação

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BINARY_FILE="${1:-libgame.so}"

echo "🔧 Binary Decompilation Setup Script"
echo "======================================"
echo "Binary: $BINARY_FILE"
echo ""

# Verificar se arquivo existe
if [ ! -f "$BINARY_FILE" ]; then
    echo "❌ Error: $BINARY_FILE not found"
    exit 1
fi

# Detectar sistema operacional
OS=$(uname -s)
echo "🖥️  Operating System: $OS"

# Instalação de dependências por OS
install_dependencies() {
    if [[ "$OS" == "Linux" ]]; then
        if command -v apt-get &> /dev/null; then
            echo "📦 Installing dependencies with apt..."
            sudo apt-get update
            sudo apt-get install -y \
                default-jdk \
                wget \
                unzip \
                binutils \
                radare2 \
                ghidra \
                cutter \
                python3 \
                python3-pip
        elif command -v yum &> /dev/null; then
            echo "📦 Installing dependencies with yum..."
            sudo yum install -y \
                java-latest-openjdk-headless \
                wget \
                unzip \
                binutils \
                radare2 \
                python3
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        echo "📦 Installing dependencies with brew..."
        brew install binutils radare2 python@3.11
        
        # Download Ghidra manualmente (não está em Homebrew)
        echo "⚠️  Ghidra not available in Homebrew - download from:"
        echo "   https://github.com/NationalSecurityAgency/ghidra/releases"
    fi
}

# Análise rápida com ferramentas CLI
quick_analysis() {
    echo ""
    echo "⚡ Running quick analysis..."
    echo "======================================"
    
    mkdir -p quick_analysis
    
    # File info
    echo "📋 File Information:"
    file "$BINARY_FILE" | tee quick_analysis/file_info.txt
    echo ""
    
    # Tamanho
    echo "📏 Size:"
    ls -lh "$BINARY_FILE" | tee quick_analysis/file_size.txt
    echo ""
    
    # Seções ELF
    echo "📚 ELF Sections:"
    readelf -S "$BINARY_FILE" | head -20 | tee quick_analysis/sections.txt
    echo ""
    
    # Símbolos
    echo "🔤 Symbol Count:"
    SYMBOL_COUNT=$(nm "$BINARY_FILE" 2>/dev/null | wc -l)
    echo "Total symbols: $SYMBOL_COUNT" | tee quick_analysis/symbol_count.txt
    
    # Funções exportadas
    echo "🔗 Exported Functions:"
    nm -D "$BINARY_FILE" 2>/dev/null | grep ' T ' | head -10 | tee quick_analysis/exported_functions.txt
    echo ""
    
    # Strings suspeitas
    echo "🔍 Interesting Strings:"
    strings "$BINARY_FILE" | grep -E "(http|/|flag|admin|password|secret|key)" | head -20 | tee quick_analysis/interesting_strings.txt
    echo ""
    
    echo "✅ Quick analysis saved to quick_analysis/"
}

# Download Ghidra
download_ghidra() {
    echo ""
    echo "⬇️  Downloading Ghidra..."
    
    GHIDRA_VERSION="11.0.3"
    GHIDRA_FILE="ghidra_${GHIDRA_VERSION}_PUBLIC_20240410.zip"
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_FILE}"
    
    if [ ! -d "ghidra_${GHIDRA_VERSION}_PUBLIC" ]; then
        if [ ! -f "$GHIDRA_FILE" ]; then
            wget -q "$GHIDRA_URL" || {
                echo "❌ Failed to download Ghidra"
                echo "   Download manually from: $GHIDRA_URL"
                return 1
            }
        fi
        unzip -q "$GHIDRA_FILE"
        rm "$GHIDRA_FILE"
    fi
    
    echo "✅ Ghidra ready"
}

# Análise com Radare2
analyze_with_radare2() {
    echo ""
    echo "🔍 Analyzing with Radare2..."
    echo "======================================"
    
    mkdir -p radare2_analysis
    
    # Análise completa em JSON
    echo "[*] Extracting functions..."
    r2 -j -c "aaa;afj" "$BINARY_FILE" > radare2_analysis/functions.json 2>/dev/null || {
        echo "[!] r2 functions failed"
    }
    
    # Strings
    echo "[*] Extracting strings..."
    r2 -j -c "izj" "$BINARY_FILE" > radare2_analysis/strings.json 2>/dev/null || {
        echo "[!] r2 strings failed"
    }
    
    # Seções
    echo "[*] Analyzing sections..."
    r2 -j -c "iSj" "$BINARY_FILE" > radare2_analysis/sections.json 2>/dev/null || {
        echo "[!] r2 sections failed"
    }
    
    # Cross-references
    echo "[*] Finding cross-references..."
    r2 -j -c "aaa;acrj" "$BINARY_FILE" > radare2_analysis/xrefs.json 2>/dev/null || {
        echo "[!] r2 xrefs failed"
    }
    
    echo "✅ Radare2 analysis saved to radare2_analysis/"
}

# Gerar relatório
generate_report() {
    echo ""
    echo "📄 Generating Report..."
    
    cat > ANALYSIS_REPORT.md << 'EOFMARK'
# Binary Analysis Report

## File Information
```
EOFMARK
    
    file "$BINARY_FILE" >> ANALYSIS_REPORT.md
    ls -lh "$BINARY_FILE" >> ANALYSIS_REPORT.md
    
    cat >> ANALYSIS_REPORT.md << 'EOFMARK'
```

## Quick Statistics

EOFMARK
    
    echo "- **Total Symbols**: $(nm "$BINARY_FILE" 2>/dev/null | wc -l)" >> ANALYSIS_REPORT.md
    echo "- **Exported Functions**: $(nm -D "$BINARY_FILE" 2>/dev/null | grep ' T ' | wc -l)" >> ANALYSIS_REPORT.md
    echo "- **Binary Size**: $(du -h "$BINARY_FILE" | cut -f1)" >> ANALYSIS_REPORT.md
    
    cat >> ANALYSIS_REPORT.md << 'EOFMARK'

## Analysis Tools Used

- readelf - ELF header inspection
- nm - Symbol table analysis
- strings - String extraction
- radare2 - Deep binary analysis
- Ghidra - Decompilation (optional, requires Java)

## Output Directories

- `quick_analysis/` - Fast preliminary analysis
- `radare2_analysis/` - Radare2 JSON outputs
- `ANALYSIS_REPORT.md` - This report

## Next Steps

1. Review `radare2_analysis/functions.json` for function list
2. Check `quick_analysis/interesting_strings.txt` for clues
3. Run full Ghidra decompilation via GitHub Actions
4. Analyze cross-references in `radare2_analysis/xrefs.json`

---
Generated: $(date)
EOFMARK
    
    echo "✅ Report saved to ANALYSIS_REPORT.md"
}

# Menu interativo
show_menu() {
    echo ""
    echo "📌 Available Analysis Options:"
    echo "======================================"
    echo "1. Install dependencies"
    echo "2. Quick analysis (readelf, nm, strings)"
    echo "3. Download Ghidra"
    echo "4. Radare2 analysis"
    echo "5. Generate report"
    echo "6. Run ALL analyses"
    echo "7. Exit"
    echo ""
}

# Main
install_dependencies

if [ "$#" -eq 0 ]; then
    # Interactive mode
    while true; do
        show_menu
        read -p "Select option (1-7): " choice
        
        case $choice in
            1) install_dependencies ;;
            2) quick_analysis ;;
            3) download_ghidra ;;
            4) 
                if command -v r2 &> /dev/null; then
                    analyze_with_radare2
                else
                    echo "❌ Radare2 not installed. Run option 1 first."
                fi
                ;;
            5) generate_report ;;
            6) 
                quick_analysis
                if command -v r2 &> /dev/null; then
                    analyze_with_radare2
                fi
                generate_report
                ;;
            7) 
                echo "👋 Exiting..."
                exit 0
                ;;
            *) echo "❌ Invalid option" ;;
        esac
    done
else
    # Non-interactive mode - run all
    quick_analysis
    if command -v r2 &> /dev/null; then
        analyze_with_radare2
    fi
    generate_report
    
    echo ""
    echo "✅ Analysis complete!"
    echo "📂 Results in:"
    echo "   - quick_analysis/"
    echo "   - radare2_analysis/"
    echo "   - ANALYSIS_REPORT.md"
fi
