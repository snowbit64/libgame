#!/usr/bin/env python3
"""
Advanced decompilation analysis for stripped dynamic libraries.
Integrates multiple tools for comprehensive reverse engineering.
"""

import os
import json
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import hashlib


@dataclass
class FunctionMetadata:
    """Function metadata structure"""
    address: str
    name: str
    size: int
    section: str
    is_plt: bool
    is_text: bool
    xrefs_count: int = 0
    strings_count: int = 0
    entropy: float = 0.0


class BinaryAnalyzer:
    """Main analysis orchestrator"""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.output_dir = Path("analysis_results")
        self.output_dir.mkdir(exist_ok=True)
        self.functions: List[FunctionMetadata] = []
    
    def analyze_with_readelf(self) -> Dict:
        """Extract binary information using readelf"""
        print("[*] Running readelf analysis...")
        
        result = {
            'sections': {},
            'symbols': {},
            'dynamic_symbols': {}
        }
        
        try:
            # Get sections
            output = subprocess.check_output(
                ['readelf', '-S', self.binary_path],
                text=True
            )
            result['sections'] = output
            
            # Get symbols
            output = subprocess.check_output(
                ['readelf', '-s', self.binary_path],
                text=True, stderr=subprocess.DEVNULL
            )
            result['symbols'] = output
            
            # Get dynamic symbols
            output = subprocess.check_output(
                ['readelf', '-sD', self.binary_path],
                text=True, stderr=subprocess.DEVNULL
            )
            result['dynamic_symbols'] = output
        except Exception as e:
            print(f"[!] readelf error: {e}")
        
        return result
    
    def analyze_with_objdump(self) -> Dict:
        """Extract disassembly using objdump"""
        print("[*] Running objdump analysis...")
        
        result = {
            'symbols': [],
            'sections': []
        }
        
        try:
            # Get all symbols
            output = subprocess.check_output(
                ['objdump', '-t', self.binary_path],
                text=True
            )
            
            for line in output.split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    result['symbols'].append({
                        'address': parts[0],
                        'type': parts[1],
                        'name': parts[-1] if len(parts) > 4 else ''
                    })
            
            # Get section info
            output = subprocess.check_output(
                ['objdump', '-h', self.binary_path],
                text=True
            )
            result['sections'] = output
            
        except Exception as e:
            print(f"[!] objdump error: {e}")
        
        return result
    
    def analyze_with_nm(self) -> List[Dict]:
        """Extract symbol information using nm"""
        print("[*] Running nm analysis...")
        
        symbols = []
        
        try:
            # Dynamic symbols
            output = subprocess.check_output(
                ['nm', '-D', self.binary_path],
                text=True, stderr=subprocess.DEVNULL
            )
            
            for line in output.split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    symbols.append({
                        'address': parts[0],
                        'type': parts[1] if len(parts) > 1 else 'U',
                        'name': parts[2] if len(parts) > 2 else 'unknown',
                        'is_dynamic': True
                    })
            
            # All symbols
            output = subprocess.check_output(
                ['nm', self.binary_path],
                text=True, stderr=subprocess.DEVNULL
            )
            
            static_symbols = []
            for line in output.split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    static_symbols.append({
                        'address': parts[0],
                        'type': parts[1] if len(parts) > 1 else 'U',
                        'name': parts[2] if len(parts) > 2 else 'unknown',
                        'is_dynamic': False
                    })
            
            symbols.extend(static_symbols)
            
        except Exception as e:
            print(f"[!] nm error: {e}")
        
        return symbols
    
    def analyze_with_strings(self) -> List[str]:
        """Extract strings from binary"""
        print("[*] Extracting strings...")
        
        strings = []
        
        try:
            output = subprocess.check_output(
                ['strings', self.binary_path],
                text=True
            )
            strings = [s for s in output.split('\n') if s.strip()]
        except Exception as e:
            print(f"[!] strings error: {e}")
        
        return strings
    
    def analyze_with_radare2(self) -> Dict:
        """Deep analysis using radare2"""
        print("[*] Running radare2 analysis...")
        
        result = {}
        
        try:
            # Function analysis
            output = subprocess.check_output(
                ['r2', '-j', '-c', 'aaa;afj', self.binary_path],
                text=True, stderr=subprocess.DEVNULL
            )
            result['functions'] = json.loads(output)
        except Exception as e:
            print(f"[!] radare2 functions error: {e}")
        
        try:
            # Strings analysis
            output = subprocess.check_output(
                ['r2', '-j', '-c', 'izj', self.binary_path],
                text=True, stderr=subprocess.DEVNULL
            )
            result['strings'] = json.loads(output)
        except Exception as e:
            print(f"[!] radare2 strings error: {e}")
        
        return result
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        entropy = 0
        for byte in range(256):
            freq = data.count(bytes([byte]))
            if freq:
                p = freq / len(data)
                entropy -= p * (p**0.5)  # Simple entropy metric
        
        return entropy
    
    def generate_reports(self):
        """Generate comprehensive analysis reports"""
        print("[*] Generating reports...")
        
        # Binary info report
        readelf_data = self.analyze_with_readelf()
        objdump_data = self.analyze_with_objdump()
        nm_symbols = self.analyze_with_nm()
        strings_list = self.analyze_with_strings()
        radare2_data = self.analyze_with_radare2()
        
        # Save to JSON
        report = {
            'binary': self.binary_path,
            'readelf': readelf_data,
            'objdump': objdump_data,
            'nm_symbols': nm_symbols[:100],  # First 100
            'strings': strings_list[:500],   # First 500
            'radare2': radare2_data
        }
        
        with open(self.output_dir / 'analysis_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Function summary
        if 'functions' in radare2_data:
            func_summary = {
                'total_functions': len(radare2_data['functions']),
                'functions': radare2_data['functions'][:50]  # First 50
            }
            
            with open(self.output_dir / 'functions_summary.json', 'w') as f:
                json.dump(func_summary, f, indent=2)
        
        # Strings summary
        with open(self.output_dir / 'strings_extracted.txt', 'w') as f:
            f.write('\n'.join(strings_list))
        
        # Symbols summary
        with open(self.output_dir / 'symbols_extracted.json', 'w') as f:
            json.dump(nm_symbols, f, indent=2)
        
        print(f"[✓] Reports saved to {self.output_dir}/")
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"ANALYSIS SUMMARY")
        print(f"{'='*60}")
        print(f"Binary: {self.binary_path}")
        print(f"Total symbols found: {len(nm_symbols)}")
        print(f"Total strings extracted: {len(strings_list)}")
        if 'functions' in radare2_data:
            print(f"Total functions detected: {len(radare2_data['functions'])}")
        print(f"Output directory: {self.output_dir.absolute()}")
        print(f"{'='*60}\n")
    
    def run(self):
        """Execute full analysis"""
        print(f"[*] Starting analysis of {self.binary_path}")
        
        if not os.path.exists(self.binary_path):
            print(f"[!] Error: {self.binary_path} not found")
            sys.exit(1)
        
        self.generate_reports()
        print("[✓] Analysis complete!")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced binary analysis for stripped libraries'
    )
    parser.add_argument('binary', help='Path to binary file')
    parser.add_argument('-o', '--output', default='analysis_results',
                       help='Output directory')
    
    args = parser.parse_args()
    
    analyzer = BinaryAnalyzer(args.binary)
    analyzer.run()


if __name__ == '__main__':
    main()
