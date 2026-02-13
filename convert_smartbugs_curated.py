#!/usr/bin/env python3

import json
import os
import re
import shutil
from pathlib import Path


# Map smartbugs categories to our vulnerability types
CATEGORY_MAP = {
    "reentrancy": "reentrancy",
    "arithmetic": "overflow",  # arithmetic covers both overflow/underflow
    "access_control": "access_control",
    "unchecked_low_level_calls": "unhandled_exception",
    "denial_of_service": "dos",
    "bad_randomness": "bad_randomness",
    "front_running": "front_running",
    "time_manipulation": "timestamp",
    "short_addresses": "short_addresses",
    "other": "other",
}


def get_solidity_version(source_code: str) -> str:
    pattern = r'pragma\s+solidity\s+([\^>=<\.\d\s]+);'
    match = re.search(pattern, source_code)
    if match:
        version_str = match.group(1).strip()
        # Extract version number
        versions = re.findall(r'(\d+\.\d+\.\d+|\d+\.\d+)', version_str)
        if versions:
            return versions[0]
    return "0.4.24"  # default


def line_to_byte_offset(content: str, line_number: int) -> tuple[int, int]:
    lines = content.split('\n')
    if line_number < 1 or line_number > len(lines):
        return (0, 0)
    
    # Calculate byte offset for start of line
    start_byte = sum(len(lines[i]) + 1 for i in range(line_number - 1))  # +1 for newline
    end_byte = start_byte + len(lines[line_number - 1])
    
    return (start_byte, end_byte)


def convert_smartbugs_curated(
    input_dir: str = "data/smartbugs-curated",
    output_dir: str = "data/smartbugs-curated-converted",
):
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    # Create output directory
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Load vulnerabilities.json
    vuln_file = input_path / "vulnerabilities.json"
    if not vuln_file.exists():
        print(f"Error: {vuln_file} not found")
        return
    
    with open(vuln_file, 'r') as f:
        vulnerabilities = json.load(f)
    
    converted_count = 0
    error_count = 0
    
    for entry in vulnerabilities:
        contract_name = entry.get("name", "")
        contract_path = entry.get("path", "")
        pragma_version = entry.get("pragma", "0.4.24")
        vuln_list = entry.get("vulnerabilities", [])
        
        if not contract_path or not vuln_list:
            continue
        
        # Full path to source contract
        source_file = input_path / contract_path
        if not source_file.exists():
            print(f"Warning: Contract not found: {source_file}")
            error_count += 1
            continue
        
        # Read contract content
        try:
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {source_file}: {e}")
            error_count += 1
            continue
        
        # Detect actual Solidity version from pragma
        sol_version = get_solidity_version(content)
        if not sol_version:
            sol_version = pragma_version
        
        # Group vulnerabilities by category
        vulns_by_category = {}
        for vuln in vuln_list:
            category = vuln.get("category", "other")
            lines = vuln.get("lines", [])
            if category not in vulns_by_category:
                vulns_by_category[category] = []
            vulns_by_category[category].extend(lines)
        
        # Create output for each vulnerability category
        for category, lines in vulns_by_category.items():
            vuln_type = CATEGORY_MAP.get(category, category)
            
            # Generate output filename
            base_name = source_file.stem  # filename without extension
            output_name = f"{base_name}_{vuln_type}"
            
            # Copy contract file
            output_sol = output_path / f"{output_name}.sol"
            shutil.copy(source_file, output_sol)
            
            # Create metadata JSON
            injected_regions = []
            for line_num in sorted(set(lines)):
                start_byte, end_byte = line_to_byte_offset(content, line_num)
                if start_byte != end_byte:
                    injected_regions.append({
                        "start_byte": start_byte,
                        "end_byte": end_byte,
                        "component": "vulnerable_code",
                        "description": f"Vulnerable line {line_num} ({category})",
                        "line": line_num,
                    })
            
            metadata = {
                "source_contract": str(contract_path),
                "output_contract": f"data/smartbugs-curated-converted/{output_name}.sol",
                "vulnerability_type": vuln_type,
                "injection_mode": "curated",
                "template_name": f"smartbugs_{category}",
                "solidity_version": sol_version,
                "injected_regions": injected_regions,
                "original_category": category,
            }
            
            output_json = output_path / f"{output_name}.json"
            with open(output_json, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            converted_count += 1
            print(f"Converted: {output_name} ({len(injected_regions)} vulnerable regions)")
    
    print(f"\n=== Conversion Complete ===")
    print(f"Converted: {converted_count} contract-vulnerability pairs")
    print(f"Errors: {error_count}")
    print(f"Output directory: {output_path}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Convert SmartBugs-Curated to sc-ast-injector format")
    parser.add_argument("--input-dir", default="data/smartbugs-curated", help="Input directory")
    parser.add_argument("--output-dir", default="data/smartbugs-curated-converted", help="Output directory")
    
    args = parser.parse_args()
    convert_smartbugs_curated(args.input_dir, args.output_dir)
