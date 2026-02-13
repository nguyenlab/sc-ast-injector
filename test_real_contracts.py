#!/usr/bin/env python3

import argparse
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple

# Add project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.version_detector import get_best_version
from services.tool_detector import (
    SLITHER_DETECTORS_BY_NAME,
    SWC_MAPPING_BY_NAME,
    SLITHER_IGNORE_DETECTORS,
    is_detection_correct,
    compile_contract as tool_compile_contract,
    run_slither as tool_run_slither,
)

# Vulnerability types to test
VULN_TYPES = ['reentrancy', 'overflow', 'underflow', 'tx_origin', 'unchecked_send', 'timestamp']

# Use centralized mappings
EXPECTED_SWC = SWC_MAPPING_BY_NAME
EXPECTED_SLITHER = SLITHER_DETECTORS_BY_NAME
GENERIC_WARNINGS = SLITHER_IGNORE_DETECTORS


def get_source_contracts(data_dir: str, limit: int = 10) -> List[str]:
    contracts_dir = os.path.join(data_dir, 'smartbugs-wild-clean-contracts')
    if not os.path.exists(contracts_dir):
        print(f"Error: Directory not found: {contracts_dir}")
        return []
    
    contracts = [os.path.join(contracts_dir, f) for f in os.listdir(contracts_dir) 
                 if f.endswith('.sol')]
    
    if len(contracts) > limit:
        contracts = random.sample(contracts, limit)
    
    return contracts


def inject_vulnerability(contract_path: str, vuln_type: str, output_dir: str) -> Tuple[bool, str, str]:
    contract_name = os.path.basename(contract_path).replace('.sol', '')
    output_path = os.path.join(output_dir, f"{contract_name}_{vuln_type}.sol")
    
    cmd = [
        "python", "main.py",
        "--mode", "point",
        "--contract", contract_path,
        "--vuln-type", vuln_type,
        "--output", output_path,
        "--no-randomize"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        if os.path.exists(output_path):
            return True, output_path, ""
        else:
            return False, "", result.stderr or "No output file created"
            
    except subprocess.TimeoutExpired:
        return False, "", "Injection timeout"
    except Exception as e:
        return False, "", str(e)


def compile_contract(filepath: str, solidity_version: str = None) -> Tuple[bool, str]:
    if not solidity_version:
        solidity_version = get_solidity_version(filepath)
    
    result = tool_compile_contract(filepath, solidity_version)
    if result.success:
        return True, ""
    error_msg = result.error[:200] if len(result.error) > 200 else result.error
    return False, error_msg


def get_solidity_version(filepath: str, tool_name: str = "slither") -> str:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return get_best_version(content, tool_name)
    except Exception:
        return "0.4.24"


def run_mythril(filepath: str, solidity_version: str, timeout: int = 120) -> Tuple[bool, List[str], float]:
    start = time.time()
    
    cmd = ["myth", "analyze", filepath, "--solv", solidity_version, "-t", "2"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.time() - start
        output = result.stdout + result.stderr
        swc_ids = list(set(re.findall(r'SWC ID: (\d+)', output)))
        return len(swc_ids) > 0, swc_ids, elapsed
    except subprocess.TimeoutExpired:
        return False, [], timeout
    except Exception as e:
        return False, [], time.time() - start


def run_slither(filepath: str, solidity_version: str, timeout: int = 60) -> Tuple[bool, List[str], float]:
    result = tool_run_slither(filepath, solidity_version, timeout)
    return result.detected, result.detectors_found, result.time_taken


def check_detection(vuln_type: str, tool: str, detected_ids: List[str]) -> bool:
    return is_detection_correct(vuln_type, detected_ids, tool=tool)


def main():
    parser = argparse.ArgumentParser(description='Test injection and verification on real contracts')
    parser.add_argument('--count', type=int, default=10, help='Number of contracts to test')
    parser.add_argument('--data-dir', default='data', help='Data directory with source contracts')
    parser.add_argument('--output-dir', default='tmp_test_files', help='Output directory for injected contracts')
    parser.add_argument('--timeout', type=int, default=120, help='Analysis timeout per contract')
    parser.add_argument('--tool', choices=['mythril', 'slither', 'all'], default='all', help='Tool to use')
    parser.add_argument('--vuln-type', choices=VULN_TYPES + ['all'], default='all', help='Vulnerability type')
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get source contracts
    contracts = get_source_contracts(args.data_dir, args.count)
    if not contracts:
        print("No contracts found!")
        return
    
    print("=" * 80)
    print("TESTING VULNERABILITY INJECTION ON REAL CONTRACTS")
    print(f"Contracts: {len(contracts)}")
    print(f"Tools: {args.tool}")
    print(f"Vuln types: {args.vuln_type}")
    print("=" * 80)
    
    # Determine vulnerability types to test
    if args.vuln_type == 'all':
        vuln_types = VULN_TYPES
    else:
        vuln_types = [args.vuln_type]
    
    # Stats
    stats = {
        'total_injections': 0,
        'successful_injections': 0,
        'compilation_success': 0,
        'mythril_detected': 0,
        'mythril_correct': 0,
        'slither_detected': 0,
        'slither_correct': 0,
        'by_vuln_type': {}
    }
    
    results = []
    
    for contract_path in contracts:
        contract_name = os.path.basename(contract_path)
        print(f"\n[*] Contract: {contract_name}")
        
        # Try one random vulnerability type per contract for speed
        vuln_type = random.choice(vuln_types)
        
        print(f"    Injecting: {vuln_type}")
        stats['total_injections'] += 1
        
        if vuln_type not in stats['by_vuln_type']:
            stats['by_vuln_type'][vuln_type] = {
                'injected': 0, 'compiled': 0, 
                'mythril_detected': 0, 'slither_detected': 0
            }
        
        # Inject vulnerability
        success, output_path, error = inject_vulnerability(contract_path, vuln_type, args.output_dir)
        
        if not success:
            print(f"    ✗ Injection failed: {error[:50]}")
            continue
        
        stats['successful_injections'] += 1
        stats['by_vuln_type'][vuln_type]['injected'] += 1
        print(f"    ✓ Injected: {os.path.basename(output_path)}")
        
        # Get Solidity version for compilation and analysis
        sol_version = get_solidity_version(output_path)
        
        # Check compilation
        compiled, comp_error = compile_contract(output_path, sol_version)
        if not compiled:
            print(f"    ✗ Compilation failed: {comp_error[:50]}")
            continue
        
        stats['compilation_success'] += 1
        stats['by_vuln_type'][vuln_type]['compiled'] += 1
        print(f"    ✓ Compilation OK (v{sol_version})")
        
        result = {
            'contract': contract_name,
            'vuln_type': vuln_type,
            'output_file': os.path.basename(output_path),
            'compiled': True,
            'solidity_version': sol_version
        }
        
        # Run Mythril
        if args.tool in ['mythril', 'all']:
            detected, swc_ids, elapsed = run_mythril(output_path, sol_version, args.timeout)
            correct = check_detection(vuln_type, 'mythril', swc_ids)
            
            if detected:
                stats['mythril_detected'] += 1
                stats['by_vuln_type'][vuln_type]['mythril_detected'] += 1
            if correct:
                stats['mythril_correct'] += 1
            
            status = "✓" if correct else "✗"
            swc_str = ','.join(swc_ids) if swc_ids else 'not detected'
            print(f"    {status} mythril: {swc_str} [{elapsed:.1f}s]")
            
            result['mythril'] = {'detected': detected, 'swc_ids': swc_ids, 'correct': correct, 'time': elapsed}
        
        # Run Slither
        if args.tool in ['slither', 'all']:
            detected, detectors, elapsed = run_slither(output_path, sol_version, 60)
            correct = check_detection(vuln_type, 'slither', detectors)
            
            if detected:
                stats['slither_detected'] += 1
                stats['by_vuln_type'][vuln_type]['slither_detected'] += 1
            if correct:
                stats['slither_correct'] += 1
            
            status = "✓" if correct else "✗"
            det_str = ','.join(detectors[:3]) if detectors else 'not detected'
            print(f"    {status} slither: {det_str} [{elapsed:.1f}s]")
            
            result['slither'] = {'detected': detected, 'detectors': detectors, 'correct': correct, 'time': elapsed}
        
        results.append(result)
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total injection attempts: {stats['total_injections']}")
    print(f"Successful injections:    {stats['successful_injections']}")
    print(f"Compilation success:      {stats['compilation_success']}")
    
    if args.tool in ['mythril', 'all']:
        print(f"Mythril detected:         {stats['mythril_detected']}/{stats['compilation_success']}")
        print(f"Mythril correct:          {stats['mythril_correct']}/{stats['compilation_success']}")
    
    if args.tool in ['slither', 'all']:
        print(f"Slither detected:         {stats['slither_detected']}/{stats['compilation_success']}")
        print(f"Slither correct:          {stats['slither_correct']}/{stats['compilation_success']}")
    
    print("\nBy Vulnerability Type:")
    for vt, vs in stats['by_vuln_type'].items():
        print(f"  {vt}: injected={vs['injected']}, compiled={vs['compiled']}, "
              f"mythril={vs.get('mythril_detected', 0)}, slither={vs.get('slither_detected', 0)}")
    
    # Save report
    report = {
        'stats': stats,
        'results': results
    }
    
    report_path = os.path.join(args.output_dir, 'real_contracts_test_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to: {report_path}")


if __name__ == '__main__':
    main()
