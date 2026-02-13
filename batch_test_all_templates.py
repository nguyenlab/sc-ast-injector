#!/usr/bin/env python3

import argparse
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field, asdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.version_detector import get_best_version
from services.tool_detector import (
    SLITHER_DETECTORS_BY_NAME,
    SLITHER_IGNORE_DETECTORS,
    get_expected_slither_detectors,
    is_detection_correct,
    compile_contract as tool_compile_contract,
    run_slither as tool_run_slither,
)
from vuln_injector.templates.point_injection import (
    OVERFLOW_TEMPLATES, TX_ORIGIN_TEMPLATES, UNCHECKED_SEND_TEMPLATES,
    UNHANDLED_CALL_TEMPLATES, TIMESTAMP_TEMPLATES, REENTRANCY_TEMPLATES
)

# All templates organized by vulnerability type
ALL_TEMPLATES = {
    'overflow': {k: v for k, v in OVERFLOW_TEMPLATES.items() if v.get('vuln_type') == 'OVERFLOW'},
    'underflow': {k: v for k, v in OVERFLOW_TEMPLATES.items() if v.get('vuln_type') == 'UNDERFLOW'},
    'tx_origin': TX_ORIGIN_TEMPLATES,
    'unchecked_send': UNCHECKED_SEND_TEMPLATES,
    'unhandled_exception': UNHANDLED_CALL_TEMPLATES,
    'timestamp': {k: v for k, v in TIMESTAMP_TEMPLATES.items() if v.get('injection_type') == 'point'},
    'reentrancy': REENTRANCY_TEMPLATES,
}

# Use centralized mappings from tool_detector
EXPECTED_SLITHER = SLITHER_DETECTORS_BY_NAME
GENERIC_WARNINGS = SLITHER_IGNORE_DETECTORS


@dataclass
class InjectionResult:
    contract: str
    template_name: str
    vuln_type: str
    solidity_version: str
    injection_success: bool = False
    compilation_success: bool = False
    slither_detected: bool = False
    slither_correct: bool = False
    slither_detectors: List[str] = field(default_factory=list)
    slither_time: float = 0.0
    error: str = ""
    output_file: str = ""


@dataclass
class ContractStats:
    contract: str
    solidity_version: str
    total_templates_tried: int = 0
    injection_success: int = 0
    compilation_success: int = 0
    slither_detected: int = 0
    slither_correct: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class BatchResults:
    start_time: str
    end_time: str = ""
    total_contracts: int = 0
    contracts_processed: int = 0
    total_injections: int = 0
    injection_success: int = 0
    compilation_success: int = 0
    slither_detected: int = 0
    slither_correct: int = 0
    by_vuln_type: Dict = field(default_factory=dict)
    by_template: Dict = field(default_factory=dict)
    contract_stats: List[ContractStats] = field(default_factory=list)
    injection_results: List[InjectionResult] = field(default_factory=list)


def get_source_contracts(data_dir: str, limit: int = 100) -> List[str]:
    contracts_dir = os.path.join(data_dir, 'smartbugs-wild-clean-contracts')
    if not os.path.exists(contracts_dir):
        print(f"Error: Directory not found: {contracts_dir}")
        return []
    
    contracts = [os.path.join(contracts_dir, f) for f in os.listdir(contracts_dir) 
                 if f.endswith('.sol')]
    
    if len(contracts) > limit:
        contracts = random.sample(contracts, limit)
    
    return sorted(contracts)


def get_solidity_version(filepath: str) -> str:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return get_best_version(content, "slither")
    except Exception:
        return "0.4.24"


def is_version_compatible(version: str, min_version: str, max_version: str) -> bool:
    def parse_version(v: str) -> Tuple[int, ...]:
        v = v.replace('^', '').replace('>=', '').replace('>', '').replace('<', '').strip()
        parts = v.split('.')[:3]
        return tuple(int(p) for p in parts if p.isdigit())
    
    try:
        ver = parse_version(version)
        min_v = parse_version(min_version)
        max_v = parse_version(max_version)
        return min_v <= ver <= max_v
    except (ValueError, IndexError):
        return False


def get_compatible_templates(version: str, vuln_type: str) -> Dict:
    templates = ALL_TEMPLATES.get(vuln_type, {})
    compatible = {}
    for name, template in templates.items():
        min_ver = template.get("min_version", "0.4.0")
        max_ver = template.get("max_version", "0.9.99")
        if is_version_compatible(version, min_ver, max_ver):
            compatible[name] = template
    return compatible


def inject_vulnerability(
    contract_path: str, 
    vuln_type: str, 
    template_name: str,
    output_path: str
) -> Tuple[bool, str]:
    
    cmd = [
        "python", "main.py",
        "--mode", "point",
        "--contract", contract_path,
        "--vuln-type", vuln_type,
        "--template", template_name,
        "--output", output_path,
        "--no-randomize"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        if os.path.exists(output_path):
            return True, ""
        else:
            error = result.stderr or result.stdout or "No output file created"
            # Extract the key error message
            if "Error" in error:
                lines = error.split('\n')
                for line in lines:
                    if "Error" in line or "error" in line:
                        return False, line.strip()[:100]
            return False, error[:100]
            
    except subprocess.TimeoutExpired:
        return False, "Injection timeout"
    except Exception as e:
        return False, str(e)[:100]


def compile_contract(filepath: str, solidity_version: str) -> Tuple[bool, str]:
    result = tool_compile_contract(filepath, solidity_version)
    if result.success:
        return True, ""
    return False, result.error[:100] if len(result.error) > 100 else result.error


def run_slither(filepath: str, solidity_version: str, timeout: int = 60) -> Tuple[bool, List[str], float]:
    result = tool_run_slither(filepath, solidity_version, timeout)
    return result.detected, result.detectors_found, result.time_taken


def check_detection(vuln_type: str, detected_ids: List[str]) -> bool:
    return is_detection_correct(vuln_type, detected_ids, tool="slither")


def process_contract(
    contract_path: str,
    output_dir: str,
    results: BatchResults,
    verbose: bool = False
) -> ContractStats:
    
    contract_name = os.path.basename(contract_path)
    sol_version = get_solidity_version(contract_path)
    
    stats = ContractStats(
        contract=contract_name,
        solidity_version=sol_version
    )
    
    if verbose:
        print(f"\n[*] Contract: {contract_name} (v{sol_version})")
    
    # Try each vulnerability type
    for vuln_type in ALL_TEMPLATES.keys():
        compatible = get_compatible_templates(sol_version, vuln_type)
        
        if not compatible:
            continue
        
        # Try each compatible template
        for template_name in compatible.keys():
            stats.total_templates_tried += 1
            results.total_injections += 1
            
            # Initialize tracking
            if vuln_type not in results.by_vuln_type:
                results.by_vuln_type[vuln_type] = {
                    'total': 0, 'injected': 0, 'compiled': 0, 
                    'detected': 0, 'correct': 0
                }
            if template_name not in results.by_template:
                results.by_template[template_name] = {
                    'vuln_type': vuln_type, 'total': 0, 'injected': 0, 
                    'compiled': 0, 'detected': 0, 'correct': 0
                }
            
            results.by_vuln_type[vuln_type]['total'] += 1
            results.by_template[template_name]['total'] += 1
            
            # Create output path
            base_name = contract_name.replace('.sol', '')
            output_path = os.path.join(output_dir, f"{base_name}_{template_name}.sol")
            
            result = InjectionResult(
                contract=contract_name,
                template_name=template_name,
                vuln_type=vuln_type,
                solidity_version=sol_version,
                output_file=os.path.basename(output_path)
            )
            
            # Step 1: Inject
            success, error = inject_vulnerability(
                contract_path, vuln_type, template_name, output_path
            )
            
            if not success:
                result.error = error
                results.injection_results.append(result)
                if verbose:
                    print(f"    ✗ {template_name}: injection failed")
                continue
            
            result.injection_success = True
            stats.injection_success += 1
            results.injection_success += 1
            results.by_vuln_type[vuln_type]['injected'] += 1
            results.by_template[template_name]['injected'] += 1
            
            # Step 2: Compile
            compiled, comp_error = compile_contract(output_path, sol_version)
            
            if not compiled:
                result.error = comp_error
                results.injection_results.append(result)
                if verbose:
                    print(f"    ✗ {template_name}: compilation failed")
                # Clean up failed file
                try:
                    os.remove(output_path)
                except:
                    pass
                continue
            
            result.compilation_success = True
            stats.compilation_success += 1
            results.compilation_success += 1
            results.by_vuln_type[vuln_type]['compiled'] += 1
            results.by_template[template_name]['compiled'] += 1
            
            # Step 3: Run Slither
            detected, detectors, elapsed = run_slither(output_path, sol_version)
            result.slither_detected = detected
            result.slither_detectors = detectors
            result.slither_time = elapsed
            
            if detected:
                stats.slither_detected += 1
                results.slither_detected += 1
                results.by_vuln_type[vuln_type]['detected'] += 1
                results.by_template[template_name]['detected'] += 1
            
            # Check if correct vulnerability was detected
            correct = check_detection(vuln_type, detectors)
            result.slither_correct = correct
            
            if correct:
                stats.slither_correct += 1
                results.slither_correct += 1
                results.by_vuln_type[vuln_type]['correct'] += 1
                results.by_template[template_name]['correct'] += 1
            
            results.injection_results.append(result)
            
            if verbose:
                status = "✓" if correct else "✗"
                print(f"    {status} {template_name}: {detectors if detectors else 'not detected'} [{elapsed:.1f}s]")
    
    return stats


def main():
    parser = argparse.ArgumentParser(description="Batch test all templates on real contracts")
    parser.add_argument("--count", type=int, default=100, help="Number of contracts to test")
    parser.add_argument("--data-dir", default="data", help="Data directory")
    parser.add_argument("--output-dir", default="batch_results", help="Output directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--seed", type=int, help="Random seed for reproducibility")
    
    args = parser.parse_args()
    
    if args.seed:
        random.seed(args.seed)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get contracts
    contracts = get_source_contracts(args.data_dir, args.count)
    if not contracts:
        print("No contracts found!")
        return
    
    print("=" * 80)
    print("BATCH TESTING ALL TEMPLATES ON REAL CONTRACTS")
    print("=" * 80)
    print(f"Contracts: {len(contracts)}")
    print(f"Output directory: {args.output_dir}")
    print(f"Vulnerability types: {list(ALL_TEMPLATES.keys())}")
    print("=" * 80)
    
    # Initialize results
    results = BatchResults(
        start_time=datetime.now().isoformat(),
        total_contracts=len(contracts)
    )
    
    # Process each contract
    for i, contract_path in enumerate(contracts, 1):
        print(f"\n[{i}/{len(contracts)}] Processing: {os.path.basename(contract_path)}")
        
        try:
            stats = process_contract(
                contract_path, 
                args.output_dir, 
                results,
                verbose=args.verbose
            )
            results.contract_stats.append(stats)
            results.contracts_processed += 1
            
            # Print progress summary
            if stats.total_templates_tried > 0:
                print(f"    Templates tried: {stats.total_templates_tried}, "
                      f"Injected: {stats.injection_success}, "
                      f"Compiled: {stats.compilation_success}, "
                      f"Detected: {stats.slither_correct}")
            else:
                print(f"    No compatible templates found")
                
        except Exception as e:
            print(f"    Error processing contract: {e}")
    
    results.end_time = datetime.now().isoformat()
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Contracts processed:    {results.contracts_processed}/{results.total_contracts}")
    print(f"Total injection attempts: {results.total_injections}")
    print(f"Successful injections:  {results.injection_success} ({100*results.injection_success/max(1,results.total_injections):.1f}%)")
    print(f"Compilation success:    {results.compilation_success} ({100*results.compilation_success/max(1,results.injection_success):.1f}%)")
    print(f"Slither detected:       {results.slither_detected}/{results.compilation_success}")
    print(f"Slither correct:        {results.slither_correct}/{results.compilation_success}")
    
    print("\nBy Vulnerability Type:")
    for vuln_type, stats in sorted(results.by_vuln_type.items()):
        print(f"  {vuln_type}: total={stats['total']}, injected={stats['injected']}, "
              f"compiled={stats['compiled']}, correct={stats['correct']}")
    
    print("\nBy Template (top 10 by success):")
    sorted_templates = sorted(
        results.by_template.items(), 
        key=lambda x: x[1]['correct'], 
        reverse=True
    )[:10]
    for template_name, stats in sorted_templates:
        print(f"  {template_name}: compiled={stats['compiled']}, correct={stats['correct']}")
    
    # Save results
    report_path = os.path.join(args.output_dir, "batch_test_report.json")
    with open(report_path, 'w') as f:
        # Convert dataclasses to dicts
        report = {
            'summary': {
                'start_time': results.start_time,
                'end_time': results.end_time,
                'total_contracts': results.total_contracts,
                'contracts_processed': results.contracts_processed,
                'total_injections': results.total_injections,
                'injection_success': results.injection_success,
                'compilation_success': results.compilation_success,
                'slither_detected': results.slither_detected,
                'slither_correct': results.slither_correct,
            },
            'by_vuln_type': results.by_vuln_type,
            'by_template': results.by_template,
            'contract_stats': [asdict(s) for s in results.contract_stats],
            'injection_results': [asdict(r) for r in results.injection_results],
        }
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
