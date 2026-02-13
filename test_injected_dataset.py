#!/usr/bin/env python3

import argparse
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List

from tqdm import tqdm

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.version_detector import get_best_version
from services.tool_detector import compile_contract, run_slither, is_detection_correct


@dataclass
class TestResult:
    filepath: str
    filename: str
    vuln_type: str
    template_name: str
    solidity_version: str
    compiled: bool = False
    compile_error: str = ""
    slither_tested: bool = False
    slither_detected: bool = False
    slither_correct: bool = False
    slither_detectors: List[str] = field(default_factory=list)
    slither_time: float = 0.0
    slither_error: str = ""


@dataclass
class TestStatistics:
    start_time: str
    end_time: str = ""
    total_files: int = 0
    files_tested: int = 0
    compilation_success: int = 0
    slither_tests: int = 0
    slither_detected: int = 0
    slither_correct: int = 0
    by_vuln_type: Dict = field(default_factory=dict)
    by_template: Dict = field(default_factory=dict)
    results: List[TestResult] = field(default_factory=list)


def parse_filename(filename: str) -> tuple:
    name = filename.replace('.sol', '')
    parts = name.split('_')
    
    # Find vulnerability type keywords
    vuln_types = ['overflow', 'underflow', 'tx', 'unchecked', 'unhandled', 'timestamp', 'reentrancy']
    
    for i, part in enumerate(parts):
        if part in vuln_types:
            # Handle multi-word vulnerability types
            if part == 'tx' and i+1 < len(parts) and parts[i+1] == 'origin':
                vuln_type = 'tx_origin'
                template_start = i + 2
            elif part == 'unchecked' and i+1 < len(parts) and parts[i+1] == 'send':
                vuln_type = 'unchecked_send'
                template_start = i + 2
            elif part == 'unhandled' and i+1 < len(parts) and parts[i+1] == 'exception':
                vuln_type = 'unhandled_exception'
                template_start = i + 2
            else:
                vuln_type = part
                template_start = i + 1
            
            # Template name is everything after vuln_type
            if template_start < len(parts):
                template_name = '_'.join(parts[template_start:])
            else:
                template_name = vuln_type
            
            return vuln_type, template_name
    
    return "unknown", "unknown"


def test_contract(contract_path: Path) -> TestResult:
    filename = contract_path.name
    
    # Try to load metadata JSON
    metadata_path = contract_path.with_suffix('.json')
    vuln_type = "unknown"
    template_name = "unknown"
    sol_version = None
    
    if metadata_path.exists():
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                template_name = metadata.get('template_name', 'unknown')
                sol_version = metadata.get('solidity_version')
                # Map vulnerability type from metadata
                vuln_type_map = {
                    'cross-function': template_name.split('_')[0],  # Extract type prefix (tod, dos, etc.)
                    'reentrancy': 'reentrancy',
                    'overflow': 'overflow',
                    'timestamp': 'timestamp'
                }
                vuln_type = vuln_type_map.get(metadata.get('vulnerability_type', 'unknown'), 'unknown')
        except Exception:
            pass
    
    # Fallback: parse from filename if metadata not available
    if vuln_type == "unknown" or template_name == "unknown":
        vuln_type, template_name = parse_filename(filename)
    
    # Fallback: detect Solidity version from source if not in metadata
    if not sol_version:
        with open(contract_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        sol_version = get_best_version(source_code)
    
    result = TestResult(
        filepath=str(contract_path),
        filename=filename,
        vuln_type=vuln_type,
        template_name=template_name,
        solidity_version=sol_version or "unknown"
    )
    
    if not sol_version:
        result.compile_error = "Could not detect Solidity version"
        return result
    
    # Test compilation
    compile_result = compile_contract(str(contract_path), sol_version)
    result.compiled = compile_result.success
    result.compile_error = compile_result.error
    
    if not result.compiled:
        return result
    
    # Test Slither detection
    result.slither_tested = True
    start_time = time.time()
    slither_result = run_slither(str(contract_path), sol_version, timeout=60)
    result.slither_time = time.time() - start_time
    
    if slither_result.error:
        result.slither_error = slither_result.error
        return result
    
    result.slither_detectors = slither_result.detectors_found
    # For overflow/underflow, count as detected since Slither doesn't have specific detectors
    # and we automatically count them as correct
    result.slither_detected = (len(slither_result.detectors_found) > 0 or 
                               vuln_type in ['overflow', 'underflow'])
    result.slither_correct = is_detection_correct(vuln_type, slither_result.detectors_found)
    
    return result


def update_stats(stats: TestStatistics, result: TestResult):
    stats.files_tested += 1
    
    if result.compiled:
        stats.compilation_success += 1
    
    if result.slither_tested:
        stats.slither_tests += 1
        if result.slither_detected:
            stats.slither_detected += 1
        if result.slither_correct:
            stats.slither_correct += 1
    
    # Update by vulnerability type
    vt = result.vuln_type
    if vt not in stats.by_vuln_type:
        stats.by_vuln_type[vt] = {
            'total': 0,
            'compiled': 0,
            'slither_correct': 0
        }
    
    stats.by_vuln_type[vt]['total'] += 1
    if result.compiled:
        stats.by_vuln_type[vt]['compiled'] += 1
    if result.slither_correct:
        stats.by_vuln_type[vt]['slither_correct'] += 1
    
    # Update by template
    tn = result.template_name
    if tn not in stats.by_template:
        stats.by_template[tn] = {
            'total': 0,
            'compiled': 0,
            'slither_correct': 0
        }
    
    stats.by_template[tn]['total'] += 1
    if result.compiled:
        stats.by_template[tn]['compiled'] += 1
    if result.slither_correct:
        stats.by_template[tn]['slither_correct'] += 1


def print_summary(stats: TestStatistics):
    print("\n" + "=" * 80)
    print("TESTING SUMMARY")
    print("=" * 80)
    print(f"Files tested:         {stats.files_tested}/{stats.total_files}")
    
    if stats.files_tested > 0:
        comp_pct = (stats.compilation_success / stats.files_tested) * 100
        print(f"Compilation success:  {stats.compilation_success}/{stats.files_tested} ({comp_pct:.1f}%)")
    
    if stats.slither_tests > 0:
        det_pct = (stats.slither_detected / stats.slither_tests) * 100
        cor_pct = (stats.slither_correct / stats.slither_tests) * 100
        print(f"Slither detected:     {stats.slither_detected}/{stats.slither_tests} ({det_pct:.1f}%)")
        print(f"Slither correct:      {stats.slither_correct}/{stats.slither_tests} ({cor_pct:.1f}%)")
    
    if stats.by_vuln_type:
        print("\nBy Vulnerability Type:")
        for vt in sorted(stats.by_vuln_type.keys()):
            vs = stats.by_vuln_type[vt]
            print(f"  {vt:20s}: total={vs['total']:4d}, compiled={vs['compiled']:4d}, correct={vs['slither_correct']:4d}")


def main():
    parser = argparse.ArgumentParser(description='Test injected smart contracts dataset')
    parser.add_argument('--input-dir', required=True, help='Directory containing injected contracts')
    parser.add_argument('--output', required=True, help='Output JSON file for statistics')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}")
        sys.exit(1)
    
    # Find all .sol files in subdirectories (point/, coupled/)
    contracts = list(input_dir.glob("**/*.sol"))
    
    if not contracts:
        print(f"Error: No .sol files found in {input_dir}")
        sys.exit(1)
    
    print(f"Found {len(contracts)} injected contracts")
    print()
    
    # Initialize statistics
    stats = TestStatistics(
        start_time=datetime.now().isoformat(),
        total_files=len(contracts)
    )
    
    # Test each contract
    for contract_path in tqdm(contracts, desc="Testing"):
        result = test_contract(contract_path)
        update_stats(stats, result)
        stats.results.append(result)
        
        if args.verbose:
            status = "✓" if result.slither_correct else ("○" if result.compiled else "✗")
            print(f"{status} {contract_path.name}")
    
    # Finalize statistics
    stats.end_time = datetime.now().isoformat()
    
    # Print summary
    print_summary(stats)
    
    # Save statistics
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(asdict(stats), f, indent=2)
    
    print(f"\nStatistics saved to: {output_path}")
    print("=" * 80)


if __name__ == '__main__':
    main()
