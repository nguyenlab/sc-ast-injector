#!/usr/bin/env python3

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from tqdm import tqdm

from services.version_detector import (
    get_best_version, 
    VersionDetector, 
    VersionConstraint,
    MIN_SUPPORTED_VERSION
)
from services.tool_detector import (
    compile_contract, 
    run_slither, 
    is_detection_correct,
    SLITHER_DETECTORS_BY_NAME
)


@dataclass
class TestResult:
    filename: str
    contract_name: str
    vuln_type: str
    solidity_version: str = ""
    
    # Compilation results
    compiled: bool = False
    compilation_error: str = ""
    compile_time: float = 0.0
    
    # Slither results
    slither_tested: bool = False
    slither_detected: bool = False
    slither_correct: bool = False
    slither_detectors: List[str] = field(default_factory=list)
    slither_time: float = 0.0
    slither_error: str = ""
    
    # Metadata from JSON
    num_regions: int = 0


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
    results: List[TestResult] = field(default_factory=list)


def parse_filename(filename: str) -> tuple:
    name = filename.replace('.sol', '')
    
    # Known vulnerability types
    vuln_types = [
        'access_control',
        'arithmetic', 
        'bad_randomness',
        'denial_of_service',
        'front_running',
        'other',
        'reentrancy',
        'short_addresses',
        'time_manipulation',
        'unchecked_low_level_calls',
        'unhandled_exception',
        'tx_origin',
        'overflow',
        'underflow',
        'timestamp'
    ]
    
    # Try to find vuln_type at the end
    for vt in sorted(vuln_types, key=len, reverse=True):  # Longest first
        suffix = f"_{vt}"
        if name.endswith(suffix):
            contract_name = name[:-len(suffix)]
            return contract_name, vt
    
    # Fallback: split by last underscore
    parts = name.rsplit('_', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    
    return name, 'unknown'


def load_metadata(json_path: Path) -> Optional[dict]:
    if json_path.exists():
        try:
            with open(json_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load metadata {json_path}: {e}")
    return None


def test_contract(contract_path: Path, verbose: bool = False) -> TestResult:
    filename = contract_path.name
    contract_name, vuln_type = parse_filename(filename)
    
    result = TestResult(
        filename=filename,
        contract_name=contract_name,
        vuln_type=vuln_type
    )
    
    # Load metadata
    json_path = contract_path.with_suffix('.json')
    metadata = load_metadata(json_path)
    if metadata:
        result.num_regions = len(metadata.get('injected_regions', []))
    
    # Read source code
    try:
        with open(contract_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
    except Exception as e:
        result.compilation_error = f"Failed to read file: {e}"
        return result
    
    # Detect pragma info to handle exact versions specially
    pragma_info = VersionDetector.detect_version(source_code)
    
    if pragma_info:
        # Check for exact version pragmas below minimum supported
        if pragma_info.constraint_type == VersionConstraint.EXACT:
            if pragma_info.min_version < MIN_SUPPORTED_VERSION:
                result.compilation_error = (
                    f"Exact pragma {pragma_info.min_version} is below minimum supported "
                    f"version {MIN_SUPPORTED_VERSION}. Cannot compile without modifying source."
                )
                result.solidity_version = str(pragma_info.min_version)
                return result
            # Use the exact version for compilation
            version = str(pragma_info.min_version)
        else:
            # For non-exact pragmas, use the recommended version
            version = str(pragma_info.recommended_version)
    else:
        # Fallback
        version = "0.4.24"
    
    result.solidity_version = version
    
    # Compile contract
    if verbose:
        print(f"  Compiling with solc {version}...")
    
    compile_result = compile_contract(str(contract_path), version)
    # compile_time is not tracked by the tool_detector module
    result.compile_time = 0.0
    
    if not compile_result.success:
        result.compilation_error = compile_result.error or "Unknown compilation error"
        return result
    
    result.compiled = True
    
    # Run Slither
    if verbose:
        print(f"  Running Slither...")
    
    result.slither_tested = True
    slither_result = run_slither(str(contract_path), version, timeout=120)  # 2 min timeout
    result.slither_time = slither_result.time_taken
    
    if slither_result.error:
        result.slither_error = slither_result.error
        return result
    
    result.slither_detectors = slither_result.detectors_found
    
    # Map SmartBugs vuln types to our detector categories
    # SmartBugs uses slightly different naming
    vuln_mapping = {
        'unchecked_low_level_calls': 'unchecked_send',
        'unhandled_exception': 'unhandled_exception',
        'time_manipulation': 'timestamp',
        'denial_of_service': 'denial_of_service',
        'arithmetic': 'overflow',  # Includes overflow/underflow
    }
    
    mapped_vuln = vuln_mapping.get(vuln_type, vuln_type)
    
    # Check detection
    result.slither_detected = len(slither_result.detectors_found) > 0
    result.slither_correct = is_detection_correct(mapped_vuln, slither_result.detectors_found)
    
    return result


def update_stats(stats: TestStatistics, result: TestResult):
    """Update statistics with a test result."""
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
            'slither_tested': 0,
            'slither_detected': 0,
            'slither_correct': 0,
            'errors': []
        }
    
    stats.by_vuln_type[vt]['total'] += 1
    if result.compiled:
        stats.by_vuln_type[vt]['compiled'] += 1
    if result.slither_tested:
        stats.by_vuln_type[vt]['slither_tested'] += 1
    if result.slither_detected:
        stats.by_vuln_type[vt]['slither_detected'] += 1
    if result.slither_correct:
        stats.by_vuln_type[vt]['slither_correct'] += 1
    if result.compilation_error:
        stats.by_vuln_type[vt]['errors'].append({
            'file': result.filename,
            'error': result.compilation_error[:200]
        })


def print_summary(stats: TestStatistics):
    """Print summary statistics."""
    print("\n" + "=" * 80)
    print("SMARTBUGS-CURATED TESTING SUMMARY")
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
        print("-" * 80)
        print(f"{'Type':<30s} {'Total':>6s} {'Compiled':>9s} {'Detected':>9s} {'Correct':>8s}")
        print("-" * 80)
        for vt in sorted(stats.by_vuln_type.keys()):
            vs = stats.by_vuln_type[vt]
            comp_str = f"{vs['compiled']}/{vs['total']}"
            det_str = f"{vs['slither_detected']}/{vs['slither_tested']}" if vs['slither_tested'] > 0 else "N/A"
            cor_str = f"{vs['slither_correct']}/{vs['slither_tested']}" if vs['slither_tested'] > 0 else "N/A"
            print(f"  {vt:<28s} {vs['total']:>6d} {comp_str:>9s} {det_str:>9s} {cor_str:>8s}")
        print("-" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Test SmartBugs-Curated converted dataset for compilation and detection'
    )
    parser.add_argument(
        '--input-dir', 
        default='data/smartbugs-curated-converted',
        help='Directory containing converted contracts (default: data/smartbugs-curated-converted)'
    )
    parser.add_argument(
        '--output', 
        default='data/smartbugs_curated_test_statistics.json',
        help='Output JSON file for statistics'
    )
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true', 
        help='Verbose output'
    )
    parser.add_argument(
        '--limit', 
        type=int, 
        default=0,
        help='Limit number of contracts to test (0 = no limit)'
    )
    parser.add_argument(
        '--vuln-type',
        type=str,
        default=None,
        help='Test only contracts of specific vulnerability type'
    )
    args = parser.parse_args()
    
    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}")
        sys.exit(1)
    
    # Find all .sol files
    contracts = list(input_dir.glob("*.sol"))
    
    # Filter by vulnerability type if specified
    if args.vuln_type:
        contracts = [c for c in contracts if args.vuln_type in c.name]
        print(f"Filtering for vulnerability type: {args.vuln_type}")
    
    if not contracts:
        print(f"Error: No .sol files found in {input_dir}")
        sys.exit(1)
    
    # Apply limit
    if args.limit > 0:
        contracts = contracts[:args.limit]
    
    print(f"Found {len(contracts)} contracts to test")
    print(f"Output will be saved to: {args.output}")
    print()
    
    # Initialize statistics
    stats = TestStatistics(
        start_time=datetime.now().isoformat(),
        total_files=len(contracts)
    )
    
    # Test each contract
    for contract_path in tqdm(contracts, desc="Testing"):
        if args.verbose:
            print(f"\nTesting: {contract_path.name}")
        
        result = test_contract(contract_path, verbose=args.verbose)
        update_stats(stats, result)
        stats.results.append(result)
        
        if args.verbose:
            status = "✓" if result.slither_correct else ("○" if result.compiled else "✗")
            print(f"  {status} Compiled: {result.compiled}, Detected: {result.slither_detected}")
            if result.slither_detectors:
                print(f"    Detectors: {', '.join(result.slither_detectors[:5])}")
    
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
