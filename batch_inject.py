#!/usr/bin/env python3

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from tqdm import tqdm

from src.utils import getSolidityVersion, ASTExtractor
from vuln_injector import PointInjector, CoupledInjector, POINT_VULN_TYPES


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Batch inject vulnerabilities into smart contracts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--input-dir",
        type=str,
        default="data/smartbugs-wild-clean-contracts",
        help="Input directory containing contracts"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/injected_sc",
        help="Output directory for injected contracts"
    )
    
    parser.add_argument(
        "--mode",
        choices=["point", "coupled", "both"],
        default="both",
        help="Injection mode"
    )
    
    parser.add_argument(
        "--max-contracts",
        type=str,
        default=None,
        help="Maximum number of contracts to process (or 'all' for all contracts)"
    )
    
    parser.add_argument(
        "--max-point",
        type=str,
        default="5",
        help="Maximum point injections per contract (or 'all' for unlimited)"
    )
    
    parser.add_argument(
        "--max-coupled",
        type=str,
        default="3",
        help="Maximum coupled injections per contract (or 'all' for unlimited)"
    )
    
    parser.add_argument(
        "--skip-errors",
        action="store_true",
        help="Continue processing even if individual injections fail"
    )
    
    return parser.parse_args()


def load_contract(contract_path: str) -> Tuple[bytes, Dict, str]:
    with open(contract_path, 'rb') as f:
        contract_bytes = f.read()
    
    contract_code = contract_bytes.decode("utf-8", errors="ignore")
    sol_version = getSolidityVersion(contract_code)
    
    if not sol_version:
        sol_version = "0.4.18"
    
    ast = ASTExtractor(contract_bytes)
    
    return contract_bytes, ast, sol_version


def inject_point_vulnerabilities(
    contract_path: str,
    ast: Dict,
    sol_version: str,
    output_dir: Path,
    max_injections: int = 5,
) -> int:
    
    injected_count = 0
    contract_name = Path(contract_path).stem
    
    # Try each vulnerability type
    for vuln_type in POINT_VULN_TYPES:
        if injected_count >= max_injections:
            break
            
        try:
            injector = PointInjector(
                contract_path,
                ast,
                sol_version,
                randomize=True,
                vuln_type=vuln_type,
            )
            
            locations = injector.find_locations(vuln_type)
            
            if not locations:
                continue
            
            # Inject at the first valid location
            for loc_idx, loc in enumerate(locations[:max_injections - injected_count]):
                output_filename = f"{contract_name}_point_{injected_count}_{vuln_type}.sol"
                output_path = output_dir / output_filename
                
                try:
                    success = injector.inject(
                        locations=[loc],
                        vuln_type=vuln_type,
                        output_path=str(output_path),
                        save_metadata=True,
                    )
                    
                    if success:
                        injected_count += 1
                        if injected_count >= max_injections:
                            break
                except Exception:
                    continue
                    
        except Exception:
            continue
    
    return injected_count


def inject_coupled_vulnerabilities(
    contract_path: str,
    ast: Dict,
    sol_version: str,
    output_dir: Path,
    max_injections: int = 3,
) -> int:
    
    injected_count = 0
    contract_name = Path(contract_path).stem
    
    try:
        injector = CoupledInjector(
            contract_path,
            ast,
            sol_version,
            randomize=True,
        )
        
        # Get all valid combinations of (injection_set × template)
        from vuln_injector.payload_generators import CrossFunctionPayloadGenerator
        
        locations = injector.find_locations()
        if not locations:
            return 0
        
        generator = CrossFunctionPayloadGenerator(sol_version, randomize=True)
        compatible_templates = generator.get_compatible_templates()
        
        if not compatible_templates:
            return 0
        
        # Get all valid (set × template) combinations
        valid_combinations = injector._filter_by_template(locations, compatible_templates)
        
        if not valid_combinations:
            return 0
        
        # Limit to max_injections (max_injections is int, use 999999 for 'all')
        combinations_to_inject = valid_combinations[:max_injections]
        
        for combo_idx, (inj_set, template_name, template) in enumerate(combinations_to_inject):
            output_filename = f"{contract_name}_coupled_{injected_count}.sol"
            output_path = output_dir / output_filename
            
            try:
                success = injector.inject(
                    template_name=template_name,
                    output_path=str(output_path),
                    save_metadata=True,
                )
                
                if success:
                    injected_count += 1
            except Exception:
                continue
                
    except Exception:
        pass
    
    return injected_count


def main() -> int:
    args = parse_arguments()
    
    # Validate input directory
    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}")
        return 1
    
    output_dir = Path(args.output_dir)
    point_output_dir = output_dir / "point"
    coupled_output_dir = output_dir / "coupled"
    
    # Create output directories
    point_output_dir.mkdir(parents=True, exist_ok=True)
    coupled_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find contracts
    contracts = list(input_dir.glob("*.sol"))
    if not contracts:
        print(f"No .sol files found in {input_dir}")
        return 1
    
    # Handle 'all' for max_contracts
    if args.max_contracts and args.max_contracts.lower() != 'all':
        contracts = contracts[:int(args.max_contracts)]
    
    # Convert max_point and max_coupled from string to int or None
    max_point = None if args.max_point.lower() == 'all' else int(args.max_point)
    max_coupled = None if args.max_coupled.lower() == 'all' else int(args.max_coupled)
    
    print(f"Found {len(contracts)} contracts to process")
    print(f"Output directory: {output_dir}")
    print(f"Mode: {args.mode}")
    print(f"Max point per contract: {args.max_point}")
    print(f"Max coupled per contract: {args.max_coupled}")
    print()
    
    # Statistics
    total_point = 0
    total_coupled = 0
    errors = 0
    
    # Process contracts
    for contract_path in tqdm(contracts, desc="Processing"):
        try:
            contract_bytes, ast, sol_version = load_contract(str(contract_path))
            
            if args.mode in ["point", "both"]:
                count = inject_point_vulnerabilities(
                    str(contract_path),
                    ast,
                    sol_version,
                    point_output_dir,
                    max_point if max_point is not None else 999999,
                )
                total_point += count
            
            if args.mode in ["coupled", "both"]:
                count = inject_coupled_vulnerabilities(
                    str(contract_path),
                    ast,
                    sol_version,
                    coupled_output_dir,
                    max_coupled if max_coupled is not None else 999999,
                )
                total_coupled += count
                
        except Exception as e:
            errors += 1
            if not args.skip_errors:
                print(f"\nError processing {contract_path}: {e}")
            continue
    
    # Print summary
    print(f"\n{'='*60}")
    print("BATCH INJECTION SUMMARY")
    print(f"{'='*60}")
    print(f"Contracts processed: {len(contracts)}")
    print(f"Point injections: {total_point}")
    print(f"Coupled injections: {total_coupled}")
    print(f"Total vulnerabilities: {total_point + total_coupled}")
    print(f"Errors: {errors}")
    print(f"\nOutput saved to: {output_dir}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
