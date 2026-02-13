#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
from typing import List, Tuple

from services import ContractLoader, ContractLoadError
from vuln_injector import CoupledInjector
from vuln_injector.payload_generators import CrossFunctionPayloadGenerator


def check_contract(contract_path: Path, loader: ContractLoader) -> Tuple[bool, int, int, str]:
    try:
        contract = loader.load(contract_path)
        
        injector = CoupledInjector(
            str(contract_path), 
            contract.ast, 
            contract.solidity_version, 
            randomize=False
        )
        all_sets = injector.find_locations()
        
        if not all_sets:
            return False, 0, 0, contract.solidity_version
        
        # Check template compatibility
        generator = CrossFunctionPayloadGenerator(contract.solidity_version, randomize=False)
        compatible_templates = generator.get_compatible_templates()
        
        if not compatible_templates:
            return False, len(all_sets), 0, contract.solidity_version
        
        # Filter by template requirements
        valid_sets = injector._filter_by_template(all_sets, compatible_templates)
        
        return len(valid_sets) > 0, len(all_sets), len(valid_sets), contract.solidity_version
        
    except ContractLoadError as e:
        return False, 0, 0, f"error: {str(e)[:50]}"
    except Exception as e:
        return False, 0, 0, f"error: {str(e)[:50]}"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find contracts suitable for coupled injection"
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        default="data/smartbugs-wild-clean-contracts",
        help="Directory containing contracts to check"
    )
    parser.add_argument(
        "--max",
        type=int,
        default=None,
        help="Maximum number of contracts to check"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="coupled_injection_candidates.txt",
        help="Output file for results"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    
    contracts_dir = Path(args.input_dir)
    
    if not contracts_dir.exists():
        print(f"Directory not found: {contracts_dir}")
        return 1
    
    contracts = sorted(contracts_dir.glob("*.sol"))
    
    if args.max:
        contracts = contracts[:args.max]
    
    total = len(contracts)
    
    print(f"Checking {total} contracts for coupled injection conditions...\n")
    print("=" * 80)
    
    loader = ContractLoader()
    valid_contracts = []
    
    for i, contract_path in enumerate(contracts):
        has_valid, num_pairs, num_valid, version = check_contract(contract_path, loader)
        
        if has_valid:
            valid_contracts.append({
                "path": contract_path,
                "pairs": num_pairs,
                "valid_pairs": num_valid,
                "version": version,
            })
            print(f"[✓] {contract_path.name} - {num_valid} valid pairs (v{version})")
        
        # Progress indicator
        if (i + 1) % 100 == 0:
            print(f"... processed {i + 1}/{total} contracts, found {len(valid_contracts)} valid so far")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print(f"Total contracts checked: {total}")
    print(f"Contracts with valid coupled injection locations: {len(valid_contracts)}")
    print(f"Success rate: {100 * len(valid_contracts) / total:.1f}%" if total > 0 else "N/A")
    
    if valid_contracts:
        print(f"\n--- Top 20 Contracts by Valid Pairs ---")
        sorted_contracts = sorted(valid_contracts, key=lambda x: x["valid_pairs"], reverse=True)
        
        for i, c in enumerate(sorted_contracts[:20], 1):
            print(f"{i:2}. {c['path'].name} - {c['valid_pairs']} valid pairs (v{c['version']})")
        
        # Save full list
        output_file = Path(args.output)
        with open(output_file, "w") as f:
            f.write(f"Contracts suitable for coupled injection\n")
            f.write(f"Total: {len(valid_contracts)}\n\n")
            for c in sorted_contracts:
                f.write(f"{c['path']},{c['valid_pairs']},{c['version']}\n")
        print(f"\nFull list saved to: {output_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
