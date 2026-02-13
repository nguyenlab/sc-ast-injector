#!/usr/bin/env python3
"""
Batch inject delegate_reentrancy and create_reentrancy templates
into ALL clean contracts from data/smartbugs-wild-clean-contracts.

Output: data/injected_sc_sereum/<contract_hash>_<template_name>.sol
"""

import os
import sys
import json
import time
import traceback
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

PROJECT_ROOT = str(Path(__file__).parent.parent)
sys.path.insert(0, PROJECT_ROOT)

INPUT_DIR = os.path.join(PROJECT_ROOT, "data", "smartbugs-wild-clean-contracts")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "data", "injected_sc_sereum")

TEMPLATES = ["delegate_reentrancy", "create_reentrancy"]
MAX_WORKERS = 8  # parallel processes


def inject_single(args):
    """Inject a single template into a single contract. Runs in a subprocess."""
    contract_path, template_name, output_path = args

    # Import inside subprocess to avoid pickling issues
    from cli import InjectorCLI, create_argument_parser

    try:
        parser = create_argument_parser()
        cli_args = parser.parse_args([
            "--mode", "point",
            "--contract", contract_path,
            "--vuln-type", "reentrancy",
            "--template", template_name,
            "--output", output_path,
            "--no-randomize",
        ])
        cli = InjectorCLI(cli_args)

        # Suppress stdout during batch processing
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = cli.run()
        finally:
            sys.stdout = old_stdout

        if os.path.exists(output_path):
            return (contract_path, template_name, True, "")
        else:
            return (contract_path, template_name, False, "No output file created")

    except Exception as e:
        return (contract_path, template_name, False, str(e)[:150])


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Collect all .sol files
    all_contracts = sorted([
        os.path.join(INPUT_DIR, f)
        for f in os.listdir(INPUT_DIR)
        if f.endswith(".sol")
    ])
    total_contracts = len(all_contracts)
    print(f"Found {total_contracts} contracts in {INPUT_DIR}")
    print(f"Templates: {TEMPLATES}")
    print(f"Output:    {OUTPUT_DIR}")
    print(f"Workers:   {MAX_WORKERS}")
    print()

    # Build work list: (contract_path, template_name, output_path)
    work_items = []
    for contract_path in all_contracts:
        basename = os.path.splitext(os.path.basename(contract_path))[0]
        for template in TEMPLATES:
            out = os.path.join(OUTPUT_DIR, f"{basename}_{template}.sol")
            # Skip if already exists (resume support)
            if os.path.exists(out):
                continue
            work_items.append((contract_path, template, out))

    total_work = total_contracts * len(TEMPLATES)
    already_done = total_work - len(work_items)
    print(f"Total jobs:    {total_work}")
    print(f"Already done:  {already_done}")
    print(f"Remaining:     {len(work_items)}")
    print()

    if not work_items:
        print("Nothing to do.")
        return 0

    # Counters
    success = already_done
    failed = 0
    errors_by_type = {}
    start_time = time.time()

    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(inject_single, item): item for item in work_items}

        for i, future in enumerate(as_completed(futures), 1):
            contract_path, template, ok, err = future.result()
            contract_name = os.path.basename(contract_path)

            if ok:
                success += 1
            else:
                failed += 1
                # Categorize errors
                err_key = err[:60] if err else "Unknown"
                errors_by_type[err_key] = errors_by_type.get(err_key, 0) + 1

            # Progress every 100 items
            if i % 100 == 0 or i == len(work_items):
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed > 0 else 0
                eta = (len(work_items) - i) / rate if rate > 0 else 0
                print(
                    f"  [{i}/{len(work_items)}] "
                    f"✅ {success} | ❌ {failed} | "
                    f"{rate:.1f} it/s | ETA {eta/60:.1f}min"
                )

    elapsed = time.time() - start_time

    # Final report
    print()
    print("=" * 70)
    print(f"BATCH INJECTION COMPLETE  ({elapsed/60:.1f} min)")
    print(f"  Total contracts:  {total_contracts}")
    print(f"  Templates:        {len(TEMPLATES)}")
    print(f"  Total jobs:       {total_work}")
    print(f"  Successful:       {success}  ({100*success/total_work:.1f}%)")
    print(f"  Failed:           {failed}  ({100*failed/total_work:.1f}%)")
    print()

    if errors_by_type:
        print("Top error categories:")
        for err, count in sorted(errors_by_type.items(), key=lambda x: -x[1])[:10]:
            print(f"  [{count:>5}] {err}")

    # Count output files per template
    print()
    for template in TEMPLATES:
        count = len([f for f in os.listdir(OUTPUT_DIR) if f.endswith(f"_{template}.sol")])
        print(f"  {template}: {count} files")

    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
