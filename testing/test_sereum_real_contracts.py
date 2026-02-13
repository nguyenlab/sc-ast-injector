#!/usr/bin/env python3
"""
Test Sereum reentrancy templates on 10 real contracts from smartbugs-wild.
Templates: delegate_reentrancy, cross_function_reentrancy, create_reentrancy.
"""

import os
import random
import re
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

PROJECT_ROOT = str(Path(__file__).parent.parent)
sys.path.insert(0, PROJECT_ROOT)

from services.tool_detector import (
    compile_contract,
    run_slither,
    is_detection_correct,
    filter_relevant_detectors,
)

DATA_DIR = os.path.join(PROJECT_ROOT, "data", "smartbugs-wild-clean-contracts")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "testing", "sereum_test_output")

SEED = 42
NUM_CONTRACTS = 10

# Templates to test: (name_selector, injection_mode, description)
# name_selector can be a string or a function(sol_version) -> template_name
def _cross_function_template(ver: str) -> str:
    """Select cross-function reentrancy template based on Solidity version."""
    parts = ver.split(".")
    minor = int(parts[1]) if len(parts) > 1 else 4
    if minor <= 4:
        return "cross_function_reentrancy_04x"
    elif minor <= 6:
        return "cross_function_reentrancy_legacy"
    else:
        return "cross_function_reentrancy"


TEMPLATES = [
    ("delegate_reentrancy",        "point",   "Delegated Re-entrancy"),
    (_cross_function_template,     "coupled", "Cross-Function Re-entrancy"),
    ("create_reentrancy",          "point",   "Create-Based Re-entrancy"),
]


@dataclass
class Result:
    contract: str
    template: str
    mode: str
    sol_version: str = ""
    injected: bool = False
    compiled: bool = False
    detected: bool = False
    detectors: List[str] = field(default_factory=list)
    error: str = ""


def detect_solidity_version(filepath: str) -> Optional[str]:
    """Extract solidity version from pragma in the contract."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read(5000)  # first 5KB is enough
        
        # Match 'pragma solidity ...' and extract version
        m = re.search(r'pragma\s+solidity\s+[\^~>=<]*\s*(\d+\.\d+\.\d+)', content)
        if m:
            return m.group(1)
        
        # Try without patch version
        m = re.search(r'pragma\s+solidity\s+[\^~>=<]*\s*(\d+\.\d+)', content)
        if m:
            ver = m.group(1)
            return ver + ".0"
    except:
        pass
    return None


def sample_contracts(n: int, seed: int) -> List[str]:
    """Randomly sample n .sol files from the data directory."""
    all_files = sorted([
        os.path.join(DATA_DIR, f) for f in os.listdir(DATA_DIR)
        if f.endswith(".sol") and os.path.getsize(os.path.join(DATA_DIR, f)) > 2000
    ])
    rng = random.Random(seed)
    return rng.sample(all_files, min(n, len(all_files)))


def inject(contract: str, template: str, mode: str, output: str) -> Tuple[bool, str]:
    """Run main.py to inject a template into a contract."""
    cmd = [
        "python", "main.py",
        "--mode", mode,
        "--contract", contract,
        "--vuln-type", "reentrancy",
        "--template", template,
        "--output", output,
        "--no-randomize"
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
            cwd=PROJECT_ROOT,
        )
        if os.path.exists(output):
            return True, ""
        err = proc.stderr or proc.stdout or "No output file"
        for line in err.splitlines():
            if "error" in line.lower() or "no suitable" in line.lower() or "no compatible" in line.lower():
                return False, line.strip()[:120]
        return False, err.strip()[:120]
    except subprocess.TimeoutExpired:
        return False, "Injection timeout"
    except Exception as e:
        return False, str(e)[:120]


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    contracts = sample_contracts(NUM_CONTRACTS, SEED)
    print(f"Sampled {len(contracts)} contracts from {DATA_DIR}")
    for i, c in enumerate(contracts):
        ver = detect_solidity_version(c)
        print(f"  [{i+1}] {os.path.basename(c)}  (Solidity {ver or 'unknown'})")
    print()

    results: List[Result] = []

    for ci, contract in enumerate(contracts):
        basename = os.path.splitext(os.path.basename(contract))[0]
        sol_version = detect_solidity_version(contract) or "0.4.26"

        for tname_or_fn, tmode, tdesc in TEMPLATES:
            # Resolve template name (may be version-dependent)
            tname = tname_or_fn(sol_version) if callable(tname_or_fn) else tname_or_fn
            out_file = os.path.join(OUTPUT_DIR, f"{basename}_{tdesc.replace(' ', '_').lower()}.sol")
            r = Result(contract=os.path.basename(contract), template=tname, mode=tmode, sol_version=sol_version)

            # -- Inject --
            ok, err = inject(contract, tname, tmode, out_file)
            r.injected = ok
            if not ok:
                r.error = err
                results.append(r)
                continue

            # -- Compile (use the contract's native Solidity version) --
            comp = compile_contract(out_file, sol_version)
            r.compiled = comp.success
            if not comp.success:
                r.error = (comp.error or "")[:120]
                results.append(r)
                continue

            # -- Slither --
            sl = run_slither(out_file, sol_version, timeout=120)
            if sl.success:
                relevant = filter_relevant_detectors(sl.detectors_found)
                r.detected = is_detection_correct("reentrancy", sl.detectors_found, "slither")
                r.detectors = relevant
            else:
                r.error = (sl.error or "")[:120]

            results.append(r)

    # -- Summary --
    print("\n" + "=" * 100)
    print(f"{'Contract':<45} {'Template':<30} {'Ver':<8} {'Inj':>3} {'Cmp':>3} {'Det':>3}")
    print("-" * 100)

    for r in results:
        inj = "✅" if r.injected else "❌"
        cmp = "✅" if r.compiled else ("—" if not r.injected else "❌")
        det = "✅" if r.detected else ("—" if not r.compiled else "❌")
        print(f"{r.contract[:44]:<45} {r.template:<30} {r.sol_version:<8} {inj:>3} {cmp:>3} {det:>3}")
        if r.error:
            print(f"  ↳ {r.error}")
        if r.detectors:
            print(f"  ↳ Detectors: {r.detectors}")

    # -- Aggregate by template --
    print("\n" + "=" * 100)
    print("Summary by template:")
    for _, _, tdesc in TEMPLATES:
        subset = [r for r in results if tdesc.replace(' ', '_').lower() in r.template.lower() 
                  or tdesc == "Delegated Re-entrancy" and r.template == "delegate_reentrancy"
                  or tdesc == "Create-Based Re-entrancy" and r.template == "create_reentrancy"
                  or tdesc == "Cross-Function Re-entrancy" and "cross_function" in r.template]
        n_inj = sum(1 for r in subset if r.injected)
        n_cmp = sum(1 for r in subset if r.compiled)
        n_det = sum(1 for r in subset if r.detected)
        print(f"  {tdesc:<30} Inject: {n_inj}/{len(subset)}  Compile: {n_cmp}/{len(subset)}  Detect: {n_det}/{len(subset)}")

    total_inj = sum(1 for r in results if r.injected)
    total_cmp = sum(1 for r in results if r.compiled)
    total_det = sum(1 for r in results if r.detected)
    print(f"\n  TOTAL                         Inject: {total_inj}/{len(results)}  Compile: {total_cmp}/{len(results)}  Detect: {total_det}/{len(results)}")
    print("=" * 100)

    return 0 if total_cmp > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
