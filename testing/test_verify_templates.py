#!/usr/bin/env python3
"""
Verify Sereum reentrancy templates (all 4 types):
  1. Same-function   (already covered by existing templates, included for reference)
  2. Cross-function   (cross_function_reentrancy)
  3. Delegated        (delegate_reentrancy)
  4. Create-based     (create_reentrancy)

Tests: (1) compilation with solcx, (2) Slither reentrancy detection.
"""

import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = str(Path(__file__).parent.parent)
sys.path.insert(0, PROJECT_ROOT)

from services.tool_detector import (
    compile_contract,
    run_slither,
    get_expected_slither_detectors,
    is_detection_correct,
    filter_relevant_detectors,
)

SOLIDITY_VERSION = "0.8.19"
VULN_TYPE = "reentrancy"

TESTING_DIR = os.path.dirname(__file__)

TEST_CONTRACTS = [
    {
        "name": "delegate_reentrancy",
        "sereum_type": "3. Delegated Re-entrancy",
        "file": os.path.join(TESTING_DIR, "test_delegate_reentrancy.sol"),
    },
    {
        "name": "cross_function_reentrancy",
        "sereum_type": "2. Cross-Function Re-entrancy",
        "file": os.path.join(TESTING_DIR, "test_cross_function_reentrancy.sol"),
    },
    {
        "name": "create_reentrancy",
        "sereum_type": "4. Create-Based Re-entrancy",
        "file": os.path.join(TESTING_DIR, "test_create_reentrancy.sol"),
    },
]


def main():
    expected = get_expected_slither_detectors(VULN_TYPE)
    print(f"Expected Slither detectors for '{VULN_TYPE}': {expected}")
    print("=" * 70)

    all_compiled = True
    all_detected = True

    for tc in TEST_CONTRACTS:
        print(f"\n{'─' * 70}")
        print(f"Template:    {tc['name']}")
        print(f"Sereum type: {tc['sereum_type']}")
        print(f"File:        {tc['file']}")
        print(f"{'─' * 70}")

        # ── Step 1: Compile ──────────────────────────────────────────────
        comp = compile_contract(tc["file"], SOLIDITY_VERSION)
        if comp.success:
            print(f"  Compilation:  ✅ success (solc {comp.version})")
        else:
            print(f"  Compilation:  ❌ FAILED")
            print(f"    Error: {comp.error[:300]}")
            all_compiled = False
            continue  # skip Slither if it doesn't compile

        # ── Step 2: Slither ──────────────────────────────────────────────
        slither = run_slither(tc["file"], SOLIDITY_VERSION, timeout=120)
        if not slither.success:
            print(f"  Slither:      ❌ FAILED ({slither.error})")
            all_detected = False
            continue

        relevant = filter_relevant_detectors(slither.detectors_found)
        correct = is_detection_correct(VULN_TYPE, slither.detectors_found, tool="slither")

        print(f"  Slither ran:  ✅ ({slither.time_taken:.1f}s)")
        print(f"  All detectors:     {slither.detectors_found}")
        print(f"  Relevant:          {relevant}")
        print(f"  Correct detection: {'✅ YES' if correct else '❌ NO'}")

        if not correct:
            all_detected = False

    print("\n" + "=" * 70)
    print(f"Compilation: {'✅ ALL PASSED' if all_compiled else '❌ SOME FAILED'}")
    print(f"Detection:   {'✅ ALL DETECTED' if all_detected else '⚠️  SOME NOT DETECTED'}")
    print("=" * 70)

    return 0 if all_compiled else 1


if __name__ == "__main__":
    sys.exit(main())
