#!/bin/bash

set -e  # Exit on error

# Configuration
INPUT_DIR="data/smartbugs-wild-clean-contracts"
OUTPUT_DIR="data/injected_sc"
STATS_FILE="data/injected_sc_statistics.json"

# Parse arguments
MAX_CONTRACTS="${1:-all}"
VERBOSE_FLAG=""
if [[ "$2" == "--verbose" ]] || [[ "$2" == "-v" ]]; then
    VERBOSE_FLAG="--verbose"
fi

echo "================================================================================"
echo "VULNERABILITY DATASET GENERATION AND TESTING"
echo "================================================================================"
echo "Input directory:     $INPUT_DIR"
echo "Output directory:    $OUTPUT_DIR"
echo "Statistics file:     $STATS_FILE"
echo "Max contracts:       $MAX_CONTRACTS"
echo "================================================================================"
echo ""

# Step 1: Inject vulnerabilities
echo "[1/2] Injecting vulnerabilities into clean contracts..."
echo "--------------------------------------------------------------------------------"

python batch_inject.py \
    --input-dir "$INPUT_DIR" \
    --output-dir "$OUTPUT_DIR" \
    --mode point \
    --max-contracts "$MAX_CONTRACTS" \
    --max-point all \
    --skip-errors \
    $VERBOSE_FLAG

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Injection failed!"
    exit 1
fi

echo ""

# Step 2: Test all injected contracts
echo "[2/2] Testing injected contracts (compilation + Slither)..."
echo "--------------------------------------------------------------------------------"

python test_injected_dataset.py \
    --input-dir "$OUTPUT_DIR" \
    --output "$STATS_FILE"

if [ $? -eq 0 ]; then
    echo ""
    echo "================================================================================"
    echo "DATASET GENERATION COMPLETED"
    echo "================================================================================"
    echo "Output directory:    $OUTPUT_DIR"
    echo "Statistics file:     $STATS_FILE"
    echo "================================================================================"
else
    echo ""
    echo "ERROR: Testing failed!"
    exit 1
fi
