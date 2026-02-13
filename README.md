# SC-AST-Injector

A smart contract vulnerability injection tool that injects realistic, stealthy vulnerabilities into Solidity contracts for testing and benchmarking security analysis tools.

## Overview

SC-AST-Injector uses AST-based analysis to identify safe injection points in Solidity smart contracts and inserts vulnerabilities that mimic real-world coding patterns. The tool is designed to create realistic vulnerable contracts with ground truth for evaluating vulnerability detection systems.

## Features

- **Multiple Vulnerability Types**
  - **Reentrancy**: 5 templates (call/send/transfer patterns)
  - **Integer Overflow**: 5 templates (addition, multiplication, uint8, etc.)
  - **Integer Underflow**: 2 templates (subtraction, transfer)
  - **tx.origin Authentication**: 3 templates (auth, transfer, with param)
  - **Unchecked Send**: 2 templates (literal, balance)
  - **Unhandled Exception**: 1 template (unchecked call)
  - **Timestamp Dependence**: 2 templates (comparison, equality)
  - **Total**: 31 point injection templates

- **Stealthy Design**
  - Realistic variable names that blend with legitimate code
  - No vulnerability markers in generated code
  - Natural code patterns mimicking common contract idioms

- **Version Compatibility**
  - Supports Solidity 0.4.0 through 0.8.x
  - Automatically adapts injection patterns to target version
  - Template-level version constraints (e.g., overflow: 0.4.0-0.7.99)

- **Comprehensive Testing**
  - Batch testing with all compatible templates
  - Slither static analysis for verification
  - Compilation testing with solcx
  - 100% detection rate on successfully compiled injections

- **Flexible Configuration**
  - 31 vulnerability templates across 7 types
  - Template selection or auto-detection
  - Deterministic mode for reproducibility

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd sc-ast-injector

# Install dependencies
pip install -r requirements.txt
```

### Requirements
- Python 3.7+
- solc (Solidity compiler) - for AST extraction
- py-solc-x - for compilation testing
- solc-select - for Slither version management
- slither-analyzer - for vulnerability detection verification (optional)

## Usage

### Point Injection

Inject a vulnerability into a single function:

```bash
# Inject any compatible vulnerability
python main.py --mode point --contract path/to/contract.sol

# Specify vulnerability type
python main.py --mode point --contract contract.sol --vuln-type reentrancy
python main.py --mode point --contract contract.sol --vuln-type overflow
python main.py --mode point --contract contract.sol --vuln-type tx_origin
```

With options:

```bash
# Specify output file
python main.py --mode point --contract contract.sol --output vulnerable.sol

# Use specific template
python main.py --mode point --contract contract.sol --vuln-type reentrancy --template reentrancy_call_check

# Deterministic mode (no randomization)
python main.py --mode point --contract contract.sol --no-randomize
```

Supported vulnerability types: `reentrancy`, `overflow`, `underflow`, `tx_origin`, `unchecked_send`, `unhandled_exception`, `timestamp`

### Coupled Injection (Cross-Function)

Inject cross-function vulnerabilities (TOD, DoS):

```bash
python main.py --mode coupled --contract path/to/contract.sol
```

With options:

```bash
# Specify template
python main.py --mode coupled --contract contract.sol --template tod_transfer

# Without comments
python main.py --mode coupled --contract contract.sol --no-comments
```

### List Injection Locations

Preview potential injection locations without modifying the contract:

```bash
# Point injection locations
python main.py --mode point --contract contract.sol --list-locations

# Coupled injection locations
python main.py --mode coupled --contract contract.sol --list-locations
```

### Batch Injection (Dataset Generation)

Inject vulnerabilities into multiple contracts at all suitable positions:

```bash
# Process 10 contracts with up to 3 point and 2 coupled injections each
python batch_inject.py --max-contracts 10 --max-point 3 --max-coupled 2 --skip-errors

# Process all contracts in a directory
python batch_inject.py --input-dir data/smartbugs-wild-clean-contracts --output-dir data/injected_sc

# Only point injections
python batch_inject.py --mode point --max-contracts 50

# Only coupled injections
python batch_inject.py --mode coupled --max-contracts 50
```

The batch script will:
- Create a structured output directory with `point/` and `coupled/` subdirectories
- Generate unique filenames: `{contract}_{mode}_{index}_{template}.sol`
- Save metadata JSON files alongside each vulnerable contract
- Provide detailed progress reporting and error handling

### Testing and Verification

**Comprehensive batch testing** on real contracts with all templates:

```bash
# Test 100 contracts with all compatible templates
python batch_test_all_templates.py --count 100 --output-dir results

# Verbose output
python batch_test_all_templates.py --count 10 --output-dir results --verbose
```

This script:
- Finds ALL compatible templates for each contract's Solidity version
- Injects each template at all suitable locations
- Compiles injected contracts with solcx
- Verifies detection with Slither static analysis
- Reports success rates by vulnerability type and template

**Test on specific contracts:**

```bash
# Test injection on 10 random real contracts
python test_real_contracts.py --count 10

# Test with Slither only
python test_real_contracts.py --count 10 --tool slither

# Test specific vulnerability type
python test_real_contracts.py --count 10 --vuln-type reentrancy
```

**View injected code:**

```bash
# View vulnerability regions with context
python view_injected.py /path/to/metadata.json

# Show only injected code
python view_injected.py /path/to/metadata.json --only
```

## Project Structure

```
sc-ast-injector/
├── main.py                      # CLI entry point for single injections
├── batch_inject.py              # Batch injection script (dataset generation)
├── batch_test_all_templates.py  # Comprehensive batch testing with Slither
├── test_real_contracts.py       # Test injection on real contracts
├── test_templates_tools.py      # Test minimal contract templates
├── test_all_injected.py         # Compilation testing for datasets
├── test_compilation.py          # Sample compilation testing
├── view_injected.py             # View injected vulnerability regions
├── check_coupled_candidates.py  # Find coupled injection candidates
│
├── cli/                         # CLI module
│   ├── __init__.py
│   ├── commands.py              # InjectorCLI class
│   └── parser.py                # Argument parser configuration
│
├── services/                    # Logic services
│   ├── __init__.py
│   ├── contract_loader.py       # ContractLoader service
│   ├── version_detector.py      # Solidity version detection
│   └── tool_detector.py         # Security tool detection mappings
│
├── testing/                     # Testing utilities
│   ├── __init__.py
│   ├── compiler.py              # SolidityCompiler wrapper
│   ├── validator.py             # ContractValidator service
│   └── viewer.py                # InjectedContractViewer
│
├── vuln_injector/               # Core injection module
│   ├── __init__.py
│   ├── injectors.py             # PointInjector & CoupledInjector
│   ├── models.py                # Data structures
│   ├── ast_helpers.py           # AST traversal utilities
│   ├── payload_generators.py    # Vulnerability payload generation
│   ├── utils.py                 # Utility functions
│   └── templates/               # Vulnerability templates
│       ├── reentrancy.py        # Reentrancy patterns
│       ├── coupled_injection.py # Coupled injection templates (18 templates)
│       ├── benign.py            # Benign code generation
│       └── point_injection.py   # Point injection templates (28 templates)
│
├── src/                         # Graph-based analysis utilities
│   └── utils.py                 # AST extraction utilities
│
├── archive/                     # Archived/deprecated scripts
│   ├── tool_verify.py           # Old multi-tool verification
│   ├── verify_vulnerabilities.py # Old Mythril verification
│   └── batch_verify.py          # Old batch verification
│
└── data/                        # Test data
    ├── smartbugs-wild-clean-contracts/  # Source contracts
    └── injected_sc/             # Output directory
        ├── point/               # Point injections
        └── coupled/             # Coupled injections
```

## Vulnerability Templates

### Point Injection Templates (31 total)

**Reentrancy (5 templates)**
- `reentrancy_call_check` - Call with balance check (all versions)
- `reentrancy_send_check` - Send with balance check
- `reentrancy_require_send` - Require with send
- `reentrancy_bool_guard` - Boolean guard pattern
- `reentrancy_jackpot` - Jackpot withdrawal pattern

**Integer Overflow (5 templates)**
- `addition_overflow` - Simple addition overflow
- `addition_overflow_input` - Addition with user input
- `multiplication_overflow` - Multiplication overflow
- `uint8_overflow` - uint8 overflow
- `lock_time_overflow` - Locktime/timestamp overflow

**Integer Underflow (2 templates)**
- `subtraction_underflow` - Subtraction underflow
- `transfer_underflow` - Transfer amount underflow

**tx.origin Authentication (3 templates)**
- `tx_origin_auth` - tx.origin authentication
- `tx_origin_transfer` - tx.origin with transfer (version-specific)
- `tx_origin_with_param` - tx.origin with parameter

**Unchecked Send (2 templates)**
- `unchecked_send_literal_legacy` - Unchecked send with literal
- `unchecked_send_balance_legacy` - Unchecked send with balance

**Unhandled Exception (1 template)**
- `unchecked_call_04x` - Unchecked low-level call (version-specific)

**Timestamp Dependence (2 templates)**
- `timestamp_comparison` - block.timestamp comparison
- `timestamp_equality` - block.timestamp equality (version-specific)

### Coupled Injection (Cross-Function)

- `tod_transfer` - Time-of-Check Time-of-Use with transfer
- `tod_selfdestruct` - TOD with selfdestruct
- `array_dos` - Array-based DoS attack
- `mapping_dos` - Mapping-based DoS attack

## Examples

### Example 1: Basic Point Injection

```bash
python main.py --mode point \
  --contract data/smartbugs-wild-clean-contracts/0x000adad69101420129a64715a1a52b7348c5e633.sol \
  --output vulnerable_reentrancy.sol
```

Output:
```
Detected Solidity version: 0.4.24

============================================================
POINT INJECTION MODE (Single-Function Vulnerability)
============================================================

### Injection Locations Found ###
Found 3 potential injection locations:

1. Function: withdraw (ID: 45)
   State variable: balance
   Assignment: balance[msg.sender] = 0

### Applying Point Injection ###

[+] Injected vulnerable code at offset 1234
[+] Injected benign code at offset 1235
Successfully created vulnerable contract: vulnerable_reentrancy.sol
```

### Example 2: Coupled Injection with Template

```bash
python main.py --mode coupled \
  --contract contract.sol \
  --template tod_transfer \
  --no-comments
```

### Example 3: Deterministic Injection

```bash
python main.py --mode point \
  --contract contract.sol \
  --no-randomize \
  --complexity 0
```

## How It Works

1. **AST Extraction**: Parses the Solidity contract to build an Abstract Syntax Tree
2. **Location Detection**: Identifies suitable injection points based on:
   - State variable assignments
   - Function visibility and mutability
   - Parameter requirements
3. **Template Selection**: Chooses compatible vulnerability templates based on Solidity version
4. **Payload Generation**: Creates stealthy code with realistic variable names
5. **Injection**: Inserts vulnerability code at calculated offsets
6. **Output**: Writes modified contract to output file

## Detection Results

Based on full dataset testing (January 2026):

- **Total injected contracts**: 122,616
- **Compilation success**: 117,770 (96.0%)
- **Slither detection**: 117,526 (99.8%)
- **Slither correctness**: 117,520 (99.8%)

### By Vulnerability Type

| Type | Injected | Compiled | Compile Rate | Detection Rate |
|------|----------|----------|--------------|----------------|
| tx_origin | 23,152 | 22,156 | 95.7% | 99.7% |
| timestamp | 19,586 | 18,772 | 95.8% | 99.7% |
| overflow | 19,586 | 18,765 | 95.8% | 100.0% |
| unchecked_send | 19,586 | 18,789 | 95.9% | 99.7% |
| reentrancy | 14,957 | 14,620 | 97.7% | 99.7% |
| unhandled_exception | 13,613 | 13,023 | 95.7% | 99.7% |
| underflow | 12,136 | 11,645 | 96.0% | 100.0% |

**Note**: Detection rate is calculated as correctly detected vulnerabilities divided by successfully compiled contracts.

## Use Cases

- **Benchmarking**: Test vulnerability detection tools with known vulnerable contracts
- **Research**: Study how well security tools detect realistic vulnerabilities
- **Training**: Create datasets for machine learning-based vulnerability detection
- **Testing**: Validate static analysis tools and symbolic execution engines

## Dataset

The repository includes a dataset of real-world contracts from SmartBugs Wild in `data/smartbugs-wild-clean-contracts/` for testing and experimentation.
=======
# sc-ast-injector
>>>>>>> c6cd8a5e1af60b13ed1eac26444dbbf152edf2d7
