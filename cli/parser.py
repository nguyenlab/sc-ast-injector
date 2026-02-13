import argparse
from vuln_injector import POINT_VULN_TYPES


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Smart Contract Vulnerability Injector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_get_help_epilog()
    )
    
    _add_mode_arguments(parser)
    _add_contract_arguments(parser)
    _add_injection_arguments(parser)
    _add_output_arguments(parser)
    _add_utility_arguments(parser)
    
    return parser


def _get_help_epilog() -> str:
    """Get the help epilog with usage examples."""
    return """
Examples:
  Point injection (auto-select vulnerability type):
    python main.py --mode point --contract contract.sol

  Point injection with specific vulnerability type:
    python main.py --mode point --contract contract.sol --vuln-type overflow
    python main.py --mode point --contract contract.sol --vuln-type tx_origin
    python main.py --mode point --contract contract.sol --vuln-type reentrancy

  Cross-function injection (TOD):
    python main.py --mode coupled --contract contract.sol --template tod_transfer

  Deterministic mode (for reproducibility):
    python main.py --mode point --contract contract.sol --no-randomize

Supported vulnerability types for point injection:
  - reentrancy: External call before state update
  - overflow: Integer overflow (pre-Solidity 0.8)
  - underflow: Integer underflow (pre-Solidity 0.8)
  - tx_origin: Authentication using tx.origin
  - unchecked_send: Ignoring return value of send()
  - unhandled_exception: Ignoring return value of call()
  - timestamp: Using block.timestamp for critical logic
"""


def _add_mode_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mode",
        choices=["point", "coupled"],
        default="point",
        help="Injection mode: 'point' for single-function, 'coupled' for cross-function"
    )


def _add_contract_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--contract",
        type=str,
        required=False,
        help="Path to the Solidity contract file"
    )


def _add_injection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--vuln-type",
        type=str,
        choices=POINT_VULN_TYPES,
        default=None,
        help="Vulnerability type for point injection (default: random selection)"
    )
    
    parser.add_argument(
        "--template",
        type=str,
        default=None,
        help="Specific template name to use"
    )
    
    parser.add_argument(
        "--no-randomize",
        action="store_true",
        help="Disable randomization (use first valid option)"
    )
    
    parser.add_argument(
        "--no-comments",
        action="store_true",
        help="Don't add comments to injected code [deprecated]"
    )


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output",
        type=str,
        default="test_vulnerable.sol",
        help="Output file path (default: test_vulnerable.sol)"
    )
    
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="Don't save metadata JSON file with bug locations"
    )


def _add_utility_arguments(parser: argparse.ArgumentParser) -> None:
    """Add utility arguments."""
    parser.add_argument(
        "--list-locations",
        action="store_true",
        help="Only list potential injection locations, don't inject"
    )
    
    parser.add_argument(
        "--list-vuln-types",
        action="store_true",
        help="List available vulnerability types and exit"
    )
