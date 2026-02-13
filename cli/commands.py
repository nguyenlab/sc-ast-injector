import sys
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

from src.utils import getSolidityVersion, ASTExtractor
from vuln_injector import PointInjector, CoupledInjector, POINT_VULN_TYPES


@dataclass
class ContractData:
    """Container for loaded contract data."""
    path: str
    content: bytes
    ast: Dict[str, Any]
    solidity_version: str


class InjectorCLI:
    VULN_DESCRIPTIONS = {
        "reentrancy": "External call before state update",
        "overflow": "Integer overflow (pre-Solidity 0.8)",
        "underflow": "Integer underflow (pre-Solidity 0.8)",
        "tx_origin": "Authentication using tx.origin",
        "unchecked_send": "Ignoring return value of send()",
        "unhandled_exception": "Ignoring return value of call()",
        "timestamp": "Using block.timestamp for critical logic",
    }
    
    def __init__(self, args):
        self.args = args
        self.contract_data: Optional[ContractData] = None
    
    def run(self) -> int:
        # Handle utility commands
        if self.args.list_vuln_types:
            self._print_vuln_types()
            return 0
        
        # Validate required arguments
        if not self.args.contract:
            print("Error: --contract is required unless using --list-vuln-types")
            return 1
        
        # Load contract
        try:
            self.contract_data = self._load_contract(self.args.contract)
        except FileNotFoundError:
            print(f"Error: Contract file not found: {self.args.contract}")
            return 1
        except Exception as e:
            print(f"Error loading contract: {e}")
            return 1
        
        # Execute appropriate mode
        if self.args.mode == "point":
            return self._run_point_mode()
        elif self.args.mode == "coupled":
            return self._run_coupled_mode()
        
        return 1
    
    def _load_contract(self, contract_path: str) -> ContractData:
        with open(contract_path, 'rb') as f:
            contract_bytes = f.read()
        
        contract_code = contract_bytes.decode("utf-8", errors="ignore")
        sol_version = getSolidityVersion(contract_code)
        
        if not sol_version:
            print("Warning: Could not detect Solidity version, using 0.4.18 as default")
            sol_version = "0.4.18"
        
        print(f"Detected Solidity version: {sol_version}\n")
        
        ast = ASTExtractor(contract_bytes)
        
        return ContractData(
            path=contract_path,
            content=contract_bytes,
            ast=ast,
            solidity_version=sol_version
        )
    
    def _print_vuln_types(self) -> None:
        """Print available vulnerability types."""
        print("Available vulnerability types for point injection:")
        print("-" * 50)
        for vt in POINT_VULN_TYPES:
            desc = self.VULN_DESCRIPTIONS.get(vt, "")
            print(f"  {vt:20s} - {desc}")
    
    def _run_point_mode(self) -> int:
        self._print_header("POINT INJECTION MODE (Single-Function Vulnerability)")
        
        if self.args.vuln_type:
            print(f"Vulnerability type: {self.args.vuln_type}\n")
        else:
            print("Vulnerability type: auto-select\n")
        
        injector = PointInjector(
            self.args.contract,
            self.contract_data.ast,
            self.contract_data.solidity_version,
            randomize=not self.args.no_randomize,
            vuln_type=self.args.vuln_type,
        )
        
        locations = injector.find_locations(self.args.vuln_type)
        
        self._display_point_locations(locations)
        
        if self.args.list_locations:
            return 0
        
        if not locations:
            print("No suitable locations found. Exiting.")
            return 1
        
        print("### Applying Point Injection ###\n")
        
        success = injector.inject(
            locations=locations,
            vuln_type=self.args.vuln_type,
            template_name=self.args.template,
            output_path=self.args.output,
            save_metadata=not self.args.no_metadata,
        )
        
        return 0 if success else 1
    
    def _run_coupled_mode(self) -> int:
        self._print_header("COUPLED INJECTION MODE (Cross-Function Vulnerability)")
        
        injector = CoupledInjector(
            self.args.contract,
            self.contract_data.ast,
            self.contract_data.solidity_version,
            randomize=not self.args.no_randomize,
        )
        
        locations = injector.find_locations()
        
        self._display_coupled_locations(locations)
        
        if self.args.list_locations:
            return 0
        
        if not locations:
            print("No suitable locations found. Exiting.")
            return 1
        
        print("### Applying Coupled Injection ###\n")
        
        success = injector.inject(
            template_name=self.args.template,
            output_path=self.args.output,
            save_metadata=not self.args.no_metadata,
        )
        
        return 0 if success else 1
    
    def _display_point_locations(self, locations: List[Dict]) -> None:
        print(f"### Injection Locations Found ###")
        print(f"Found {len(locations)} potential injection locations:\n")
        
        for i, loc in enumerate(locations[:10], 1):
            print(f"{i}. Contract: {loc['contract'].name}")
            print(f"   Function: {loc['function'].name}")
            print(f"   Has address param: {loc.get('has_address_param', False)}")
            print(f"   Is payable: {loc.get('is_payable', False)}")
            print(f"   State modifying: {loc.get('is_state_modifying', False)}")
            if loc.get('state_variable'):
                print(f"   State variable: {loc['state_variable']}")
            print()
        
        if len(locations) > 10:
            print(f"   ... and {len(locations) - 10} more locations\n")
    
    def _display_coupled_locations(self, locations: List) -> None:
        print(f"### Cross-Function Injection Locations Found ###")
        print(f"Found {len(locations)} potential setter-executor pairs:\n")
        
        for i, loc_set in enumerate(locations[:5], 1):
            print(f"{i}. Contract: {loc_set.contract.name}")
            print(f"   Setter: {loc_set.setter.name} (params: {[p['name'] for p in loc_set.setter.params]})")
            print(f"   Executor: {loc_set.executor.name} (payable: {loc_set.executor.is_payable})")
            print()
        
        if len(locations) > 5:
            print(f"   ... and {len(locations) - 5} more pairs\n")
    
    @staticmethod
    def _print_header(title: str) -> None:
        print("=" * 60)
        print(title)
        print("=" * 60 + "\n")
