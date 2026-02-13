import random
from typing import Dict, List, Optional

from .models import InjectionContext, InjectionPayload
from .utils import is_version_compatible, sample_items, select_one
from .templates import reentrancy, coupled_injection, point_injection


# Vulnerability types supported by point injection
POINT_VULN_TYPES = [
    "reentrancy",
    "overflow",
    "underflow", 
    "tx_origin",
    "unchecked_send",
    "unhandled_exception",
    "timestamp",
]


class PayloadGenerator:
    
    def __init__(self, solidity_version: str, randomize: bool = True):
        self.solidity_version = solidity_version
        self.randomize = randomize
    
    def _get_compatible_templates(self, templates: Dict, version: str) -> Dict:
        """Filter templates compatible with the Solidity version."""
        return {
            k: v for k, v in templates.items()
            if is_version_compatible(version, v["min_version"], v["max_version"])
        }


class ReentrancyPayloadGenerator(PayloadGenerator):
    
    def generate(
        self,
        context: InjectionContext,
        indentation: str = "    ",
        template_name: Optional[str] = None,
    ) -> bytes:
        
        dest = context.beneficiary
        amt = context.amount
        
        # Get compatible templates from CORE templates (not point injection templates)
        compatible = self._get_compatible_templates(
            reentrancy.REENTRANCY_CORE_TEMPLATES, 
            self.solidity_version
        )
        
        if not compatible:
            # Fallback to legacy template
            compatible = {"call_value_legacy": reentrancy.REENTRANCY_CORE_TEMPLATES["call_value_legacy"]}
        
        # Select template
        if template_name and template_name in compatible:
            template = compatible[template_name]
        else:
            template = select_one(list(compatible.values()), self.randomize)
        
        # Build payload - just the vulnerable core
        core_code = template["core"].format(dest=dest, amt=amt)
        parts = [core_code]
        
        # Join with dynamic indentation
        indent = "\n" + indentation
        payload = indent + indent.join(parts) + indent
        
        return payload.encode('utf-8')


class PointPayloadGenerator(PayloadGenerator):
    
    def __init__(self, solidity_version: str, randomize: bool = True):
        super().__init__(solidity_version, randomize)
        self._current_var_names = {}
    
    def _get_templates_for_type(self, vuln_type: str) -> Dict:
        vuln_type_upper = vuln_type.upper()
        
        if vuln_type_upper in ["OVERFLOW", "UNDERFLOW"]:
            # Combine OVERFLOW_TEMPLATES and BATCH_TRANSFER_OVERFLOW
            all_overflow_templates = {
                **point_injection.OVERFLOW_TEMPLATES,
                **point_injection.BATCH_TRANSFER_OVERFLOW
            }
            # Filter by specific vuln type and point injection
            return {k: v for k, v in all_overflow_templates.items() 
                    if v.get("vuln_type") == vuln_type_upper 
                    and v.get("injection_type") == "point"}
        elif vuln_type_upper == "TX_ORIGIN":
            return point_injection.TX_ORIGIN_TEMPLATES
        elif vuln_type_upper == "UNCHECKED_SEND":
            return point_injection.UNCHECKED_SEND_TEMPLATES
        elif vuln_type_upper in ["UNHANDLED_EXCEPTION", "UNHANDLED_CALL"]:
            return point_injection.UNHANDLED_CALL_TEMPLATES
        elif vuln_type_upper == "TIMESTAMP":
            # Filter to only point injection templates
            return {k: v for k, v in point_injection.TIMESTAMP_TEMPLATES.items()
                    if v.get("injection_type") == "point"}
        elif vuln_type_upper == "REENTRANCY":
            # All point-injection reentrancy templates live in reentrancy.py
            return reentrancy.REENTRANCY_TEMPLATES
        else:
            # Return all point templates if type not recognized
            return point_injection.ALL_POINT_TEMPLATES
    
    def get_compatible_templates(self, vuln_type: str = None) -> Dict:
        if vuln_type:
            templates = self._get_templates_for_type(vuln_type)
        else:
            templates = point_injection.ALL_POINT_TEMPLATES
        
        return self._get_compatible_templates(templates, self.solidity_version)
    
    def _generate_var_names(self, template: Dict, existing_names: set = None) -> Dict[str, str]:
        var_types = template.get("var_types", [])
        return point_injection.generate_var_names(var_types, existing_names)
    
    def _apply_vars(self, code: str, var_names: Dict[str, str], input_param: str = None, indent: str = "    ") -> str:
        return point_injection.apply_var_names(code, var_names, input_param, indent)
    
    def check_template_requirements(self, template: Dict, location: Dict) -> bool:
        # Check if template needs address parameter
        if template.get("needs_addr_param", False):
            if not location.get("has_address_param", False):
                return False
        
        # Check if template needs uint parameter for Mythril detectability
        if template.get("needs_uint_param", False):
            if not location.get("has_uint_param", False):
                return False
        
        # Check if template needs state modification (cannot be view/pure)
        if template.get("needs_state_modifying", False):
            if not location.get("is_state_modifying", True):
                return False
        
        # Check if template needs state declaration
        if template.get("state") is not None:
            if not location.get("is_state_modifying", True):
                return False
        
        return True
    
    def generate(
        self,
        location: Dict,
        vuln_type: str = None,
        template_name: str = None,
        existing_names: set = None,
        indentation: str = "    ",
        state_indentation: str = None,
    ) -> tuple:
        # Use same indentation for state if not specified
        if state_indentation is None:
            state_indentation = indentation
            
        # Get compatible templates
        compatible = self.get_compatible_templates(vuln_type)
        
        if not compatible:
            raise ValueError(f"No compatible templates for Solidity {self.solidity_version} and vuln type {vuln_type}")
        
        # Filter by template requirements
        filtered = {
            k: v for k, v in compatible.items()
            if self.check_template_requirements(v, location)
        }
        
        if not filtered:
            raise ValueError(f"No compatible templates for location in function {location['function'].name}")
        
        # Select template
        if template_name and template_name in filtered:
            template = filtered[template_name]
            selected_name = template_name
        elif template_name and template_name in compatible:
            # Template exists but is incompatible with this location
            raise ValueError(f"Template {template_name} is incompatible with function {location['function'].name} (state mutability)")
        else:
            selected_name = select_one(list(filtered.keys()), self.randomize)
            template = filtered[selected_name]
        
        # Get vulnerability type from template
        actual_vuln_type = template.get("vuln_type", vuln_type or "unknown")
        
        # Generate variable names
        var_names = self._generate_var_names(template, existing_names)
        self._current_var_names = var_names
        
        # Get input parameters from location
        func = location["function"]
        input_param = func.get_first_param_of_type("address") or func.get_first_param() or "msg.sender"
        uint_param = func.get_first_param_of_type("uint") or "1"
        
        # Generate state payload if needed (uses state_indentation)
        state_payload = None
        if template.get("state"):
            state_code = self._apply_vars(template["state"], var_names, input_param, state_indentation)
            state_payload = f"\n{state_indentation}{state_code}\n"
        
        # Generate code payload (uses function body indentation)
        code_template = template.get("code", "")
        # Replace {uint_param} placeholder if present
        code_template = code_template.replace("{uint_param}", uint_param)
        code = self._apply_vars(code_template, var_names, input_param, indentation)
        code_payload = f"\n{indentation}{code}\n{indentation}"
        
        return state_payload, code_payload, selected_name, actual_vuln_type


class CrossFunctionPayloadGenerator(PayloadGenerator):
    
    def __init__(self, solidity_version: str, randomize: bool = True):
        super().__init__(solidity_version, randomize)
        self._current_var_names = {}
    
    def _generate_stealthy_vars(self, template: Dict, existing_names: set = None) -> Dict[str, str]:
        var_types = template.get("var_types", [])
        return coupled_injection.generate_var_names(var_types, existing_names)
    
    def _apply_vars(self, code: str, var_names: Dict[str, str]) -> str:
        return coupled_injection.apply_var_names(code, var_names)
    
    def generate_state_payload(
        self,
        template: Dict,
        var_names: Dict[str, str],
        indentation: str,
    ) -> str:
        state_code = template["state"]
        state_code = self._apply_vars(state_code, var_names)
        state_code = state_code.format(indent=indentation)
        
        return f"\n{indentation}{state_code}\n"
    
    def generate_setter_payload(
        self,
        template: Dict,
        var_names: Dict[str, str],
        input_param: str,
        indentation: str,
    ) -> str:
        
        if template.get("setter_condition"):
            setter_code = template["setter_condition"]
        else:
            setter_code = template["setter"]
        
        setter_code = self._apply_vars(setter_code, var_names)
        setter_code = setter_code.format(
            input_param=input_param,
            indent=indentation,
        )
        
        return f"\n{indentation}{setter_code}\n{indentation}"
    
    def generate_executor_payload(
        self,
        template: Dict,
        var_names: Dict[str, str],
        indentation: str,
        benign_complexity: int = 0,
    ) -> str:
        
        executor_code = template["executor"]
        executor_code = self._apply_vars(executor_code, var_names)
        executor_code = executor_code.format(indent=indentation)
        
        # Add benign code if requested  
        if benign_complexity >= 1:
            benign_parts = []
            if benign_complexity >= 1:
                # Add a simple local variable assignment
                benign_parts.append(f"uint256 _timestamp = block.timestamp;")
            if benign_complexity >= 2:
                # Add another safe computation
                benign_parts.append(f"uint256 _blockNumber = block.number;")
            
            if benign_parts:
                benign_code = "\n" + indentation + ("\n" + indentation).join(benign_parts)
                executor_code = f"{executor_code}{benign_code}"
        
        return f"\n{indentation}{executor_code}\n{indentation}"
    
    def get_compatible_templates(self) -> Dict:
        return self._get_compatible_templates(
            coupled_injection.ALL_COUPLED_TEMPLATES,
            self.solidity_version
        )
    
    def prepare_injection(self, template_name: str = None) -> tuple:
        compatible = self.get_compatible_templates()
        
        if template_name and template_name in compatible:
            template = compatible[template_name]
        else:
            template = select_one(list(compatible.values()), self.randomize)
        
        var_names = self._generate_stealthy_vars(template)
        return template, var_names
