import random
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from .models import (
    FunctionInfo, ContractInfo, InjectionLocation, 
    CoupledInjectionSet, InjectionContext, InjectionPayload, InjectionMetadata
)
from .ast_helpers import (
    find_node_by_id, find_contracts, find_functions_in_contract,
    find_reentrancy_locations, find_point_injection_locations, extract_all_identifiers
)
from .utils import (
    detect_indentation, find_brace_offset, parse_src_location,
    is_version_compatible, select_one
)
from .payload_generators import (
    ReentrancyPayloadGenerator, CrossFunctionPayloadGenerator,
    PointPayloadGenerator, POINT_VULN_TYPES
)
from .templates import coupled_injection


class BaseInjector:
    
    def __init__(
        self,
        source_path: str,
        ast: Dict,
        solidity_version: str,
        randomize: bool = True,
    ):
        self.source_path = Path(source_path)
        self.ast = ast
        self.solidity_version = solidity_version
        self.randomize = randomize
        self._content: Optional[bytes] = None
        self.metadata: Optional[InjectionMetadata] = None
    
    @property
    def content(self) -> bytes:
        """Lazy load source content."""
        if self._content is None:
            self._content = self.source_path.read_bytes()
        return self._content
    
    def _apply_payloads(self, payloads: List[InjectionPayload]) -> bytes:
        content = self.content
        
        # Sort by offset descending
        sorted_payloads = sorted(payloads, key=lambda p: p.offset, reverse=True)
        
        # First pass: apply payloads and track metadata
        # Since we apply in reverse order (high to low offset), earlier insertions
        # don't affect later positions
        cumulative_added = 0
        
        for i, payload in enumerate(sorted_payloads):
            # Calculate the bytes added after this position (from lower offset injections)
            bytes_added_after = sum(len(p.content) for p in sorted_payloads[i+1:])
            
            # Actual position in final file
            final_start = payload.offset + bytes_added_after
            final_end = final_start + len(payload.content)
            
            content = content[:payload.offset] + payload.content + content[payload.offset:]
            print(f"[+] Injected {payload.component_name} at offset {payload.offset}")
            
            # Track in metadata if available
            if self.metadata:
                self.metadata.add_region(
                    start_byte=final_start,
                    end_byte=final_end,
                    component=payload.component_name,
                    description=f"Injected {payload.component_name} code"
                )
        
        return content
    
    def _write_output(self, content: bytes, output_path: str) -> None:
        Path(output_path).write_bytes(content)
    
    def _save_metadata(self, output_path: str) -> None:
        if self.metadata is None:
            return
        
        metadata_path = Path(output_path).with_suffix('.json')
        with open(metadata_path, 'w') as f:
            json.dump(self.metadata.to_dict(), f, indent=2)
        print(f"[+] Saved metadata to {metadata_path}")


class PointInjector(BaseInjector):
    
    def __init__(
        self,
        source_path: str,
        ast: Dict,
        solidity_version: str,
        randomize: bool = True,
        vuln_type: str = None,
    ):
        super().__init__(source_path, ast, solidity_version, randomize)
        self.vuln_type = vuln_type
    
    def find_locations(self, vuln_type: str = None) -> List[Dict]:
        vuln_type = vuln_type or self.vuln_type
        
        if vuln_type and vuln_type.lower() == "reentrancy":
            # Use specialized reentrancy location finder (requires state var assignment)
            reentrancy_locs = find_reentrancy_locations(self.ast)
            # Convert to general location format
            locations = []
            for loc in reentrancy_locs:
                func_node = find_node_by_id(self.ast, loc.function_id)
                if func_node:
                    func_info = FunctionInfo.from_ast_node(func_node)
                    if func_info:
                        # Find parent contract
                        contracts = find_contracts(self.ast)
                        parent_contract = None
                        for contract in contracts:
                            funcs = find_functions_in_contract(contract.node)
                            if any(f.id == func_info.id for f in funcs):
                                parent_contract = contract
                                break
                        
                        if parent_contract:
                            locations.append({
                                "contract": parent_contract,
                                "function": func_info,
                                "has_params": func_info.has_params,
                                "has_address_param": any(
                                    "address" in p.get("type", "").lower()
                                    for p in func_info.params
                                ),
                                "has_uint_param": any(
                                    "uint" in p.get("type", "").lower()
                                    for p in func_info.params
                                ),
                                "is_payable": func_info.is_payable,
                                "is_state_modifying": func_info.is_state_modifying(),
                                "assignment_src": loc.assignment_src,
                                "state_variable": loc.state_variable,
                            })
            return locations
        else:
            # Use general location finder for other vulnerability types
            return find_point_injection_locations(self.ast)
    
    def _get_contract_body_offset(self, contract: ContractInfo) -> int:
        start, length, _ = parse_src_location(contract.src)
        return find_brace_offset(self.content, start, length)
    
    def _get_function_body_offset(self, func: FunctionInfo) -> int:
        start, _, _ = parse_src_location(func.body_src)
        return start + 1
    
    def inject(
        self,
        locations: Optional[List[Dict]] = None,
        vuln_type: Optional[str] = None,
        template_name: Optional[str] = None,
        output_path: str = "test_vulnerable.sol",
        save_metadata: bool = True,
    ) -> bool:
        
        vuln_type = vuln_type or self.vuln_type
        
        if locations is None:
            locations = self.find_locations(vuln_type)
        
        if not locations:
            print("No suitable locations found for injection.")
            return False
        
        # Select one location
        selected = select_one(locations, self.randomize)
        
        print(f"Selected 1 location out of {len(locations)} suitable locations.")
        print(f"Contract: {selected['contract'].name}")
        print(f"Function: {selected['function'].name}\n")
        
        func_info = selected["function"]
        contract_info = selected["contract"]
        
        # Extract existing identifiers to avoid collisions
        existing_identifiers = extract_all_identifiers(self.ast)
        
        # Detect indentation from the function body
        func_offset = self._get_function_body_offset(func_info)
        func_indent = detect_indentation(self.content, func_offset)
        
        # Detect indentation for state variables (contract body level)
        contract_offset = self._get_contract_body_offset(contract_info)
        state_indent = detect_indentation(self.content, contract_offset)
        
        # Create payload generator
        generator = PointPayloadGenerator(self.solidity_version, self.randomize)
        
        # Get compatible templates and select vulnerability type if not specified
        if not vuln_type:
            # Try each vulnerability type to find one with compatible templates
            available_types = []
            for vt in POINT_VULN_TYPES:
                compatible = generator.get_compatible_templates(vt)
                # Filter by location requirements
                valid = {k: v for k, v in compatible.items() 
                        if generator.check_template_requirements(v, selected)}
                if valid:
                    available_types.append(vt)
            
            if not available_types:
                print("No compatible vulnerability types found for this location.")
                return False
            
            vuln_type = select_one(available_types, self.randomize)
            print(f"Auto-selected vulnerability type: {vuln_type}")
        
        # Generate payloads with detected indentation
        try:
            state_payload, code_payload, selected_template, actual_vuln_type = generator.generate(
                location=selected,
                vuln_type=vuln_type,
                template_name=template_name,
                existing_names=existing_identifiers,
                indentation=func_indent,
                state_indentation=state_indent,
            )
        except ValueError as e:
            print(f"Error generating payload: {e}")
            return False
        
        print(f"=== Point Injection Plan ===")
        print(f"Vulnerability type: {actual_vuln_type}")
        print(f"Template: {selected_template}")
        
        # Initialize metadata
        if save_metadata:
            self.metadata = InjectionMetadata(
                source_contract=str(self.source_path),
                output_contract=output_path,
                vulnerability_type=actual_vuln_type.lower(),
                injection_mode="point",
                template_name=selected_template,
                solidity_version=self.solidity_version,
            )
        
        # Calculate offsets and build payloads
        payloads = []
        
        # Add state variable if needed
        if state_payload:
            contract_offset = self._get_contract_body_offset(contract_info)
            if contract_offset == -1:
                print("Error: Could not find contract body offset.")
                return False
            payloads.append(InjectionPayload(
                offset=contract_offset,
                content=state_payload.encode('utf-8'),
                component_name="state",
            ))
        
        # Add code payload to function body
        func_offset = self._get_function_body_offset(func_info)
        if func_offset == -1:
            print("Error: Could not find function body offset.")
            return False
        
        payloads.append(InjectionPayload(
            offset=func_offset,
            content=code_payload.encode('utf-8'),
            component_name="vulnerable_code",
        ))
        
        # Apply and write
        modified_content = self._apply_payloads(payloads)
        self._write_output(modified_content, output_path)
        
        # Save metadata
        if save_metadata:
            self._save_metadata(output_path)
        
        print(f"\nSuccess! Saved vulnerability to {output_path}")
        return True


class CoupledInjector(BaseInjector):
    
    def find_locations(self) -> List[CoupledInjectionSet]:
        """Find all suitable setter-executor pairs."""
        injection_sets = []
        contracts = find_contracts(self.ast)
        
        for contract_info in contracts:
            if not contract_info.is_concrete_contract():
                continue
            
            functions = find_functions_in_contract(contract_info.node)
            
            # Categorize functions
            setter_candidates = [f for f in functions 
                               if f.is_public_or_external() 
                               and f.is_state_modifying()
                               and f.has_params]
            
            executor_candidates = [f for f in functions
                                  if f.is_public_or_external()
                                  and f.is_state_modifying()
                                  and (f.is_payable or not f.has_params)]
            
            # Create pairs
            for setter in setter_candidates:
                for executor in executor_candidates:
                    if setter.id != executor.id:
                        injection_sets.append(CoupledInjectionSet(
                            contract=contract_info,
                            setter=setter,
                            executor=executor,
                        ))
        
        return injection_sets
    
    def _filter_by_template(
        self,
        sets: List[CoupledInjectionSet],
        templates: Dict,
    ) -> List[Tuple[CoupledInjectionSet, str, Dict]]:
        
        valid = []
        
        for inj_set in sets:
            for tmpl_name, tmpl in templates.items():
                # Check setter requirements
                if tmpl.get("setter_needs_args", False) and not inj_set.setter.has_params:
                    continue
                
                # Check executor requirements
                if tmpl.get("requires_payable_executor", False) and not inj_set.executor.is_payable:
                    continue
                
                # Check if template needs payable setter (for msg.value usage)
                if tmpl.get("needs_payable_setter", False) and not inj_set.setter.is_payable:
                    continue
                
                # Check parameter type compatibility
                var_types = tmpl.get("var_types", [])
                
                # Check for address parameter requirement
                if tmpl.get("needs_addr_param", False) and inj_set.setter.has_params:
                    has_address_param = any(
                        "address" in param.get("type", "").lower() 
                        for param in inj_set.setter.params
                    )
                    if not has_address_param:
                        continue
                
                # Check for uint parameter requirement
                if tmpl.get("needs_uint_param", False) and inj_set.setter.has_params:
                    has_uint_param = any(
                        "uint" in param.get("type", "").lower()
                        for param in inj_set.setter.params
                    )
                    if not has_uint_param:
                        continue
                
                # Legacy address parameter check from var_types
                if "addr" in var_types and inj_set.setter.has_params:
                    # Template needs address parameter - check if setter has at least one address param
                    has_address_param = any(
                        "address" in param.get("type", "").lower() 
                        for param in inj_set.setter.params
                    )
                    if not has_address_param:
                        continue
                
                # Add all valid combinations (set × template)
                valid.append((inj_set, tmpl_name, tmpl))
        
        return valid
    
    def _get_contract_body_offset(self, contract: ContractInfo) -> int:
        start, length, _ = parse_src_location(contract.src)
        return find_brace_offset(self.content, start, length)
    
    def _get_function_body_offset(self, func: FunctionInfo) -> int:
        start, _, _ = parse_src_location(func.body_src)
        return start + 1
    
    def inject(
        self,
        template_name: Optional[str] = None,
        output_path: str = "test_vulnerable.sol",
        save_metadata: bool = True,
    ) -> bool:
        
        # Find locations
        all_sets = self.find_locations()
        if not all_sets:
            print("No suitable locations found for cross-function injection.")
            return False
        
        print(f"Found {len(all_sets)} potential injection sets.")
        
        # Get compatible templates
        generator = CrossFunctionPayloadGenerator(self.solidity_version, self.randomize)
        compatible_templates = generator.get_compatible_templates()
        
        if not compatible_templates:
            print(f"No compatible templates for Solidity version {self.solidity_version}")
            return False
        
        print(f"Found {len(compatible_templates)} compatible templates.")
        
        # Filter by template requirements
        valid_sets = self._filter_by_template(all_sets, compatible_templates)
        
        if not valid_sets:
            print("No valid injection sets matching template requirements.")
            return False
        
        print(f"Found {len(valid_sets)} valid injection sets.")
        
        # Select one
        if template_name:
            matching = [t for t in valid_sets if t[1] == template_name]
            selected = select_one(matching, self.randomize) if matching else select_one(valid_sets, self.randomize)
        else:
            selected = select_one(valid_sets, self.randomize)
        
        inj_set, tmpl_name, template = selected
        
        # Extract existing identifiers to avoid name collisions
        existing_identifiers = extract_all_identifiers(self.ast)
        
        # Generate stealthy variable names that don't collide with existing names
        var_names = generator._generate_stealthy_vars(template, existing_identifiers)
        
        print(f"\n=== Cross-Function Injection Plan ===")
        print(f"Template: {tmpl_name} - {template['description']}")
        print(f"Contract: {inj_set.contract.name}")
        print(f"Setter Function: {inj_set.setter.name}")
        print(f"Executor Function: {inj_set.executor.name}")
        print(f"Variable names: {var_names}")
        
        # Initialize metadata
        if save_metadata:
            self.metadata = InjectionMetadata(
                source_contract=str(self.source_path),
                output_contract=output_path,
                vulnerability_type=template.get("vulnerability_type", "cross-function"),
                injection_mode="coupled",
                template_name=tmpl_name,
                solidity_version=self.solidity_version,
            )
        
        # Get input parameter based on template requirements
        if template.get("needs_uint_param"):
            # Template requires uint parameter
            input_param = inj_set.setter.get_first_param_of_type("uint") or "1"
        elif template.get("needs_addr_param"):
            # Template requires address parameter
            input_param = inj_set.setter.get_first_param_of_type("address") or "msg.sender"
        else:
            # Default: prefer address, then any param
            input_param = (
                inj_set.setter.get_first_param_of_type("address") or
                inj_set.setter.get_first_param() or
                "msg.sender"
            )
        print(f"Input parameter: {input_param}")
        
        # Calculate offsets
        contract_offset = self._get_contract_body_offset(inj_set.contract)
        setter_offset = self._get_function_body_offset(inj_set.setter)
        executor_offset = self._get_function_body_offset(inj_set.executor)
        
        if -1 in (contract_offset, setter_offset, executor_offset):
            print("Error: Could not determine injection offsets.")
            return False
        
        # Generate payloads with stealthy variable names
        payloads = []
        
        # State payload
        state_indent = detect_indentation(self.content, contract_offset)
        state_code = generator.generate_state_payload(
            template, var_names, state_indent
        )
        payloads.append(InjectionPayload(contract_offset, state_code.encode(), "state"))
        
        # Setter payload
        setter_indent = detect_indentation(self.content, setter_offset)
        if not setter_indent.strip() == "":
            setter_indent = "        "  # Default function body indent
        setter_code = generator.generate_setter_payload(
            template, var_names, input_param, setter_indent
        )
        payloads.append(InjectionPayload(setter_offset, setter_code.encode(), "setter"))
        
        # Executor payload
        executor_indent = detect_indentation(self.content, executor_offset)
        if not executor_indent.strip() == "":
            executor_indent = "        "
        executor_code = generator.generate_executor_payload(
            template, var_names, executor_indent
        )
        payloads.append(InjectionPayload(executor_offset, executor_code.encode(), "executor"))
        
        # Apply and write
        modified_content = self._apply_payloads(payloads)
        self._write_output(modified_content, output_path)
        
        # Save metadata
        if save_metadata:
            self._save_metadata(output_path)
        
        print(f"\nSuccess! Saved cross-function vulnerability to {output_path}")
        return True
