from typing import Dict, List, Optional, Callable, Any, Generator

from .models import FunctionInfo, ContractInfo, InjectionLocation


def traverse_ast(node: Dict, visitor: Callable[[Dict], None]) -> None:
    if not isinstance(node, dict):
        return
    
    visitor(node)
    
    for child in node.get("children", []):
        traverse_ast(child, visitor)


def find_nodes_by_name(ast: Dict, node_name: str) -> Generator[Dict, None, None]:
    def _search(node: Dict):
        if not isinstance(node, dict):
            return
        
        if node.get("name") == node_name:
            yield node
        
        for child in node.get("children", []):
            yield from _search(child)
    
    yield from _search(ast)


def find_node_by_id(ast: Dict, target_id: int) -> Optional[Dict]:
    if not isinstance(ast, dict):
        return None
    
    if ast.get("id") == target_id:
        return ast
    
    for child in ast.get("children", []):
        result = find_node_by_id(child, target_id)
        if result:
            return result
    
    return None


def find_state_variables(ast: Dict) -> Dict[int, str]:
    state_vars = {}
    
    def visitor(node: Dict):
        if node.get("name") == "VariableDeclaration":
            attrs = node.get("attributes", {})
            if attrs.get("stateVariable"):
                var_id = node.get("id")
                var_name = attrs.get("name")
                if var_id is not None and var_name:
                    state_vars[var_id] = var_name
    
    traverse_ast(ast, visitor)
    return state_vars


def extract_all_identifiers(ast: Dict) -> set:
    identifiers = set()
    
    def visitor(node: Dict):
        attrs = node.get("attributes", {})
        name = attrs.get("name")
        
        # Collect names from various node types
        node_name = node.get("name")
        if node_name in (
            "VariableDeclaration",
            "FunctionDefinition", 
            "EventDefinition",
            "ModifierDefinition",
            "StructDefinition",
            "EnumDefinition",
            "ContractDefinition",
        ):
            if name:
                identifiers.add(name)
        
        # Also check for Identifier nodes (references)
        if node_name == "Identifier" and name:
            identifiers.add(name)
    
    traverse_ast(ast, visitor)
    return identifiers


def find_contracts(ast: Dict) -> List[ContractInfo]:
    contracts = []
    
    for node in find_nodes_by_name(ast, "ContractDefinition"):
        contract_info = ContractInfo.from_ast_node(node)
        if contract_info:
            contracts.append(contract_info)
    
    return contracts


def find_functions_in_contract(contract_node: Dict) -> List[FunctionInfo]:
    functions = []
    
    for child in contract_node.get("children", []):
        if child.get("name") == "FunctionDefinition":
            func_info = FunctionInfo.from_ast_node(child)
            if func_info:
                functions.append(func_info)
    
    return functions


def check_assignment_target(assignment_node: Dict, state_vars: Dict[int, str]) -> Optional[str]:
    children = assignment_node.get("children", [])
    if not children:
        return None
    
    lhs = children[0]  # First child is the LHS
    
    # Direct identifier reference
    if lhs.get("name") == "Identifier":
        ref_id = lhs.get("attributes", {}).get("referencedDeclaration")
        if ref_id in state_vars:
            return state_vars[ref_id]
    
    # Mapping/array access or member access (e.g., mapping[key] or obj.field)
    if lhs.get("name") in ["IndexAccess", "MemberAccess"]:
        lhs_children = lhs.get("children", [])
        if lhs_children:
            base = lhs_children[0]
            if base.get("name") == "Identifier":
                ref_id = base.get("attributes", {}).get("referencedDeclaration")
                if ref_id in state_vars:
                    return state_vars[ref_id]
    
    return None


def find_state_variable_assignments(node: Dict, state_vars: Dict[int, str]) -> List[tuple]:
    assignments = []
    
    def visitor(n: Dict):
        if n.get("name") == "Assignment":
            state_var = check_assignment_target(n, state_vars)
            if state_var:
                assignments.append((n, state_var))
    
    traverse_ast(node, visitor)
    return assignments


def find_reentrancy_locations(ast: Dict) -> List[InjectionLocation]:
    state_vars = find_state_variables(ast)
    locations = []
    
    for func_node in find_nodes_by_name(ast, "FunctionDefinition"):
        func_info = FunctionInfo.from_ast_node(func_node)
        if not func_info:
            continue
        
        # Check function is suitable
        if not func_info.is_public_or_external():
            continue
        if not func_info.is_state_modifying():
            continue
        
        # Find assignments to state variables
        assignments = find_state_variable_assignments(func_node, state_vars)
        
        for assignment_node, state_var_name in assignments:
            locations.append(InjectionLocation(
                function_id=func_info.id,
                function_name=func_info.name,
                function_src=func_info.src,
                assignment_id=assignment_node.get("id"),
                assignment_src=assignment_node.get("src"),
                state_variable=state_var_name,
            ))
    
    return locations


def find_point_injection_locations(ast: Dict) -> List[Dict]:
    locations = []
    contracts = find_contracts(ast)
    
    for contract_info in contracts:
        if not contract_info.is_concrete_contract():
            continue
        
        functions = find_functions_in_contract(contract_info.node)
        
        for func_info in functions:
            # Check function is publicly accessible
            if not func_info.is_public_or_external():
                continue
            
            # Get function body offset
            if not func_info.body_src:
                continue
            
            locations.append({
                "contract": contract_info,
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
            })
    
    return locations
