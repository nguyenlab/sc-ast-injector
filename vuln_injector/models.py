from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class FunctionInfo:
    node: Dict[str, Any]
    id: int
    name: str
    src: str
    body_src: str
    visibility: str
    state_mutability: str
    is_payable: bool
    params: List[Dict[str, str]]
    has_params: bool
    
    @classmethod
    def from_ast_node(cls, node: Dict) -> Optional["FunctionInfo"]:
        """Create FunctionInfo from an AST FunctionDefinition node."""
        if node.get("name") != "FunctionDefinition":
            return None
        
        attrs = node.get("attributes", {})
        func_name = attrs.get("name", "")
        visibility = attrs.get("visibility", "")
        state_mutability = attrs.get("stateMutability", "")
        is_constructor = attrs.get("isConstructor", False)
        
        # Skip constructors or unnamed functions
        if is_constructor or not func_name:
            return None
        
        # Get function parameters
        params = []
        for param_list in node.get("children", []):
            if param_list.get("name") == "ParameterList":
                for param in param_list.get("children", []):
                    if param.get("name") == "VariableDeclaration":
                        param_attrs = param.get("attributes", {})
                        params.append({
                            "name": param_attrs.get("name"),
                            "type": param_attrs.get("type"),
                        })
                break  # Only first ParameterList (input params)
        
        # Get function body
        func_body = None
        for child in node.get("children", []):
            if child.get("name") == "Block":
                func_body = child
                break
        
        if not func_body:
            return None
        
        return cls(
            node=node,
            id=node.get("id"),
            name=func_name,
            src=node.get("src", ""),
            body_src=func_body.get("src", ""),
            visibility=visibility,
            state_mutability=state_mutability,
            is_payable=state_mutability == "payable",
            params=params,
            has_params=len(params) > 0,
        )
    
    def is_public_or_external(self) -> bool:
        return self.visibility in ["public", "external"]
    
    def is_state_modifying(self) -> bool:
        return self.state_mutability not in ["view", "pure", "constant"]
    
    def get_first_param_of_type(self, type_substr: str) -> Optional[str]:
        for param in self.params:
            if type_substr in param.get("type", ""):
                return param["name"]
        return None
    
    def get_first_param(self) -> Optional[str]:
        if self.params:
            return self.params[0].get("name")
        return None


@dataclass
class ContractInfo:

    node: Dict[str, Any]
    id: int
    name: str
    src: str
    contract_kind: str
    
    @classmethod
    def from_ast_node(cls, node: Dict) -> Optional["ContractInfo"]:
        if node.get("name") != "ContractDefinition":
            return None
        
        attrs = node.get("attributes", {})
        return cls(
            node=node,
            id=node.get("id"),
            name=attrs.get("name", ""),
            src=node.get("src", ""),
            contract_kind=attrs.get("contractKind", "contract"),
        )
    
    def is_concrete_contract(self) -> bool:
        return self.contract_kind not in ["interface", "library"]


@dataclass
class InjectionLocation:

    function_id: int
    function_name: str
    function_src: str
    assignment_id: int
    assignment_src: str
    state_variable: str
    
    def get_start_offset(self) -> int:
        return int(self.assignment_src.split(':')[0])


@dataclass
class CoupledInjectionSet:

    contract: ContractInfo
    setter: FunctionInfo
    executor: FunctionInfo


@dataclass
class InjectionContext:

    beneficiary: str = "msg.sender"
    amount: str = "0"
    input_param: str = "msg.sender"
    
    @classmethod
    def from_function(cls, func: FunctionInfo) -> "InjectionContext":
        beneficiary = func.get_first_param_of_type("address") or "msg.sender"
        amount = func.get_first_param_of_type("uint") or "0"
        input_param = func.get_first_param_of_type("address") or func.get_first_param() or "msg.sender"
        
        return cls(
            beneficiary=beneficiary,
            amount=amount,
            input_param=input_param,
        )


@dataclass
class InjectionPayload:
    offset: int
    content: bytes
    component_name: str  # e.g., "state", "setter", "executor", "reentrancy"
    
    def __lt__(self, other: "InjectionPayload") -> bool:
        return self.offset > other.offset  # Reversed for descending sort


@dataclass
class InjectionMetadata:
    source_contract: str
    output_contract: str
    vulnerability_type: str  # "reentrancy", "tod", "dos", etc.
    injection_mode: str  # "point" or "coupled"
    template_name: str
    solidity_version: str
    injected_regions: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_region(self, start_byte: int, end_byte: int, component: str, description: str = ""):
        """Add an injected code region."""
        self.injected_regions.append({
            "start_byte": start_byte,
            "end_byte": end_byte,
            "component": component,
            "description": description,
        })
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_contract": self.source_contract,
            "output_contract": self.output_contract,
            "vulnerability_type": self.vulnerability_type,
            "injection_mode": self.injection_mode,
            "template_name": self.template_name,
            "solidity_version": self.solidity_version,
            "injected_regions": self.injected_regions,
        }
