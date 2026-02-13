def _mk_state_legacy(var):
    return ("mapping(address => uint256) {var_mapping};\n"
            "{indent}function deposit_{var_mapping}() public payable {\n"
            "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
            "{indent}}")

def _mk_state_modern(var):
    return ("mapping(address => uint256) {var_mapping};\n"
            "{indent}function deposit_{var_mapping}() public payable {\n"
            "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
            "{indent}}")


REENTRANCY_TEMPLATES = {
    "call_value_legacy": {
        "description": "Classic reentrancy with .call.value() (Solidity <0.5)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.0",
        "max_version": "0.4.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _amt = {var_mapping}[msg.sender];\n"
                 "{indent}if (_amt > 0) {\n"
                 "{indent}    require(msg.sender.call.value(_amt)());\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    "call_value_050": {
        "description": "Classic reentrancy with .call.value() (Solidity 0.5.x-0.6.x)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.5.0",
        "max_version": "0.6.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _amt = {var_mapping}[msg.sender];\n"
                 "{indent}if (_amt > 0) {\n"
                 "{indent}    (bool _success, ) = msg.sender.call.value(_amt)(\"\");\n"
                 "{indent}    require(_success);\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    "call_value_modern": {
        "description": "Classic reentrancy with .call{value:} (Solidity >=0.7)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.7.0", 
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _amt = {var_mapping}[msg.sender];\n"
                 "{indent}if (_amt > 0) {\n"
                 "{indent}    (bool _success, ) = msg.sender.call{value: _amt}(\"\");\n"
                 "{indent}    require(_success);\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    "send_reentrancy": {
        "description": "Reentrancy using send() - limited gas, harder to exploit",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.0",
        "max_version": "0.7.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _amt = {var_mapping}[msg.sender];\n"
                 "{indent}if (_amt > 0) {\n"
                 "{indent}    msg.sender.send(_amt);\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    "transfer_reentrancy_legacy": {
        "description": "Reentrancy using transfer() for Solidity <0.6 - limited gas",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.0",
        "max_version": "0.5.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _amt = {var_mapping}[msg.sender];\n"
                 "{indent}if (_amt > 0) {\n"
                 "{indent}    msg.sender.transfer(_amt);\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    "transfer_reentrancy": {
        "description": "Reentrancy using transfer() with payable() (Solidity >=0.6) - limited gas",
        "vuln_type": "REENTRANCY",
        "min_version": "0.6.0",
        "max_version": "0.8.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _amt = {var_mapping}[msg.sender];\n"
                 "{indent}if (_amt > 0) {\n"
                 "{indent}    payable(msg.sender).transfer(_amt);\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    "withdraw_reentrancy_legacy": {
        "description": "Withdraw function reentrancy pattern (Solidity <0.5)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.0",
        "max_version": "0.4.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _balance = {var_mapping}[msg.sender];\n"
                 "{indent}if (_balance > 0) {\n"
                 "{indent}    msg.sender.call.value(_balance)();\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    "withdraw_reentrancy_050": {
        "description": "Withdraw function reentrancy pattern (Solidity 0.5.x-0.6.x)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.5.0",
        "max_version": "0.6.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _balance = {var_mapping}[msg.sender];\n"
                 "{indent}if (_balance > 0) {\n"
                 "{indent}    (bool _sent, ) = msg.sender.call.value(_balance)(\"\");\n"
                 "{indent}    require(_sent);\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    "delegate_reentrancy": {
        "description": "Reentrancy via delegatecall - state update after delegated external call (Sereum: Delegated Re-entrancy)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.7.0",
        "max_version": "0.8.99",
        "injection_type": "point",
        "state": ("address public {var_addr}_lib;\n"
                  "{indent}mapping(address => uint256) public {var_mapping};\n"
                  "{indent}function setLib_{var_mapping}(address _lib) public {\n"
                  "{indent}    {var_addr}_lib = _lib;\n"
                  "{indent}}\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": ("uint256 _amt = {var_mapping}[msg.sender];\n"
                 "{indent}if (_amt > 0) {\n"
                 "{indent}    (bool success, ) = {var_addr}_lib.delegatecall(\n"
                 "{indent}        abi.encodeWithSignature(\"sendEth(address,uint256)\", msg.sender, _amt)\n"
                 "{indent}    );\n"
                 "{indent}    require(success, \"Delegatecall failed\");\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping", "address"],
    },
    "create_reentrancy": {
        "description": "Reentrancy during contract creation via constructor external call (Sereum: Create-Based Re-entrancy)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.7.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) public {var_mapping};\n"
                  "{indent}bool public {var_bool}_initialized;\n"
                  "{indent}constructor() payable {\n"
                  "{indent}    {var_mapping}[msg.sender] = msg.value;\n"
                  "{indent}    (bool _ok, ) = msg.sender.call{value: address(this).balance}(\"\");\n"
                  "{indent}    require(_ok);\n"
                  "{indent}    {var_bool}_initialized = true;\n"
                  "{indent}}"),
        "code": ("uint256 _credit = {var_mapping}[msg.sender];\n"
                 "{indent}if (_credit > 0) {\n"
                 "{indent}    (bool _ok, ) = msg.sender.call{value: _credit}(\"\");\n"
                 "{indent}    require(_ok);\n"
                 "{indent}    {var_mapping}[msg.sender] = 0;\n"
                 "{indent}}"),
        "var_types": ["mapping", "bool"],
    },
}


# ============================================================================
# LEGACY CORE TEMPLATES (for ReentrancyPayloadGenerator)
# These are simple call patterns without state management
# ============================================================================

REENTRANCY_CORE_TEMPLATES = {
    "call_value_legacy": {
        "description": "Legacy .call.value() pattern (Solidity <0.5)",
        "min_version": "0.4.0",
        "max_version": "0.4.99",
        "core": "bool _callSuccess = {dest}.call.value({amt})(\"\");\n        require(_callSuccess);",
    },
    "call_value_050": {
        "description": "Legacy .call.value() pattern (Solidity 0.5.x-0.6.x)",
        "min_version": "0.5.0",
        "max_version": "0.6.99",
        "core": "(bool _callSuccess, ) = {dest}.call.value({amt})(\"\");\n        require(_callSuccess);",
    },
    "call_value_modern": {
        "description": "Modern .call{{value: }} pattern (Solidity >=0.7)",
        "min_version": "0.7.0", 
        "max_version": "0.9.99",
        "core": "(bool _callSuccess, ) = {dest}.call{{value: {amt}}}(\"\");\n        require(_callSuccess);",
    },
    "send_unchecked": {
        "description": "Unchecked send()",
        "min_version": "0.4.0",
        "max_version": "0.9.99",
        "core": "bool _sent = {dest}.send({amt});\n        require(_sent);",
    },
    "transfer_pattern": {
        "description": "Transfer pattern",
        "min_version": "0.4.0",
        "max_version": "0.9.99",
        "core": "{dest}.transfer({amt});",
    },
}