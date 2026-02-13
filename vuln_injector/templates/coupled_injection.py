import random

# ============================================================================
# VARIABLE NAME POOLS (Stealthy - no vulnerability markers)
# ============================================================================

# Pool of realistic variable name components
REALISTIC_PREFIXES = [
    "pending", "current", "last", "next", "active", "primary", "default",
    "registered", "approved", "verified", "authorized", "delegated",
]

REALISTIC_SUFFIXES = [
    "Recipient", "Account", "Address", "Wallet", "Handler", "Manager",
    "Controller", "Target", "Destination", "Payee", "Holder", "Owner",
]

AMOUNT_NAMES = [
    "pendingAmount", "currentBalance", "reservedFunds", "allocatedValue",
    "depositAmount", "withdrawalLimit", "transferAmount", "payoutValue",
]

TIME_NAMES = [
    "releaseTime", "lockPeriod", "expirationTime", "activationTime",
    "cooldownEnd", "nextAllowedTime", "scheduledTime", "unlockTimestamp",
]

ARRAY_NAMES = [
    "participants", "members", "registeredUsers", "activeAccounts",
    "pendingRecipients", "queuedAddresses", "enrolledUsers", "subscribers",
]

MAPPING_NAMES = [
    "balances", "deposits", "allocations", "contributions",
    "pendingPayouts", "userCredits", "accountValues", "reservedAmounts",
]

BOOL_VAR_NAMES = [
    "isActive", "isEnabled", "isValid", "isProcessed", "isComplete",
    "hasExecuted", "canWithdraw", "isAuthorized", "isLocked",
]

UINT_VAR_NAMES = [
    "amount", "value", "balance", "total", "count", "limit",
    "threshold", "allocation", "deposit", "fee", "reward",
]

ADDR_VAR_NAMES = [
    "recipient", "sender", "account", "target", "destination",
    "beneficiary", "payee", "delegate", "handler", "controller",
]


# ============================================================================
# HELPER FUNCTIONS FOR GENERATING UNIQUE NAMES
# ============================================================================

def get_random_address_var():
    return random.choice(REALISTIC_PREFIXES) + random.choice(REALISTIC_SUFFIXES)


def get_random_amount_var():
    return random.choice(AMOUNT_NAMES)


def get_random_time_var():
    return random.choice(TIME_NAMES)


def get_random_array_var():
    return random.choice(ARRAY_NAMES)


def get_random_mapping_var():
    return random.choice(MAPPING_NAMES)


def get_random_bool_var():
    return random.choice(BOOL_VAR_NAMES)


def get_random_uint_var():
    return random.choice(UINT_VAR_NAMES)


def get_random_addr_var():
    return random.choice(ADDR_VAR_NAMES)


def generate_unique_name(generator_func, existing_names: set, max_attempts: int = 50) -> str:
    for _ in range(max_attempts):
        name = generator_func()
        if name not in existing_names:
            return name
    
    # If we can't find a unique name, add a random suffix
    base_name = generator_func()
    suffix = random.randint(1, 999)
    return f"{base_name}{suffix}"


def generate_var_names(var_types: list, existing_names: set = None) -> dict:
    if existing_names is None:
        existing_names = set()
    
    names = {}
    used_names = existing_names.copy()
    
    if "addr" in var_types:
        name = generate_unique_name(get_random_address_var, used_names)
        names["var_addr"] = name
        used_names.add(name)
    if "time" in var_types:
        name = generate_unique_name(get_random_time_var, used_names)
        names["var_time"] = name
        used_names.add(name)
    if "amt" in var_types:
        name = generate_unique_name(get_random_amount_var, used_names)
        names["var_amt"] = name
        used_names.add(name)
    if "array" in var_types:
        name = generate_unique_name(get_random_array_var, used_names)
        names["var_array"] = name
        used_names.add(name)
    if "mapping" in var_types:
        name = generate_unique_name(get_random_mapping_var, used_names)
        names["var_mapping"] = name
        used_names.add(name)
    if "bool" in var_types:
        name = generate_unique_name(get_random_bool_var, used_names)
        names["var_bool"] = name
        used_names.add(name)
    if "uint" in var_types:
        name = generate_unique_name(get_random_uint_var, used_names)
        names["var_uint"] = name
        used_names.add(name)
    
    return names


def apply_var_names(template_str: str, var_names: dict, input_param: str = None, indent: str = "    ") -> str:
    if template_str is None:
        return None
    
    result = template_str
    for placeholder, name in var_names.items():
        result = result.replace("{" + placeholder + "}", name)
    
    if input_param:
        result = result.replace("{input_param}", input_param)
    
    result = result.replace("{indent}", indent)
    return result


# ============================================================================
# CROSS-FUNCTION TEMPLATES (TOD, DOS, ACCESS CONTROL)
# ============================================================================

CROSS_FUNCTION_TEMPLATES = {
    # Transaction Order Dependence (TOD) / Front-running vulnerability
    "tod_transfer_legacy": {
        "description": "Transaction Order Dependence - winner gets transfer (Solidity <0.5)",
        "vuln_type": "TOD",
        "min_version": "0.4.11",
        "max_version": "0.4.99",
        "state": "address {var_addr};",
        "setter": "{var_addr} = {input_param};",
        "setter_condition": None,
        "executor": "{var_addr}.transfer(msg.value);",
        "requires_payable_executor": True,
        "setter_needs_args": True,
        "var_types": ["addr"],
    },
    
    "tod_transfer": {
        "description": "Transaction Order Dependence - winner gets transfer (Solidity >=0.5)",
        "vuln_type": "TOD",
        "min_version": "0.5.0",
        "max_version": "0.9.99",
        "state": "address payable {var_addr};",
        "setter": "{var_addr} = address(uint160({input_param}));",
        "setter_condition": None,
        "executor": "{var_addr}.transfer(msg.value);",
        "requires_payable_executor": True,
        "setter_needs_args": True,
        "var_types": ["addr"],
    },
    
    "tod_send_legacy": {
        "description": "Transaction Order Dependence - winner gets send (Solidity <0.5)",
        "vuln_type": "TOD",
        "min_version": "0.4.11",
        "max_version": "0.4.99",
        "state": "address {var_addr};",
        "setter": "{var_addr} = {input_param};",
        "setter_condition": None,
        "executor": "{var_addr}.send(msg.value);",
        "requires_payable_executor": True,
        "setter_needs_args": True,
        "var_types": ["addr"],
    },
    
    "tod_send": {
        "description": "Transaction Order Dependence - winner gets send (Solidity >=0.5)",
        "vuln_type": "TOD",
        "min_version": "0.5.0",
        "max_version": "0.9.99",
        "state": "address payable {var_addr};",
        "setter": "{var_addr} = address(uint160({input_param}));",
        "setter_condition": None,
        "executor": "{var_addr}.send(msg.value);",
        "requires_payable_executor": True,
        "setter_needs_args": True,
        "var_types": ["addr"],
    },
    
    "tod_call_04x": {
        "description": "Transaction Order Dependence - call.value (Solidity 0.4.x)",
        "vuln_type": "TOD",
        "min_version": "0.4.11",
        "max_version": "0.4.99",
        "state": "address {var_addr};",
        "setter": "{var_addr} = {input_param};",
        "setter_condition": None,
        "executor": "require({var_addr}.call.value(msg.value)(\"\"));",
        "requires_payable_executor": True,
        "setter_needs_args": True,
        "var_types": ["addr"],
    },
    
    "tod_call_legacy": {
        "description": "Transaction Order Dependence - call.value (Solidity 0.5-0.6)",
        "vuln_type": "TOD",
        "min_version": "0.5.0",
        "max_version": "0.6.99",
        "state": "address payable {var_addr};",
        "setter": "{var_addr} = address(uint160({input_param}));",
        "setter_condition": None,
        "executor": "(bool success, ) = {var_addr}.call.value(msg.value)(\"\");\n{indent}require(success);",
        "requires_payable_executor": True,
        "setter_needs_args": True,
        "var_types": ["addr"],
    },
    
    "tod_call_modern": {
        "description": "Transaction Order Dependence - call{{value:}} (Solidity >=0.7)",
        "vuln_type": "TOD",
        "min_version": "0.7.0",
        "max_version": "0.9.99",
        "state": "address payable {var_addr};",
        "setter": "{var_addr} = payable({input_param});",
        "setter_condition": None,
        "executor": "(bool success, ) = {var_addr}.call{value: msg.value}(\"\");\n{indent}require(success);",
        "requires_payable_executor": True,
        "setter_needs_args": True,
        "var_types": ["addr"],
    },
    
    # Access Control vulnerability - missing authorization check
    "access_control_owner": {
        "description": "Access Control - unprotected owner change",
        "vuln_type": "ACCESS_CONTROL",
        "min_version": "0.4.11",
        "max_version": "0.9.99",
        "state": "address {var_addr};",
        "setter": "{var_addr} = {input_param};",
        "setter_condition": None,
        "executor": "require(msg.sender == {var_addr});",
        "requires_payable_executor": False,
        "setter_needs_args": True,
        "var_types": ["addr"],
    },
    
    # Timestamp Dependence combined with cross-function
    "timestamp_unlock": {
        "description": "Timestamp Dependence - block.timestamp based unlock",
        "vuln_type": "TIMESTAMP",
        "min_version": "0.4.11",
        "max_version": "0.9.99",
        "state": "uint256 {var_time};\n    address payable {var_addr};",
        "setter": "{var_time} = block.timestamp + 1 days;\n{indent}{var_addr} = msg.sender;",
        "setter_condition": None,
        "executor": "require(block.timestamp >= {var_time});\n{indent}{var_addr}.transfer(msg.value);",
        "requires_payable_executor": True,
        "setter_needs_args": True,
        "var_types": ["addr", "time"],
    },
    
    # Denial of Service - external call in loop pattern
    "dos_refund_legacy": {
        "description": "Denial of Service - refund pattern with external call (Solidity <0.5)",
        "vuln_type": "DOS",
        "min_version": "0.4.11",
        "max_version": "0.4.99",
        "state": "address[] {var_array};\n    mapping(address => uint256) {var_mapping};",
        "setter": "{var_array}.push({input_param});\n{indent}{var_mapping}[{input_param}] = msg.value;",
        "setter_condition": None,
        "executor": "for(uint i = 0; i < {var_array}.length; i++) {{\n{indent}    {var_array}[i].transfer({var_mapping}[{var_array}[i]]);\n{indent}}}",
        "requires_payable_executor": False,
        "setter_needs_args": True,
        "var_types": ["array", "mapping", "addr"],
    },
    
    "dos_refund_050": {
        "description": "Denial of Service - refund pattern with external call (Solidity 0.5.x)",
        "vuln_type": "DOS",
        "min_version": "0.5.0",
        "max_version": "0.5.99",
        "state": "address payable[] {var_array};\n    mapping(address => uint256) {var_mapping};",
        "setter": "{var_array}.push(address(uint160({input_param})));\n{indent}{var_mapping}[{input_param}] = msg.value;",
        "setter_condition": None,
        "executor": "for(uint i = 0; i < {var_array}.length; i++) {{\n{indent}    {var_array}[i].transfer({var_mapping}[{var_array}[i]]);\n{indent}}}",
        "requires_payable_executor": False,
        "needs_payable_setter": True,
        "setter_needs_args": True,
        "var_types": ["array", "mapping", "addr"],
    },
    
    "dos_refund": {
        "description": "Denial of Service - refund pattern with external call (Solidity >=0.6)",
        "vuln_type": "DOS",
        "min_version": "0.6.0",
        "max_version": "0.9.99",
        "state": "address payable[] {var_array};\n    mapping(address => uint256) {var_mapping};",
        "setter": "{var_array}.push(payable({input_param}));\n{indent}{var_mapping}[{input_param}] = msg.value;",
        "setter_condition": None,
        "executor": "for(uint i = 0; i < {var_array}.length; i++) {{\n{indent}    {var_array}[i].transfer({var_mapping}[{var_array}[i]]);\n{indent}}}",
        "requires_payable_executor": False,
        "setter_needs_args": True,
        "var_types": ["array", "mapping", "addr"],
    },
    
    # Simple reentrancy-like pattern across functions
    "state_update_after_call": {
        "description": "State update after external call pattern",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.11",
        "max_version": "0.4.99",
        "state": "mapping(address => uint256) {var_mapping};\n    address {var_addr};",
        "setter": "{var_mapping}[msg.sender] = msg.value;\n{indent}{var_addr} = msg.sender;",
        "setter_condition": None,
        "executor": "uint256 amount = {var_mapping}[msg.sender];\n{indent}{var_addr}.call.value(amount)(\"\");\n{indent}{var_mapping}[msg.sender] = 0;",
        "requires_payable_executor": False,
        "setter_needs_args": False,
        "var_types": ["addr", "mapping"],
    },
}


# ============================================================================
# REENTRANCY COUPLED TEMPLATES (from point_injection.py)
# ============================================================================

REENTRANCY_COUPLED_TEMPLATES = {
    "reentrancy_call_check": {
        "description": "Reentrancy with conditional success check",
        "vuln_type": "REENTRANCY",
        "min_version": "0.5.0",
        "max_version": "0.6.99",
        "injection_type": "coupled",
        "state": "mapping(address => uint256) {var_mapping};",
        "setter": "{var_mapping}[msg.sender] = msg.value;",
        "executor": "(bool success,) = msg.sender.call.value({var_mapping}[msg.sender])(\"\");\n{indent}if (success)\n{indent}    {var_mapping}[msg.sender] = 0;",
        "needs_payable_setter": True,
        "var_types": ["mapping"],
    },
    
    "reentrancy_send_check": {
        "description": "Reentrancy with send success check",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.11",
        "max_version": "0.9.99",
        "injection_type": "coupled",
        "state": "mapping(address => uint256) {var_mapping};",
        "setter": "{var_mapping}[msg.sender] = msg.value;",
        "executor": "if (msg.sender.send({var_mapping}[msg.sender]))\n{indent}    {var_mapping}[msg.sender] = 0;",
        "needs_payable_setter": True,
        "var_types": ["mapping"],
    },
    
    "reentrancy_require_send": {
        "description": "Reentrancy with require(send)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.11",
        "max_version": "0.9.99",
        "injection_type": "coupled",
        "state": "mapping(address => uint256) {var_mapping};",
        "setter": "{var_mapping}[msg.sender] = msg.value;",
        "executor": "require(msg.sender.send({var_mapping}[msg.sender]));\n{indent}{var_mapping}[msg.sender] = 0;",        "needs_payable_setter": True,        "var_types": ["mapping"],
    },
    
    "reentrancy_bool_guard": {
        "description": "Reentrancy with boolean guard (flawed)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.11",
        "max_version": "0.9.99",
        "injection_type": "coupled",
        "state": "bool {var_bool} = true;",
        "setter": "{var_bool} = true;",
        "executor": ("require({var_bool});\n"
                     "{indent}if (!msg.sender.send(1 ether)) {\n"
                     "{indent}    revert();\n"
                     "{indent}}\n"
                     "{indent}{var_bool} = false;"),
        "var_types": ["bool"],
    },
    
    "reentrancy_jackpot": {
        "description": "Jackpot-style reentrancy",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.11",
        "max_version": "0.9.99",
        "injection_type": "coupled",
        "state": "address payable {var_addr};\n    uint256 {var_uint};",
        "setter": "{var_addr} = msg.sender;\n{indent}{var_uint} = {input_param};",
        "executor": "if ({var_addr}.send({var_uint})) {\n{indent}    {var_uint} = 0;\n{indent}}",
        "var_types": ["addr", "uint"],
        "needs_uint_param": True,
    },
    
    "logging_reentrancy_04x": {
        "description": "Reentrancy with external logging (PERSONAL_BANK pattern, Solidity 0.4.x)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.11",
        "max_version": "0.4.99",
        "injection_type": "coupled",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "address {var_addr};"),
        "setter": "{var_addr} = {input_param};",
        "executor": ("if ({var_mapping}[msg.sender] > 0) {\n"
                     "{indent}    uint256 _amount = {var_mapping}[msg.sender];\n"
                     "{indent}    if (msg.sender.call.value(_amount)()) {\n"
                     "{indent}        {var_mapping}[msg.sender] = 0;\n"
                     "{indent}        {var_addr}.call(bytes4(keccak256(\"AddMessage(address,uint256,string)\")), msg.sender, _amount, \"Withdrawal\");\n"
                     "{indent}    }\n"
                     "{indent}}"),
        "var_types": ["mapping", "addr"],
        "needs_addr_param": True,
    },
    
    "logging_reentrancy_modern": {
        "description": "Reentrancy with external logging (PERSONAL_BANK pattern, Solidity 0.7+)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.7.0",
        "max_version": "0.9.99",
        "injection_type": "coupled",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "address {var_addr};"),
        "setter": "{var_addr} = {input_param};",
        "executor": ("if ({var_mapping}[msg.sender] > 0) {\n"
                     "{indent}    uint256 _amount = {var_mapping}[msg.sender];\n"
                     "{indent}    (bool success,) = payable(msg.sender).call{value: _amount}(\"\");\n"
                     "{indent}    if (success) {\n"
                     "{indent}        {var_mapping}[msg.sender] = 0;\n"
                     "{indent}        (bool logSuccess,) = {var_addr}.call(abi.encodeWithSignature(\"AddMessage(address,uint256,string)\", msg.sender, _amount, \"Withdrawal\"));\n"
                     "{indent}        require(logSuccess);\n"
                     "{indent}    }\n"
                     "{indent}}"),
        "var_types": ["mapping", "addr"],
        "needs_addr_param": True,
    },
    
    "min_balance_reentrancy": {
        "description": "Reentrancy with minimum balance check (PERSONAL_BANK pattern)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.7.0",
        "max_version": "0.9.99",
        "injection_type": "coupled",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "uint256 {var_uint} = 0.1 ether;"),
        "setter": "{var_uint} = {input_param};",
        "executor": ("if ({var_mapping}[msg.sender] >= {var_uint}) {\n"
                     "{indent}    uint256 withdrawAmount = {var_mapping}[msg.sender];\n"
                     "{indent}    (bool success,) = msg.sender.call{value: withdrawAmount}(\"\");\n"
                     "{indent}    if (success) {\n"
                     "{indent}        {var_mapping}[msg.sender] = 0;\n"
                     "{indent}    }\n"
                     "{indent}}"),
        "var_types": ["mapping", "uint"],
        "needs_uint_param": True,
    },
    
    "cross_function_reentrancy_04x": {
        "description": "Cross-function reentrancy - withdraw and transfer share same mapping (Sereum: Cross-Function, Solidity 0.4.x)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.4.0",
        "max_version": "0.4.99",
        "injection_type": "coupled",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function transfer_{var_mapping}(address _to, uint256 _amount) public {\n"
                  "{indent}    require({var_mapping}[msg.sender] >= _amount);\n"
                  "{indent}    {var_mapping}[_to] += _amount;\n"
                  "{indent}    {var_mapping}[msg.sender] -= _amount;\n"
                  "{indent}}"),
        "setter": "{var_mapping}[msg.sender] += msg.value;",
        "executor": ("uint256 _bal = {var_mapping}[msg.sender];\n"
                     "{indent}if (_bal > 0) {\n"
                     "{indent}    require(msg.sender.call.value(_bal)());\n"
                     "{indent}    {var_mapping}[msg.sender] = 0;\n"
                     "{indent}}"),
        "needs_payable_setter": True,
        "var_types": ["mapping"],
    },

    "cross_function_reentrancy_legacy": {
        "description": "Cross-function reentrancy - withdraw and transfer share same mapping (Sereum: Cross-Function, Solidity 0.5-0.6)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.5.0",
        "max_version": "0.6.99",
        "injection_type": "coupled",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function transfer_{var_mapping}(address _to, uint256 _amount) public {\n"
                  "{indent}    require({var_mapping}[msg.sender] >= _amount);\n"
                  "{indent}    {var_mapping}[_to] += _amount;\n"
                  "{indent}    {var_mapping}[msg.sender] -= _amount;\n"
                  "{indent}}"),
        "setter": "{var_mapping}[msg.sender] += msg.value;",
        "executor": ("uint256 _bal = {var_mapping}[msg.sender];\n"
                     "{indent}if (_bal > 0) {\n"
                     "{indent}    (bool _ok,) = msg.sender.call.value(_bal)(\"\");\n"
                     "{indent}    require(_ok);\n"
                     "{indent}    {var_mapping}[msg.sender] = 0;\n"
                     "{indent}}"),
        "needs_payable_setter": True,
        "var_types": ["mapping"],
    },

    "cross_function_reentrancy": {
        "description": "Cross-function reentrancy - withdraw and transfer share same mapping (Sereum: Cross-Function, Solidity >=0.7)",
        "vuln_type": "REENTRANCY",
        "min_version": "0.7.0",
        "max_version": "0.9.99",
        "injection_type": "coupled",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function transfer_{var_mapping}(address _to, uint256 _amount) public {\n"
                  "{indent}    require({var_mapping}[msg.sender] >= _amount);\n"
                  "{indent}    {var_mapping}[_to] += _amount;\n"
                  "{indent}    {var_mapping}[msg.sender] -= _amount;\n"
                  "{indent}}"),
        "setter": "{var_mapping}[msg.sender] += msg.value;",
        "executor": ("uint256 _bal = {var_mapping}[msg.sender];\n"
                     "{indent}if (_bal > 0) {\n"
                     "{indent}    (bool _ok,) = msg.sender.call{value: _bal}(\"\");\n"
                     "{indent}    require(_ok);\n"
                     "{indent}    {var_mapping}[msg.sender] = 0;\n"
                     "{indent}}"),
        "needs_payable_setter": True,
        "var_types": ["mapping"],
    },
}


# ============================================================================
# OVERFLOW/TIMESTAMP COUPLED TEMPLATES (from point_injection.py)
# ============================================================================

OTHER_COUPLED_TEMPLATES = {
    "lock_time_overflow": {
        "description": "Lock time overflow pattern",
        "vuln_type": "OVERFLOW",
        "min_version": "0.4.11",
        "max_version": "0.7.99",
        "injection_type": "coupled",
        "state": "mapping(address => uint256) {var_time};",
        "setter": "{var_time}[msg.sender] += {input_param};",
        "executor": "require(block.timestamp > {var_time}[msg.sender]);",
        "var_types": ["time"],
        "needs_uint_param": True,
    },
    
    "timestamp_winner": {
        "description": "Winner selection based on timestamp",
        "vuln_type": "TIMESTAMP",
        "min_version": "0.4.11",
        "max_version": "0.9.99",
        "injection_type": "coupled",
        "state": "address {var_addr};",
        "setter": ("if ({input_param} + (5 * 1 days) == block.timestamp) {\n"
                   "{indent}    {var_addr} = msg.sender;\n"
                   "{indent}}"),
        "executor": "require(msg.sender == {var_addr});",
        "var_types": ["addr"],
        "needs_uint_param": True,
    },
}


# ============================================================================
# AGGREGATE ALL COUPLED TEMPLATES
# ============================================================================

ALL_COUPLED_TEMPLATES = {
    **CROSS_FUNCTION_TEMPLATES,
    **REENTRANCY_COUPLED_TEMPLATES,
    **OTHER_COUPLED_TEMPLATES,
}


# Empty - no comments to avoid ML exploitation
COUPLED_BENIGN = {
    "state_comments": [],
    "setter_comments": [],
    "executor_comments": [],
}
