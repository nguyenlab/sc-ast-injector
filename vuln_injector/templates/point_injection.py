import random

# ============================================================================
# VARIABLE NAME POOLS (Stealthy - no vulnerability markers)
# ============================================================================

UINT_VAR_NAMES = [
    "amount", "value", "balance", "total", "count", "limit",
    "threshold", "allocation", "deposit", "fee", "reward",
]

ADDR_VAR_NAMES = [
    "recipient", "sender", "account", "target", "destination",
    "beneficiary", "payee", "delegate", "handler", "controller",
]

MAPPING_VAR_NAMES = [
    "balances", "deposits", "allocations", "credits", "amounts",
    "userBalances", "accountValues", "pendingPayouts", "reserves",
]

BOOL_VAR_NAMES = [
    "isActive", "isEnabled", "isValid", "isProcessed", "isComplete",
    "hasExecuted", "canWithdraw", "isAuthorized", "isLocked",
]

TIME_VAR_NAMES = [
    "lockTime", "releaseTime", "expirationTime", "deadline",
    "cooldownEnd", "unlockTime", "scheduledTime", "activeUntil",
]

# Domain-specific variable pools (Quick Win Enhancement)
BANKING_UINT_NAMES = [
    "MinSum", "minBalance", "minimumDeposit", "withdrawalLimit",
    "dailyLimit", "accountMinimum", "requiredBalance", "lockAmount",
]

CONTRACT_REF_NAMES = [
    "LogFile", "TransferLog", "EventLogger", "AuditContract",
    "Treasury", "VaultContract", "ControllerAddress", "RegistryContract",
]

GAME_UINT_NAMES = [
    "jackpot", "prize", "pot", "winnings", "stake", "wager",
    "betAmount", "poolBalance", "rewardPool",
]

TOKEN_UINT_NAMES = [
    "totalSupply", "allowance", "burnAmount", "mintAmount",
    "transferAmount", "batchValue", "tokenBalance",
]


def get_random_uint_var(context="generic"):
    if context == "banking":
        return random.choice(BANKING_UINT_NAMES + UINT_VAR_NAMES)
    elif context == "game":
        return random.choice(GAME_UINT_NAMES + UINT_VAR_NAMES)
    elif context == "token":
        return random.choice(TOKEN_UINT_NAMES + UINT_VAR_NAMES)
    return random.choice(UINT_VAR_NAMES)

def get_random_addr_var():
    return random.choice(ADDR_VAR_NAMES)

def get_random_mapping_var():
    return random.choice(MAPPING_VAR_NAMES)

def get_random_bool_var():
    return random.choice(BOOL_VAR_NAMES)

def get_random_time_var():
    return random.choice(TIME_VAR_NAMES)


def generate_unique_name(generator_func, existing_names: set, max_attempts: int = 50) -> str:
    for _ in range(max_attempts):
        name = generator_func()
        if name not in existing_names:
            return name
    base_name = generator_func()
    return f"{base_name}{random.randint(1, 999)}"


# ============================================================================
# OVERFLOW / UNDERFLOW TEMPLATES (Pre-Solidity 0.8)
# ============================================================================

OVERFLOW_TEMPLATES = {
    "addition_overflow": {
        "description": "Integer overflow in addition with user input",
        "vuln_type": "OVERFLOW",
        "min_version": "0.4.0",
        "max_version": "0.7.99",  # 0.8+ has built-in overflow checks
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function set_{var_mapping}(uint256 _val) public {\n"
                  "{indent}    {var_mapping}[msg.sender] = _val;\n"
                  "{indent}}"),
        "code": "{var_mapping}[msg.sender] = {var_mapping}[msg.sender] + {uint_param};",
        "var_types": ["mapping"],
        "needs_uint_param": True,
    },
    
    "addition_overflow_input": {
        "description": "Integer overflow in addition with direct input",
        "vuln_type": "OVERFLOW",
        "min_version": "0.4.0",
        "max_version": "0.7.99",
        "injection_type": "point",
        "state": "uint256 {var_uint};",
        "code": "{var_uint} = {var_uint} + 1;",
        "var_types": ["uint"],
    },
    
    "subtraction_underflow": {
        "description": "Integer underflow in subtraction",
        "vuln_type": "UNDERFLOW",
        "min_version": "0.4.0",
        "max_version": "0.7.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function set_{var_mapping}(uint256 _val) public {\n"
                  "{indent}    {var_mapping}[msg.sender] = _val;\n"
                  "{indent}}"),
        "code": "{var_mapping}[msg.sender] = {var_mapping}[msg.sender] - {uint_param};",
        "var_types": ["mapping"],
        "needs_uint_param": True,
    },
    
    "multiplication_overflow": {
        "description": "Integer overflow in multiplication",
        "vuln_type": "OVERFLOW",
        "min_version": "0.4.0",
        "max_version": "0.7.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function set_{var_mapping}(uint256 _val) public {\n"
                  "{indent}    {var_mapping}[msg.sender] = _val;\n"
                  "{indent}}"),
        "code": "{var_mapping}[msg.sender] = {var_mapping}[msg.sender] * {uint_param};",
        "var_types": ["mapping"],
        "needs_uint_param": True,
    },
    
    "uint8_overflow": {
        "description": "Small integer overflow (uint8)",
        "vuln_type": "OVERFLOW",
        "min_version": "0.4.0",
        "max_version": "0.7.99",
        "injection_type": "point",
        "state": "uint8 {var_uint} = 255;",
        "code": "{var_uint} = {var_uint} + 1;",
        "var_types": ["uint"],
    },
    
    "transfer_underflow": {
        "description": "Underflow in balance transfer",
        "vuln_type": "UNDERFLOW",
        "min_version": "0.4.0",
        "max_version": "0.7.99",
        "injection_type": "point",
        "state": ("mapping(address => uint256) {var_mapping};\n"
                  "{indent}function deposit_{var_mapping}() public payable {\n"
                  "{indent}    {var_mapping}[msg.sender] += msg.value;\n"
                  "{indent}}"),
        "code": "{var_mapping}[msg.sender] = {var_mapping}[msg.sender] - {uint_param};",
        "var_types": ["mapping"],
        "needs_uint_param": True,
    },
}


# ============================================================================
# BATCH TRANSFER OVERFLOW TEMPLATES (Quick Win Enhancement)
# ============================================================================

BATCH_TRANSFER_OVERFLOW = {
    "batch_transfer_overflow": {
        "description": "Batch transfer multiplication overflow (BECToken pattern)",
        "vuln_type": "OVERFLOW",
        "min_version": "0.4.0",
        "max_version": "0.7.99",
        "injection_type": "point",
        "state": "mapping(address => uint256) {var_mapping};",
        "code": ("function batchTransfer_{var_mapping}(address[] memory _receivers, uint256 _value) public {\n"
                 "{indent}    uint cnt = _receivers.length;\n"
                 "{indent}    uint256 amount = uint256(cnt) * _value;\n"
                 "{indent}    require(cnt > 0 && cnt <= 20);\n"
                 "{indent}    require(_value > 0 && {var_mapping}[msg.sender] >= amount);\n"
                 "{indent}    {var_mapping}[msg.sender] -= amount;\n"
                 "{indent}    for (uint i = 0; i < cnt; i++) {\n"
                 "{indent}        {var_mapping}[_receivers[i]] += _value;\n"
                 "{indent}    }\n"
                 "{indent}}"),
        "var_types": ["mapping"],
    },
    
    "safemath_present_not_used": {
        "description": "SafeMath library present but NOT used (realistic BECToken pattern)",
        "vuln_type": "OVERFLOW",
        "min_version": "0.4.0",
        "max_version": "0.7.99",
        "injection_type": "point",
        "state": ("library SafeMath {\n"
                  "{indent}    function add(uint256 a, uint256 b) internal pure returns (uint256) {\n"
                  "{indent}        uint256 c = a + b;\n"
                  "{indent}        require(c >= a);\n"
                  "{indent}        return c;\n"
                  "{indent}    }\n"
                  "{indent}}\n"
                  "{indent}mapping(address => uint256) {var_mapping};\n"
                  "{indent}using SafeMath for uint256;  // DECLARED but NOT USED!"),
        "code": "{var_mapping}[msg.sender] = {var_mapping}[msg.sender] + {uint_param};  // NOT using .add()!",
        "var_types": ["mapping"],
        "needs_uint_param": True,
    },
}


# ============================================================================
# TX.ORIGIN AUTHENTICATION TEMPLATES
# ============================================================================

TX_ORIGIN_TEMPLATES = {
    "tx_origin_auth": {
        "description": "Authentication using tx.origin",
        "vuln_type": "TX_ORIGIN",
        "min_version": "0.4.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": "address {var_addr};",
        "code": "require(tx.origin == {var_addr});",
        "var_types": ["addr"],
    },
    
    "tx_origin_transfer": {
        "description": "Transfer protected by tx.origin (legacy)",
        "vuln_type": "TX_ORIGIN",
        "min_version": "0.4.0",
        "max_version": "0.4.99",
        "injection_type": "point",
        "state": "address {var_addr};",
        "code": "require(tx.origin == {var_addr});\n{indent}msg.sender.transfer(address(this).balance);",
        "var_types": ["addr"],
    },
    
    "tx_origin_transfer_050": {
        "description": "Transfer protected by tx.origin (0.5.x)",
        "vuln_type": "TX_ORIGIN",
        "min_version": "0.5.0",
        "max_version": "0.5.99",
        "injection_type": "point",
        "state": "address {var_addr};",
        "code": "require(tx.origin == {var_addr});\n{indent}msg.sender.transfer(address(this).balance);",
        "var_types": ["addr"],
    },
    
    "tx_origin_transfer_060": {
        "description": "Transfer protected by tx.origin (0.6+)",
        "vuln_type": "TX_ORIGIN",
        "min_version": "0.6.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": "address {var_addr};",
        "code": "require(tx.origin == {var_addr});\n{indent}payable(msg.sender).transfer(address(this).balance);",
        "var_types": ["addr"],
    },
    
    "tx_origin_with_param": {
        "description": "tx.origin check with address parameter",
        "vuln_type": "TX_ORIGIN",
        "min_version": "0.4.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": None,
        "code": "require(tx.origin == {input_param});",
        "needs_addr_param": True,
        "var_types": [],
    },
}


# ============================================================================
# UNCHECKED SEND TEMPLATES
# ============================================================================

UNCHECKED_SEND_TEMPLATES = {
    # Legacy syntax for Solidity 0.4.x
    "unchecked_send_literal_legacy": {
        "description": "Unchecked send with literal amount (legacy)",
        "vuln_type": "UNCHECKED_SEND",
        "min_version": "0.4.0",
        "max_version": "0.5.99",
        "injection_type": "point",
        "state": None,
        "code": "msg.sender.send(1 ether);",
        "var_types": [],
        "needs_state_modifying": True,
    },
    
    # Modern syntax for Solidity 0.6+
    "unchecked_send_literal": {
        "description": "Unchecked send with literal amount",
        "vuln_type": "UNCHECKED_SEND",
        "min_version": "0.6.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": None,
        "code": "payable(msg.sender).send(1 ether);",
        "var_types": [],
        "needs_state_modifying": True,
    },
    
    # Legacy syntax for Solidity 0.4.x
    "unchecked_send_balance_legacy": {
        "description": "Unchecked send of contract balance (legacy)",
        "vuln_type": "UNCHECKED_SEND",
        "min_version": "0.4.0",
        "max_version": "0.5.99",
        "injection_type": "point",
        "state": None,
        "code": "msg.sender.send(address(this).balance);",
        "var_types": [],
        "needs_state_modifying": True,
    },
    
    # Modern syntax for Solidity 0.6+
    "unchecked_send_balance": {
        "description": "Unchecked send of contract balance",
        "vuln_type": "UNCHECKED_SEND",
        "min_version": "0.6.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": None,
        "code": "payable(msg.sender).send(address(this).balance);",
        "var_types": [],
        "needs_state_modifying": True,
    },
}


# ============================================================================
# UNHANDLED EXCEPTION TEMPLATES (Unchecked call return)
# ============================================================================

UNHANDLED_CALL_TEMPLATES = {
    # For Solidity 0.4.x - simple call.value syntax
    "unchecked_call_04x": {
        "description": "Unchecked call.value (Solidity 0.4.x)",
        "vuln_type": "UNHANDLED_EXCEPTION",
        "min_version": "0.4.0",
        "max_version": "0.4.99",
        "injection_type": "point",
        "state": "uint256 {var_uint} = 1 ether;",
        "code": "{input_param}.call.value({var_uint})();",
        "needs_addr_param": True,
        "var_types": ["uint"],
        "needs_state_modifying": True,
    },
    
    # For Solidity 0.5.x - need address payable
    "unchecked_call_05x": {
        "description": "Unchecked call.value (Solidity 0.5.x)",
        "vuln_type": "UNHANDLED_EXCEPTION",
        "min_version": "0.5.0",
        "max_version": "0.5.99",
        "injection_type": "point",
        "state": "uint256 {var_uint} = 1 ether;",
        "code": "address(uint160({input_param})).call.value({var_uint})(\"\");",
        "needs_addr_param": True,
        "var_types": ["uint"],
        "needs_state_modifying": True,
    },
    
    # For Solidity 0.6.x - payable() cast and call.value
    "unchecked_call_06x": {
        "description": "Unchecked call.value (Solidity 0.6.x)",
        "vuln_type": "UNHANDLED_EXCEPTION",
        "min_version": "0.6.0",
        "max_version": "0.6.99",
        "injection_type": "point",
        "state": "uint256 {var_uint} = 1 ether;",
        "code": "payable({input_param}).call{value: {var_uint}}(\"\");",
        "needs_addr_param": True,
        "var_types": ["uint"],
        "needs_state_modifying": True,
    },
    
    "unchecked_call_modern": {
        "description": "Unchecked call{value:} (Solidity >=0.7)",
        "vuln_type": "UNHANDLED_EXCEPTION",
        "min_version": "0.7.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": "uint256 {var_uint} = 1 ether;",
        "code": "payable({input_param}).call{value: {var_uint}}(\"\");",
        "needs_addr_param": True,
        "var_types": ["uint"],
        "needs_state_modifying": True,
    },
}


# ============================================================================
# TIMESTAMP DEPENDENCY TEMPLATES
# ============================================================================

TIMESTAMP_TEMPLATES = {
    "timestamp_comparison": {
        "description": "Comparison with block.timestamp",
        "vuln_type": "TIMESTAMP",
        "min_version": "0.4.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": "uint256 {var_uint};",
        "code": "require(block.timestamp >= {var_uint});",
        "var_types": ["uint"],
    },
    
    "timestamp_equality": {
        "description": "Equality check with block.timestamp (legacy)",
        "vuln_type": "TIMESTAMP",
        "min_version": "0.4.0",
        "max_version": "0.4.99",
        "injection_type": "point",
        "state": "uint256 {var_uint};",
        "code": ("if (block.timestamp == {var_uint}) {\n"
                 "{indent}    msg.sender.transfer(1 wei);\n"
                 "{indent}}"),
        "var_types": ["uint"],
        "needs_state_modifying": True,
    },
    
    "timestamp_equality_050": {
        "description": "Equality check with block.timestamp (0.5.x)",
        "vuln_type": "TIMESTAMP",
        "min_version": "0.5.0",
        "max_version": "0.5.99",
        "injection_type": "point",
        "state": "uint256 {var_uint};",
        "code": ("if (block.timestamp == {var_uint}) {\n"
                 "{indent}    msg.sender.transfer(1 wei);\n"
                 "{indent}}"),
        "var_types": ["uint"],
        "needs_state_modifying": True,
    },
    
    "timestamp_equality_060": {
        "description": "Equality check with block.timestamp (0.6+)",
        "vuln_type": "TIMESTAMP",
        "min_version": "0.6.0",
        "max_version": "0.9.99",
        "injection_type": "point",
        "state": "uint256 {var_uint};",
        "code": ("if (block.timestamp == {var_uint}) {\n"
                 "{indent}    payable(msg.sender).transfer(1 wei);\n"
                 "{indent}}"),
        "var_types": ["uint"],
        "needs_state_modifying": True,
    },
    
    "timestamp_storage": {
        "description": "Storing block.timestamp in state variable",
        "vuln_type": "TIMESTAMP",
        "min_version": "0.4.0",
        "max_version": "0.9.99",
        "injection_type": "state_only",
        "state": "uint256 {var_time} = block.timestamp;",
        "var_types": ["time"],
    },
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_var_names(var_types: list, existing_names: set = None) -> dict:
    if existing_names is None:
        existing_names = set()
    
    names = {}
    used = existing_names.copy()
    
    if "addr" in var_types:
        name = generate_unique_name(get_random_addr_var, used)
        names["var_addr"] = name
        used.add(name)
    if "uint" in var_types:
        name = generate_unique_name(get_random_uint_var, used)
        names["var_uint"] = name
        used.add(name)
    if "mapping" in var_types:
        name = generate_unique_name(get_random_mapping_var, used)
        names["var_mapping"] = name
        used.add(name)
    if "bool" in var_types:
        name = generate_unique_name(get_random_bool_var, used)
        names["var_bool"] = name
        used.add(name)
    if "time" in var_types:
        name = generate_unique_name(get_random_time_var, used)
        names["var_time"] = name
        used.add(name)
    
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


# Aggregate all point templates only (no coupled templates)
ALL_POINT_TEMPLATES = {
    **OVERFLOW_TEMPLATES,
    **BATCH_TRANSFER_OVERFLOW,
    **TX_ORIGIN_TEMPLATES,
    **UNCHECKED_SEND_TEMPLATES,
    **UNHANDLED_CALL_TEMPLATES,
    **{k: v for k, v in TIMESTAMP_TEMPLATES.items() if v.get("injection_type") != "coupled"},
}

# Templates organized by vulnerability type for easy access (point injection only)
TEMPLATES_BY_TYPE = {
    "OVERFLOW": {**{k: v for k, v in OVERFLOW_TEMPLATES.items() if v["vuln_type"] == "OVERFLOW" and v.get("injection_type") != "coupled"}, **BATCH_TRANSFER_OVERFLOW},
    "UNDERFLOW": {k: v for k, v in OVERFLOW_TEMPLATES.items() if v["vuln_type"] == "UNDERFLOW"},
    "TX_ORIGIN": TX_ORIGIN_TEMPLATES,
    "UNCHECKED_SEND": UNCHECKED_SEND_TEMPLATES,
    "UNHANDLED_EXCEPTION": UNHANDLED_CALL_TEMPLATES,
    "TIMESTAMP": {k: v for k, v in TIMESTAMP_TEMPLATES.items() if v.get("injection_type") != "coupled"},
}
