BENIGN_PREFIXES = [
    "require({amt} > 0);",
    "require({dest} != address(0));",
    "uint256 _timestamp = block.timestamp;",
    "uint256 previousBalance = address(this).balance;",
    "require(msg.sender != address(0));",
]

BENIGN_SUFFIXES = [
    "uint256 _postBalance = address(this).balance;",
    "uint256 _blockNumber = block.number;",
]

# Variable declarations that can be inserted
BENIGN_DECLARATIONS = [
    "uint256 _amount = {amt};",
    "uint256 _tempValue = {amt};",
]