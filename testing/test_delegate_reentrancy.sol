// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DelegateReentrancy
 * @dev Sereum: Delegated Re-entrancy.
 *      State update occurs AFTER delegatecall returns, allowing the
 *      delegated library to trigger re-entrancy before balance is zeroed.
 */
contract DelegateReentrancy {
    address public impl_lib;
    mapping(address => uint256) public balances;

    function setLib_balances(address _lib) public {
        impl_lib = _lib;
    }

    function deposit_balances() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 _amt = balances[msg.sender];
        if (_amt > 0) {
            (bool success, ) = impl_lib.delegatecall(
                abi.encodeWithSignature("sendEth(address,uint256)", msg.sender, _amt)
            );
            require(success, "Delegatecall failed");
            balances[msg.sender] = 0;
        }
    }
}
