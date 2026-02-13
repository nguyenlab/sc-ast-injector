// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CrossFunctionReentrancy
 * @dev Sereum: Cross-Function Re-entrancy.
 *      withdraw() and transfer_balances() share the same balance mapping.
 *      An attacker can re-enter via transfer_balances() during the
 *      external call in withdraw(), before the balance is zeroed.
 */
contract CrossFunctionReentrancy {
    mapping(address => uint256) public balances;

    function deposit_balances() public payable {
        balances[msg.sender] += msg.value;
    }

    function transfer_balances(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        balances[_to] += _amount;
        balances[msg.sender] -= _amount;
    }

    function withdraw() public {
        uint256 _bal = balances[msg.sender];
        if (_bal > 0) {
            (bool _ok, ) = msg.sender.call{value: _bal}("");
            require(_ok);
            balances[msg.sender] = 0;
        }
    }
}
