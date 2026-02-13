// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CreateReentrancy
 * @dev Sereum: Create-Based Re-entrancy.
 *      Constructor makes an external call sending ETH before state is
 *      finalized. The withdraw function also has state update after call.
 */
contract CreateReentrancy {
    mapping(address => uint256) public deposits;
    bool public isReady_initialized;

    constructor() payable {
        deposits[msg.sender] = msg.value;
        (bool _ok, ) = msg.sender.call{value: address(this).balance}("");
        require(_ok);
        isReady_initialized = true;
    }

    function withdraw() public {
        uint256 _credit = deposits[msg.sender];
        if (_credit > 0) {
            (bool _ok, ) = msg.sender.call{value: _credit}("");
            require(_ok);
            deposits[msg.sender] = 0;
        }
    }
}
