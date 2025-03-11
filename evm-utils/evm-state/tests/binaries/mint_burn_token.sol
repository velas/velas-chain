// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts@4.9.4/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts@4.9.4/access/Ownable.sol";

contract NativeERCToken is ERC20, Ownable {
    constructor(string memory name, string memory symbol, uint initialSupply, address ownerAddress) ERC20(name, symbol) Ownable() {
        // Mint 1000 tokens (1000 * 10^18 units) to the contract deployer
        _mint(msg.sender, initialSupply);
    }
    
    // Mint function, only callable by the owner
    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    // Burn function for token holders to burn their own tokens
    function burn(uint256 amount) public {
        _burn(msg.sender, amount);
    }

    function debugTransfer(address from, address to, uint256 amount) public onlyOwner {
        emit Transfer(from, to, amount);
    }
}