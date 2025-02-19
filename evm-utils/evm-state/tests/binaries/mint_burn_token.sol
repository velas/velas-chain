// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

// import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
// import "@openzeppelin/contracts/access/Ownable.sol";

// !!! This contract used _ONLY_ for testing, do not use it in production !!!

contract MintBurnToken // is ERC20, Ownable 
{
    // constructor(string memory name, string memory symbol, address initialOwner) ERC20(name, symbol) Ownable(initialOwner) {}
    event Transfer(address indexed from, address indexed to, uint256 value);

    function _mint(address account, uint256 amount) private {
        emit Transfer(0x0000000000000000000000000000000000000000, account, amount);
    }
    function _burn(uint256 amount) private {
        emit Transfer(msg.sender, 0x0000000000000000000000000000000000000000, amount);
    }

    function mint(address account, uint256 amount) external // onlyOwner
    {
        _mint(account, amount);
    }

    // function adminBurn(address account, uint256 amount) external onlyOwner
    // {
    //     emit Transfer(account, 0, amount)
    // }

    function burn(uint256 amount) public {
        _burn(amount);
    }
}