// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockERC20
/// @notice Simple ERC20 token for testing purposes
/// @dev Initial supply is minted to deployer, designed as USDT replacement
contract MockERC20 is ERC20 {
    uint8 private _decimals;

    /// @notice Constructor that mints initial supply to deployer
    /// @param name Token name
    /// @param symbol Token symbol
    /// @param decimals_ Number of decimals (typically 6 for USDT-like tokens)
    /// @param initialSupply Initial supply to mint to deployer (in token units with decimals)
    constructor(
        string memory name,
        string memory symbol,
        uint8 decimals_,
        uint256 initialSupply
    ) ERC20(name, symbol) {
        _decimals = decimals_;

        // Mint initial supply to deployer (msg.sender)
        if (initialSupply > 0) {
            _mint(msg.sender, initialSupply);
        }
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }

    /// @notice Mint tokens (kept for testing flexibility)
    /// @param to Recipient address
    /// @param amount Amount to mint
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// @notice Burn tokens (kept for testing flexibility)
    /// @param from Address to burn from
    /// @param amount Amount to burn
    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}
