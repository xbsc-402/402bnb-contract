// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IWrappedUSDT
/// @notice Interface for EIP-3009 compatible USDT wrapper
/// @dev Used by X402Token to unwrap payment tokens before LP deployment
interface IWrappedUSDT {
    /// @notice Withdraw USDT by burning wUSDT (1:1 minus fees)
    /// @param amount Amount of wUSDT to burn
    /// @return usdtAmount Amount of USDT returned (after fees)
    function withdraw(uint256 amount) external returns (uint256 usdtAmount);

    /// @notice Withdraw for auto-mint flow (no reentrancy guard)
    /// @dev Used by X402Token during _deployLiquidity to avoid reentrancy conflicts
    /// @param amount Amount of wUSDT to burn
    /// @return usdtAmount Amount of USDT returned (after fees)
    function withdrawForAutoMint(uint256 amount) external returns (uint256 usdtAmount);
}
