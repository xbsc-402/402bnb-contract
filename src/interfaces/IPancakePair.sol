// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IPancakePair
/// @notice Interface for PancakeSwap V2 Pair (LP Token)
/// @dev Pairs are ERC20 tokens that represent liquidity pool shares
interface IPancakePair {
    /// @notice Emitted on every mint (liquidity addition)
    event Mint(address indexed sender, uint256 amount0, uint256 amount1);

    /// @notice Emitted on every burn (liquidity removal)
    event Burn(address indexed sender, uint256 amount0, uint256 amount1, address indexed to);

    /// @notice Emitted on every swap
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );

    /// @notice Emitted when reserves are synced
    event Sync(uint112 reserve0, uint112 reserve1);

    /// @notice Returns the address of token0
    function token0() external view returns (address);

    /// @notice Returns the address of token1
    function token1() external view returns (address);

    /// @notice Returns the reserves and last block timestamp
    /// @return reserve0 Reserve of token0
    /// @return reserve1 Reserve of token1
    /// @return blockTimestampLast Last block timestamp when reserves were updated
    function getReserves()
        external
        view
        returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);

    /// @notice Returns the total supply of LP tokens
    function totalSupply() external view returns (uint256);

    /// @notice Returns the balance of LP tokens for an account
    /// @param owner Address to query
    function balanceOf(address owner) external view returns (uint256);

    /// @notice Minimum liquidity that is permanently locked
    function MINIMUM_LIQUIDITY() external pure returns (uint256);

    /// @notice Returns the factory address
    function factory() external view returns (address);

    /// @notice Price cumulative values for TWAP oracles
    function price0CumulativeLast() external view returns (uint256);
    function price1CumulativeLast() external view returns (uint256);

    /// @notice Returns the kLast value (used for protocol fee calculation)
    function kLast() external view returns (uint256);
}
