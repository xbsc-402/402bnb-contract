// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IPancakeFactory
/// @notice Interface for PancakeSwap V2 Factory
interface IPancakeFactory {
    /// @notice Emitted when a new pair is created
    event PairCreated(address indexed token0, address indexed token1, address pair, uint256);

    /// @notice Returns the address of the pair for tokenA and tokenB, if it exists
    /// @param tokenA Address of token A
    /// @param tokenB Address of token B
    /// @return pair Address of the pair (returns address(0) if pair doesn't exist)
    function getPair(address tokenA, address tokenB) external view returns (address pair);

    /// @notice Creates a new pair for tokenA and tokenB
    /// @param tokenA Address of token A
    /// @param tokenB Address of token B
    /// @return pair Address of the newly created pair
    function createPair(address tokenA, address tokenB) external returns (address pair);

    /// @notice Returns the total number of pairs created
    function allPairsLength() external view returns (uint256);

    /// @notice Returns the address of the pair at the given index
    /// @param index Index in the pairs array
    function allPairs(uint256 index) external view returns (address pair);

    /// @notice Returns the address that receives protocol fees
    function feeTo() external view returns (address);

    /// @notice Returns the address that can set feeTo
    function feeToSetter() external view returns (address);
}
