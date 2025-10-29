// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title IPancakeRouter02
/// @notice Interface for PancakeSwap V2 Router
interface IPancakeRouter02 {
    /// @notice Returns the factory address
    function factory() external pure returns (address);

    /// @notice Returns the WETH address
    function WETH() external pure returns (address);

    /// @notice Adds liquidity to a pool
    /// @param tokenA Address of token A
    /// @param tokenB Address of token B
    /// @param amountADesired Desired amount of token A
    /// @param amountBDesired Desired amount of token B
    /// @param amountAMin Minimum amount of token A
    /// @param amountBMin Minimum amount of token B
    /// @param to Address to receive LP tokens
    /// @param deadline Transaction deadline
    /// @return amountA Actual amount of token A added
    /// @return amountB Actual amount of token B added
    /// @return liquidity Amount of LP tokens minted
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB, uint256 liquidity);

    /// @notice Removes liquidity from a pool
    /// @param tokenA Address of token A
    /// @param tokenB Address of token B
    /// @param liquidity Amount of LP tokens to burn
    /// @param amountAMin Minimum amount of token A to receive
    /// @param amountBMin Minimum amount of token B to receive
    /// @param to Address to receive tokens
    /// @param deadline Transaction deadline
    /// @return amountA Amount of token A received
    /// @return amountB Amount of token B received
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB);

    /// @notice Swaps exact tokens for tokens
    /// @param amountIn Amount of input tokens
    /// @param amountOutMin Minimum amount of output tokens
    /// @param path Array of token addresses for the swap path
    /// @param to Address to receive output tokens
    /// @param deadline Transaction deadline
    /// @return amounts Array of amounts for each step in the path
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    /// @notice Get amounts out for a given input amount
    /// @param amountIn Input amount
    /// @param path Swap path
    /// @return amounts Array of output amounts
    function getAmountsOut(uint256 amountIn, address[] calldata path)
        external
        view
        returns (uint256[] memory amounts);
}
