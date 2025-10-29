// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title MockRouter
/// @notice Mock PancakeSwap V2 Router for testing
contract MockRouter {
    address public immutable factory;
    address public immutable WETH;

    constructor(address _factory, address _weth) {
        factory = _factory;
        WETH = _weth;
    }

    // Mock implementation of addLiquidity
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB, uint256 liquidity) {
        // Mock return values
        return (amountADesired, amountBDesired, amountADesired + amountBDesired);
    }

    // Mock implementation of removeLiquidity
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB) {
        // Mock return values
        return (liquidity / 2, liquidity / 2);
    }
}

/// @title MockFactory
/// @notice Mock PancakeSwap V2 Factory for testing
contract MockFactory {
    mapping(address => mapping(address => address)) public getPair;
    address[] public allPairs;

    function createPair(address tokenA, address tokenB) external returns (address pair) {
        // Create a deterministic address for testing
        pair = address(uint160(uint256(keccak256(abi.encodePacked(tokenA, tokenB)))));
        getPair[tokenA][tokenB] = pair;
        getPair[tokenB][tokenA] = pair;
        allPairs.push(pair);
        return pair;
    }

    function allPairsLength() external view returns (uint) {
        return allPairs.length;
    }
}
