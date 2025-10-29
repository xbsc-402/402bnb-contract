// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPancakeRouter02} from "./IPancakeRouter02.sol";

/// @title IX402Token
/// @notice Interface for X402Token contract with standardized economics
/// @dev All tokens use fixed parameters: 1B supply, 40K per mint, 20K mints, 200M pool seed
interface IX402Token {
    /// @notice Initializes the token contract (called by factory after cloning)
    /// @param name Token name
    /// @param symbol Token symbol
    /// @param initialOwner Address that will own the token (project creator)
    /// @param minter Address that will have MINTER_ROLE (USD4 wrapped USDT contract)
    /// @param router PancakeSwap V2 Router address
    /// @param paymentToken Payment token address (USDC/BUSD or wUSDT wrapper)
    /// @param underlyingToken Underlying token for LP (e.g., USDT when using wUSDT wrapper, or address(0) if not using wrapper)
    /// @dev Economics parameters are hardcoded in the implementation
    function initialize(
        string memory name,
        string memory symbol,
        address initialOwner,
        address minter,
        IPancakeRouter02 router,
        address paymentToken,
        address underlyingToken
    ) external;

    /// @notice Returns the token name
    function name() external view returns (string memory);

    /// @notice Returns the token symbol
    function symbol() external view returns (string memory);

    /// @notice Returns the current mint count
    function mintCount() external view returns (uint256);

    /// @notice Returns the maximum mint count
    function maxMintCount() external view returns (uint256);

    /// @notice Returns whether liquidity has been deployed
    function liquidityDeployed() external view returns (bool);

    /// @notice Returns the LP token (pair) address
    function lpToken() external view returns (address);

    /// @notice Returns the deployment deadline (24 hours after token creation)
    function deploymentDeadline() external view returns (uint256);

    /// @notice Withdraws accumulated transaction fees to TokenFactory
    /// @dev Only callable by TokenFactory contract
    function withdrawFees() external;

    /// @notice Withdraws accumulated refund fees to TokenFactory
    /// @dev Only callable by TokenFactory contract
    function withdrawRefundFees() external;

    /// @notice Allows users to refund their tokens if deployment fails
    /// @dev Only available after deadline if liquidity not deployed
    function refund() external;

    /// @notice Withdraws excess payment tokens
    /// @dev Only callable by token owner (project creator)
    /// @return excessAmount Amount withdrawn
    function withdrawExcessPayment() external returns (uint256 excessAmount);

    /// @notice Advanced batch mint with variable mint counts per address
    /// @param to Array of addresses to mint tokens to
    /// @param mintCounts Array of mint counts for each address
    /// @param txHashes Array of unique transaction hashes
    /// @dev Each address receives mintCounts[i] * MINT_AMOUNT tokens
    /// @dev Requires MINTER_ROLE
    function ai_batchMint(
        address[] memory to,
        uint256[] memory mintCounts,
        bytes32[] memory txHashes
    ) external;
}
