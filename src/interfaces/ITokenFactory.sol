// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title ITokenFactory
/// @notice Interface for TokenFactory verification
interface ITokenFactory {
    /// @notice Check if an address is a token created by this factory
    /// @param token Address to check
    /// @return True if token was created by factory
    function isFactoryToken(address token) external view returns (bool);
}
