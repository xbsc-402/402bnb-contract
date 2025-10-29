// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title LPTokenTimelock - Simple LP Token Locking Contract
/// @notice Locks PancakeSwap LP tokens for a specified duration (402 days)
/// @dev Based on OpenZeppelin's TokenTimelock pattern, simplified for LP tokens
/// @dev Used by X402Token contracts to ensure long-term liquidity commitment
contract LPTokenTimelock is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice The LP token being locked
    IERC20 public immutable lpToken;

    /// @notice Beneficiary who can withdraw LP tokens after lock period
    address public immutable beneficiary;

    /// @notice Timestamp when tokens become withdrawable
    uint256 public immutable releaseTime;

    /// @notice Lock duration in seconds (402 days = 402 * 24 * 60 * 60)
    uint256 public constant LOCK_DURATION = 402 days;

    /// @notice Emitted when tokens are released to beneficiary
    event TokensReleased(uint256 amount);

    /// @notice Error thrown when tokens are still locked
    error TokensStillLocked(uint256 currentTime, uint256 releaseTime);

    /// @notice Error thrown when no tokens to release
    error NoTokensToRelease();

    /// @dev Constructor parameters are immutable for security and gas optimization
    /// @param lpToken_ The PancakeSwap LP token address
    /// @param beneficiary_ Address that can withdraw tokens after lock period
    /// @param releaseTime_ Optional custom release time, defaults to 402 days from deployment
    constructor(
        address lpToken_,
        address beneficiary_,
        uint256 releaseTime_
    ) {
        require(lpToken_ != address(0), "LPTokenTimelock: LP token is zero address");
        require(beneficiary_ != address(0), "LPTokenTimelock: beneficiary is zero address");

        // If releaseTime_ is 0, use default 402 days from now
        if (releaseTime_ == 0) {
            releaseTime_ = block.timestamp + LOCK_DURATION;
        } else {
            require(releaseTime_ > block.timestamp, "LPTokenTimelock: release time is before current time");
        }

        lpToken = IERC20(lpToken_);
        beneficiary = beneficiary_;
        releaseTime = releaseTime_;
    }

    /// @notice Release the LP tokens to the beneficiary after lock period
    /// @dev Only callable after releaseTime has passed
    /// @dev Uses nonReentrant for security
    /// @dev SafeERC20 prevents silent failures
    function release() external nonReentrant {
        // CHECKS: Validate time constraint
        if (block.timestamp < releaseTime) {
            revert TokensStillLocked(block.timestamp, releaseTime);
        }

        // EFFECTS: Calculate amount to release
        uint256 amount = lpToken.balanceOf(address(this));
        if (amount == 0) {
            revert NoTokensToRelease();
        }

        emit TokensReleased(amount);

        // INTERACTIONS: Transfer tokens to beneficiary
        lpToken.safeTransfer(beneficiary, amount);
    }

    /// @notice Returns the current timestamp
    /// @dev Useful for frontend integration to check lock status
    /// @return Current block timestamp
    function currentTime() external view returns (uint256) {
        return block.timestamp;
    }

    /// @notice Returns the remaining lock time in seconds
    /// @dev Returns 0 if tokens are already unlocked
    /// @return Remaining lock time in seconds
    function remainingLockTime() external view returns (uint256) {
        if (block.timestamp >= releaseTime) {
            return 0;
        }
        return releaseTime - block.timestamp;
    }

    /// @notice Returns the locked token balance
    /// @dev Current balance of LP tokens held by this timelock contract
    /// @return Amount of LP tokens currently locked
    function lockedBalance() external view returns (uint256) {
        return lpToken.balanceOf(address(this));
    }

    /// @notice Check if tokens are unlocked
    /// @dev Returns true if current time is at or after releaseTime
    /// @return True if tokens can be released, false otherwise
    function isUnlocked() external view returns (bool) {
        return block.timestamp >= releaseTime;
    }

    /// @notice Returns contract information as a struct
    /// @dev Useful for batch operations and frontend display
    /// @return lpTokenAddress Address of the locked LP token
    /// @return beneficiaryAddress Address that can receive tokens
    /// @return releaseTimestamp When tokens become withdrawable
    /// @return balance Current locked token amount
    /// @return unlocked Whether tokens are currently unlocked
    function getInfo() external view returns (
        address lpTokenAddress,
        address beneficiaryAddress,
        uint256 releaseTimestamp,
        uint256 balance,
        bool unlocked
    ) {
        return (
            address(lpToken),
            beneficiary,
            releaseTime,
            lpToken.balanceOf(address(this)),
            block.timestamp >= releaseTime
        );
    }
}