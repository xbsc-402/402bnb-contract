// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ITokenFactory} from "./interfaces/ITokenFactory.sol";
import {IX402Token} from "./interfaces/IX402Token.sol";

/// @title WrappedUSDT
/// @notice EIP-3009 compatible wrapper for USDT on BSC
/// @dev Allows 1:1 wrapping of USDT into wUSDT with EIP-3009 gasless transfer support
/// @dev Enables x402 protocol payments on BSC using USDT as the underlying asset
/// @dev Decentralized design - anyone can wrap/unwrap freely
///
/// @custom:deployment-pattern UUPS Upgradeable Proxy
/// @custom:security-note This contract uses UUPS proxy pattern for upgradeability
/// @custom:security-note Storage layout must be preserved across upgrades
/// @custom:security-note Only owner can authorize upgrades via _authorizeUpgrade
contract WrappedUSDT is 
    ERC20Upgradeable, 
    OwnableUpgradeable, 
    ReentrancyGuardUpgradeable, 
    EIP712Upgradeable,
    UUPSUpgradeable 
{
    using SafeERC20 for IERC20;

    // ==================== Constants ====================

    /// @notice EIP-3009 typehash for transferWithAuthorization
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    /// @notice EIP-3009 typehash for receiveWithAuthorization
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    /// @notice EIP-3009 typehash for cancelAuthorization
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    /// @notice Maximum fee: 5% (500 basis points)
    uint256 public constant MAX_FEE_BPS = 500;

    /// @notice Basis points denominator (10000 = 100%)
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Decimal scaling factor (18 - 6 = 12 zeros)
    /// @dev wUSDT uses 6 decimals (compact format), USDT uses 18 decimals (BSC standard)
    /// @dev 1 USDT (10^18 units) = 1 wUSDT (10^6 units)
    uint256 private constant DECIMAL_SCALE = 10**12;

    // ==================== State Variables ====================

    /// @notice Contract version for upgrade tracking
    string public constant VERSION = "1.0.0";

    /// @notice The underlying USDT token (changed from immutable to support UUPS)
    /// @dev CRITICAL: This must remain in slot 0 of custom storage to maintain compatibility
    IERC20 public underlyingToken;

    /// @notice TokenFactory address for verifying X402Token contracts
    ITokenFactory public tokenFactory;

    /// @notice Deposit fee in basis points (e.g., 0 = 0%, 100 = 1%, 500 = 5%)
    uint256 public depositFeeBps;

    /// @notice Withdraw fee in basis points
    uint256 public withdrawFeeBps;

    /// @notice Total fees collected (in USDT, 18 decimals)
    uint256 public totalFeesCollected;

    /// @notice Total dust collected from precision loss (in USDT, 18 decimals)
    uint256 public totalDustCollected;

    /// @notice Mapping to track individual user's dust balance (in USDT, 18 decimals)
    /// @dev user => dust amount
    mapping(address => uint256) public userDust;

    /// @notice Mapping of nonce states for EIP-3009
    /// @dev authorizer => nonce => used
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    /// @dev Storage gap for future upgrades (reserve 50 slots)
    /// @dev Subtract slots already used: underlyingToken(1) + tokenFactory(1) + depositFeeBps(1) 
    ///      + withdrawFeeBps(1) + totalFeesCollected(1) + totalDustCollected(1) + userDust(1) 
    ///      + _authorizationStates(1) = 8 slots used
    /// @dev Gap = 50 - 8 = 42 slots reserved
    uint256[42] private __gap;

    // ==================== Events ====================

    event Deposited(address indexed user, uint256 usdtAmount, uint256 wusdtAmount, uint256 fee, uint256 dust);
    event Withdrawn(address indexed user, uint256 wusdtAmount, uint256 usdtAmount, uint256 fee);
    event DepositFeeUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event WithdrawFeeUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event FeesWithdrawn(address indexed recipient, uint256 amount);
    event DustCollected(address indexed user, uint256 amount);
    event DustWithdrawn(address indexed recipient, uint256 amount);

    // EIP-3009 events
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    // X402 integration events
    event AutoMintTriggered(address indexed token, address indexed recipient, uint256 mintCount, bytes32 txHash);
    event TokenFactoryUpdated(address indexed oldFactory, address indexed newFactory);

    // Upgrade events
    event Upgraded(address indexed implementation, string version);

    // ==================== Errors ====================

    error InvalidAmount();
    error InsufficientBalance();
    error FeeTooHigh();
    error InvalidRecipient(address to, address expected);
    error AuthorizationStateInvalid(address authorizer, bytes32 nonce);
    error AuthorizationExpired(uint256 validBefore, uint256 currentTime);
    error AuthorizationNotYetValid(uint256 validAfter, uint256 currentTime);
    error InvalidSigner(address recovered, address expected);
    error InvalidX402Token(address token);
    error MintCountReached(address token);
    error AutoMintFailed(address token, string reason);

    // ==================== Constructor ====================

    /// @notice Constructor disables initializers for the implementation contract
    /// @dev This prevents the implementation contract from being initialized
    /// @dev Only proxy instances can be initialized
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract (UUPS proxy pattern)
    /// @param _underlyingToken Address of the underlying USDT token
    /// @param _owner Contract owner
    /// @dev This can only be called once (initializer modifier)
    function initialize(address _underlyingToken, address _owner) external initializer {
        require(_underlyingToken != address(0), "WrappedUSDT: underlying token cannot be zero address");
        require(_owner != address(0), "WrappedUSDT: owner cannot be zero address");

        // Set underlying token (now stored in state, not immutable)
        underlyingToken = IERC20(_underlyingToken);

        // Initialize inherited contracts
        __ERC20_init("USD4", "USD4");
        __Ownable_init(_owner);
        __ReentrancyGuard_init();
        __EIP712_init("USD4", "1");
        __UUPSUpgradeable_init();

        // Initial fees are 0
        depositFeeBps = 0;
        withdrawFeeBps = 0;
    }

    /// @notice Returns the number of decimals used by the token
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    // ==================== Core Wrapper Functions ====================

    /// @notice Deposit USDT and receive wUSDT (1:1 value minus fees)
    /// @param amount Amount of USDT to deposit (18 decimals)
    /// @return wusdtAmount Amount of wUSDT minted (6 decimals, after fees)
    /// @dev Process:
    ///      1. Deduct deposit fee (if any)
    ///      2. Transfer USDT from user to contract
    ///      3. Scale down from 18 to 6 decimals
    ///      4. Track precision loss (dust) for user
    ///      5. Mint wUSDT to user
    /// @dev Precision loss (dust) is tracked per user and can be withdrawn by owner
    /// @dev Minimum deposit: 10^12 USDT (0.000001 USDT) to mint at least 1 wUSDT unit
    function deposit(uint256 amount) external nonReentrant returns (uint256 wusdtAmount) {
        if (amount == 0) revert InvalidAmount();

        // Calculate fee (in USDT units, 18 decimals)
        uint256 fee = (amount * depositFeeBps) / BPS_DENOMINATOR;
        uint256 usdtAfterFee = amount - fee;

        // Update fee accounting (keep in USDT units, 18 decimals)
        if (fee > 0) {
            totalFeesCollected += fee;
        }

        // Transfer USDT from user (18 decimals)
        underlyingToken.safeTransferFrom(msg.sender, address(this), amount);

        // Scale down to wUSDT (6 decimals): divide by 10^12
        wusdtAmount = usdtAfterFee / DECIMAL_SCALE;

        // Calculate dust (precision loss)
        uint256 dust = usdtAfterFee % DECIMAL_SCALE;

        // Track dust for user
        if (dust > 0) {
            userDust[msg.sender] += dust;
            totalDustCollected += dust;
            emit DustCollected(msg.sender, dust);
        }

        // Prevent precision loss: ensure user is depositing at least 1 unit of wUSDT
        // Minimum: 10^12 USDT (0.000001 USDT) = 1 wUSDT unit (0.000001 wUSDT)
        if (wusdtAmount == 0) revert InvalidAmount();

        // Mint wUSDT to user (6 decimals)
        _mint(msg.sender, wusdtAmount);

        emit Deposited(msg.sender, amount, wusdtAmount, fee, dust);
    }

    /// @notice Withdraw USDT by burning wUSDT (1:1 value minus fees)
    /// @param amount Amount of wUSDT to burn (6 decimals)
    /// @return usdtAmount Amount of USDT returned (18 decimals, after fees)
    /// @dev Process:
    ///      1. Burn user's wUSDT
    ///      2. Scale up from 6 to 18 decimals
    ///      3. Deduct withdraw fee (if any)
    ///      4. Transfer USDT to user
    /// @dev No precision loss on withdrawal (scaling 6→18 is exact)
    function withdraw(uint256 amount) external nonReentrant returns (uint256 usdtAmount) {
        return _withdraw(msg.sender, amount);
    }

    /// @notice Internal withdraw logic without reentrancy guard
    /// @dev Used by both public withdraw() and internal auto-mint flow
    /// @param account Address to burn wUSDT from and send USDT to
    /// @param amount Amount of wUSDT to burn
    /// @return usdtAmount Amount of USDT returned
    function _withdraw(address account, uint256 amount) internal returns (uint256 usdtAmount) {
        if (amount == 0) revert InvalidAmount();
        if (balanceOf(account) < amount) revert InsufficientBalance();

        // Burn wUSDT (6 decimals)
        _burn(account, amount);

        // Scale up to USDT units (18 decimals): multiply by 10^12
        uint256 usdtEquivalent = amount * DECIMAL_SCALE;

        // Calculate fee (in USDT units, 18 decimals)
        uint256 fee = (usdtEquivalent * withdrawFeeBps) / BPS_DENOMINATOR;
        usdtAmount = usdtEquivalent - fee;

        // Update fee accounting (in USDT units, 18 decimals)
        if (fee > 0) {
            totalFeesCollected += fee;
        }

        // Transfer USDT to recipient (18 decimals)
        underlyingToken.safeTransfer(account, usdtAmount);

        emit Withdrawn(account, amount, usdtAmount, fee);
    }

    /// @notice Withdraw wUSDT to USDT for auto-mint flow (no reentrancy guard)
    /// @dev Called by X402Token during liquidity deployment
    /// @dev No reentrancy guard because caller is already protected by transferWithAuthorization's guard
    /// @dev Only callable by factory-verified X402Tokens
    /// @param amount Amount of wUSDT to withdraw
    /// @return usdtAmount Amount of USDT returned
    function withdrawForAutoMint(uint256 amount) external returns (uint256 usdtAmount) {
        // Verify caller is a factory-created token
        if (address(tokenFactory) == address(0)) revert InvalidX402Token(msg.sender);
        if (!tokenFactory.isFactoryToken(msg.sender)) revert InvalidX402Token(msg.sender);

        // Use internal withdraw (no reentrancy guard)
        return _withdraw(msg.sender, amount);
    }

    // ==================== EIP-3009 Functions ====================

    /// @notice Execute a transfer with a signed authorization (gasless transfer)
    /// @param from Payer's address
    /// @param to Payee's address (can be X402Token contract)
    /// @param value Amount to transfer (in wUSDT, 6 decimals)
    /// @param validAfter Authorization valid after this timestamp (exclusive)
    /// @param validBefore Authorization valid before this timestamp (exclusive)
    /// @param nonce Unique nonce to prevent replay
    /// @param v Signature recovery id
    /// @param r Signature r component
    /// @param s Signature s component
    /// @dev If `to` is a verified X402Token contract, automatically mints tokens for `from`
    /// @dev Auto-mint logic:
    ///      1. Verify `to` is a factory-created X402Token
    ///      2. Check if token's mintCount < maxMintCount
    ///      3. Calculate mint count: value / PAYMENT_PER_MINT (10 wUSDT)
    ///      4. Call token's ai_batchMint to mint tokens for `from`
    ///      5. Revert if token already reached max mint count
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        // ===== CHECKS =====
        _validateTimeframe(validAfter, validBefore);
        _requireUnusedAuthorization(from, nonce);

        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        _requireValidSignature(from, structHash, v, r, s);

        // ===== EFFECTS =====
        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        // ===== INTERACTIONS =====
        _transfer(from, to, value);

        // ===== X402 AUTO-MINT LOGIC (AFTER TRANSFER!) =====
        // NOTE: Transfer must happen first so X402Token has wUSDT balance
        // X402Token needs wUSDT to call withdrawForAutoMint() during ai_batchMint
        // If auto-mint fails, entire transaction still reverts (atomicity guaranteed)
        if (address(tokenFactory) != address(0)) {
            // Check if `to` is a factory-created token
            if (tokenFactory.isFactoryToken(to)) {
                _handleAutoMint(from, to, value, nonce);
            }
        }
    }

    /// @notice Receive a transfer with a signed authorization (front-running protection)
    /// @dev Only msg.sender can call this for themselves (to = msg.sender)
    /// @param from Payer's address
    /// @param to Payee's address (must be msg.sender)
    /// @param value Amount to transfer
    /// @param validAfter Authorization valid after this timestamp (exclusive)
    /// @param validBefore Authorization valid before this timestamp (exclusive)
    /// @param nonce Unique nonce to prevent replay
    /// @param v Signature recovery id
    /// @param r Signature r component
    /// @param s Signature s component
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        if (to != msg.sender) revert InvalidRecipient(to, msg.sender);

        _validateTimeframe(validAfter, validBefore);
        _requireUnusedAuthorization(from, nonce);

        bytes32 structHash = keccak256(
            abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        _requireValidSignature(from, structHash, v, r, s);

        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        _transfer(from, to, value);
    }

    /// @notice Cancel an unused authorization
    /// @param authorizer Authorizer's address
    /// @param nonce Nonce to cancel
    /// @param v Signature recovery id
    /// @param r Signature r component
    /// @param s Signature s component
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)
        external
        nonReentrant
    {
        _requireUnusedAuthorization(authorizer, nonce);

        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce));
        _requireValidSignature(authorizer, structHash, v, r, s);

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    /// @notice Check if an authorization has been used
    /// @param authorizer Authorizer's address
    /// @param nonce Nonce to check
    /// @return True if used, false otherwise
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    // ==================== X402 Auto-Mint Internal Logic ====================

    /// @dev Handle automatic minting for X402Token contracts
    /// @param from Payer address (will receive minted tokens)
    /// @param token X402Token contract address
    /// @param value Amount of wUSDT being transferred (6 decimals)
    /// @param nonce Authorization nonce (used to generate unique txHash)
    /// @dev This function is called within transferWithAuthorization after signature verification
    /// @dev Requires: WrappedUSDT contract must have MINTER_ROLE on the token
    /// @dev Setup: After creating X402Token, project owner must run:
    ///      x402Token.grantRole(MINTER_ROLE, address(wrappedUSDT))
    function _handleAutoMint(address from, address token, uint256 value, bytes32 nonce) internal {
        IX402Token x402Token = IX402Token(token);

        // 1. Check current mint status
        uint256 currentMintCount = x402Token.mintCount();
        uint256 maxMintCount = x402Token.maxMintCount();

        // Revert if token already reached max mint count
        if (currentMintCount >= maxMintCount) {
            revert MintCountReached(token);
        }

        // 2. Calculate how many mints this payment represents
        // PAYMENT_PER_MINT = 10 * 10^6 (10 wUSDT with 6 decimals)
        // Example: value = 50 * 10^6 → mintCount = 5 mints
        uint256 PAYMENT_PER_MINT = 10 * 10**6; // 10 wUSDT

        // ⚠️ CRITICAL: Validate payment is exact multiple to prevent user fund loss
        // Without this check: user pays 25 wUSDT → gets 2 mints (20 wUSDT) → loses 5 wUSDT
        if (value % PAYMENT_PER_MINT != 0) {
            revert InvalidAmount(); // "Payment must be multiple of 10 wUSDT"
        }

        uint256 userMintCount = value / PAYMENT_PER_MINT;

        // Must mint at least 1 (guaranteed by modulo check above, but keep for clarity)
        if (userMintCount == 0) {
            revert InvalidAmount();
        }

        // 3. Ensure we don't exceed max mint count
        if (currentMintCount + userMintCount > maxMintCount) {
            revert MintCountReached(token);
        }

        // 4. Generate unique txHash for this mint
        // nonce is already unique and verified by EIP-3009, so we include it with context
        bytes32 txHash = keccak256(
            abi.encodePacked(
                from,
                token,
                value,
                nonce,
                block.timestamp,
                block.number
            )
        );

        // 5. Call ai_batchMint with single recipient
        // ai_batchMint(address[] to, uint256[] mintCounts, bytes32[] txHashes)
        address[] memory recipients = new address[](1);
        recipients[0] = from;

        uint256[] memory mintCounts = new uint256[](1);
        mintCounts[0] = userMintCount;

        bytes32[] memory txHashes = new bytes32[](1);
        txHashes[0] = txHash;

        // This will revert if:
        // - WrappedUSDT doesn't have MINTER_ROLE
        // - txHash already used
        // - Minting period expired
        // - Liquidity already deployed
        try x402Token.ai_batchMint(recipients, mintCounts, txHashes) {
            emit AutoMintTriggered(token, from, userMintCount, txHash);
        } catch Error(string memory reason) {
            revert AutoMintFailed(token, reason);
        } catch {
            revert AutoMintFailed(token, "Unknown error");
        }
    }

    // ==================== EIP-3009 Internal Helpers ====================

    /// @dev Validate that the current time is within the authorization time window
    /// @dev Time window is EXCLUSIVE on both ends: validAfter < now < validBefore
    /// @param validAfter Authorization valid after this timestamp (exclusive)
    /// @param validBefore Authorization valid before this timestamp (exclusive)
    function _validateTimeframe(uint256 validAfter, uint256 validBefore) internal view {
        uint256 nowTs = block.timestamp;

        // Time window is EXCLUSIVE on both ends: validAfter < now < validBefore
        if (nowTs <= validAfter) revert AuthorizationNotYetValid(validAfter, nowTs);
        if (nowTs >= validBefore) revert AuthorizationExpired(validBefore, nowTs);
    }

    /// @dev Require that an authorization has not been used yet
    /// @param authorizer Authorizer's address
    /// @param nonce Nonce to check
    function _requireUnusedAuthorization(address authorizer, bytes32 nonce) internal view {
        if (_authorizationStates[authorizer][nonce]) {
            revert AuthorizationStateInvalid(authorizer, nonce);
        }
    }

    /// @dev Validate EIP-712 signature
    /// @param expectedSigner Expected signer's address
    /// @param structHash Hash of the struct to sign
    /// @param v Signature recovery id
    /// @param r Signature r component
    /// @param s Signature s component
    function _requireValidSignature(address expectedSigner, bytes32 structHash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
    {
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, v, r, s);
        if (signer != expectedSigner) revert InvalidSigner(signer, expectedSigner);
    }

    // ==================== Fee Management (Owner Only) ====================

    /// @notice Update deposit fee
    /// @param newFeeBps New fee in basis points (max 5%)
    function setDepositFee(uint256 newFeeBps) external onlyOwner {
        if (newFeeBps > MAX_FEE_BPS) revert FeeTooHigh();

        uint256 oldFeeBps = depositFeeBps;
        depositFeeBps = newFeeBps;

        emit DepositFeeUpdated(oldFeeBps, newFeeBps);
    }

    /// @notice Update withdraw fee
    /// @param newFeeBps New fee in basis points (max 5%)
    function setWithdrawFee(uint256 newFeeBps) external onlyOwner {
        if (newFeeBps > MAX_FEE_BPS) revert FeeTooHigh();

        uint256 oldFeeBps = withdrawFeeBps;
        withdrawFeeBps = newFeeBps;

        emit WithdrawFeeUpdated(oldFeeBps, newFeeBps);
    }

    /// @notice Withdraw collected fees
    /// @param recipient Address to receive fees
    function withdrawFees(address recipient) external onlyOwner nonReentrant {
        uint256 amount = totalFeesCollected;
        if (amount == 0) revert InvalidAmount();

        totalFeesCollected = 0;

        underlyingToken.safeTransfer(recipient, amount);

        emit FeesWithdrawn(recipient, amount);
    }

    /// @notice Withdraw all accumulated dust (admin only)
    /// @dev Only owner can withdraw dust collected from all users
    /// @param recipient Address to receive the dust as USDT
    function withdrawDust(address recipient) external onlyOwner nonReentrant {
        uint256 amount = totalDustCollected;
        if (amount == 0) revert InvalidAmount();

        // Reset total dust collected
        totalDustCollected = 0;

        // Transfer dust as USDT to recipient
        underlyingToken.safeTransfer(recipient, amount);

        emit DustWithdrawn(recipient, amount);
    }

    /// @notice Get total dust information
    /// @return totalDust Total dust collected from all users (18 decimals)
    /// @return userCount Number of users with dust balance
    function getDustInfo() external view returns (uint256 totalDust, uint256 userCount) {
        totalDust = totalDustCollected;
        // Note: userCount would require iteration through all users, which is not gas-efficient
        // For production, consider using events or off-chain tracking for user count
        userCount = 0; // Placeholder
    }

    /// @notice Withdraw all fees and dust in one transaction
    /// @param recipient Address to receive fees and dust
    /// @return totalAmount Total amount withdrawn (fees + dust)
    function withdrawAllCollected(address recipient) external onlyOwner nonReentrant returns (uint256 totalAmount) {
        uint256 fees = totalFeesCollected;
        uint256 dust = totalDustCollected;
        totalAmount = fees + dust;

        if (totalAmount == 0) revert InvalidAmount();

        // Reset both counters
        totalFeesCollected = 0;
        totalDustCollected = 0;

        // Transfer combined amount
        underlyingToken.safeTransfer(recipient, totalAmount);

        // Emit separate events for transparency
        if (fees > 0) {
            emit FeesWithdrawn(recipient, fees);
        }
        if (dust > 0) {
            emit DustWithdrawn(recipient, dust);
        }
    }

    /// @notice Set TokenFactory address for X402 integration
    /// @param _tokenFactory Address of the TokenFactory contract
    /// @dev Only owner can set this
    function setTokenFactory(address _tokenFactory) external onlyOwner {
        address oldFactory = address(tokenFactory);
        tokenFactory = ITokenFactory(_tokenFactory);
        emit TokenFactoryUpdated(oldFactory, _tokenFactory);
    }

    // ==================== View Functions ====================

    /// @notice Get total USDT backing the wUSDT supply (excluding fees and dust)
    /// @dev Calculation: USDT balance - totalFeesCollected - totalDustCollected
    /// @dev Should approximately equal: totalSupply() * DECIMAL_SCALE
    /// @return Total USDT reserves available for redemption (18 decimals)
    function totalReserves() external view returns (uint256) {
        return underlyingToken.balanceOf(address(this)) - totalFeesCollected - totalDustCollected;
    }

    /// @notice Calculate deposit output (amount of wUSDT minted for USDT input)
    /// @param usdtAmount Amount of USDT to deposit (18 decimals)
    /// @return wusdtAmount Amount of wUSDT that would be minted (6 decimals)
    /// @return fee Fee that would be charged (18 decimals USDT)
    /// @return dust Precision loss that would be collected (18 decimals USDT)
    function previewDeposit(uint256 usdtAmount) external view returns (uint256 wusdtAmount, uint256 fee, uint256 dust) {
        fee = (usdtAmount * depositFeeBps) / BPS_DENOMINATOR;
        uint256 usdtAfterFee = usdtAmount - fee;
        wusdtAmount = usdtAfterFee / DECIMAL_SCALE;  // Scale to 6 decimals
        dust = usdtAfterFee % DECIMAL_SCALE;  // Calculate precision loss
    }

    /// @notice Calculate withdraw output (amount of USDT returned for wUSDT input)
    /// @param wusdtAmount Amount of wUSDT to burn (6 decimals)
    /// @return usdtAmount Amount of USDT that would be returned (18 decimals)
    /// @return fee Fee that would be charged (18 decimals USDT)
    function previewWithdraw(uint256 wusdtAmount) external view returns (uint256 usdtAmount, uint256 fee) {
        uint256 usdtEquivalent = wusdtAmount * DECIMAL_SCALE;  // Scale to 18 decimals
        fee = (usdtEquivalent * withdrawFeeBps) / BPS_DENOMINATOR;
        usdtAmount = usdtEquivalent - fee;
    }

    // ==================== UUPS Upgrade Authorization ====================

    /// @notice Authorize an upgrade to a new implementation
    /// @param newImplementation Address of the new implementation contract
    /// @dev Only owner can authorize upgrades
    /// @dev This is called by upgradeTo() and upgradeToAndCall()
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        emit Upgraded(newImplementation, VERSION);
    }

    /// @notice Get the current implementation address
    /// @return impl Address of the current implementation
    /// @dev This is useful for verifying which implementation is active
    function getImplementation() external view returns (address impl) {
        // Access the implementation slot defined in ERC1967Upgrade
        bytes32 slot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        assembly {
            impl := sload(slot)
        }
    }
}
