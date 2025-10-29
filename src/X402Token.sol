// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.4.0
pragma solidity ^0.8.26;

/// @title X402Token - EIP-3009 Compatible Token with Automated Liquidity
/// @notice Implements x402 protocol payments and automatic PancakeSwap liquidity deployment
/// @dev Uses EIP-1167 Clone pattern for gas-efficient deployment

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {ERC20BurnableUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IPancakeRouter02} from "./interfaces/IPancakeRouter02.sol";
import {IPancakeFactory} from "./interfaces/IPancakeFactory.sol";
import {IPancakePair} from "./interfaces/IPancakePair.sol";
import {IWrappedUSDT} from "./interfaces/IWrappedUSDT.sol";

contract X402Token is Initializable, ERC20Upgradeable, ERC20BurnableUpgradeable, OwnableUpgradeable, EIP712Upgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice The error thrown when the array length mismatch
    error ArrayLengthMismatch();
    /// @notice The error thrown when the tx hash has already been minted
    error AlreadyMinted(address to, bytes32 txHash);
    /// @notice The error thrown when the mint count exceeds the maximum mint count
    error MaxMintCountExceeded();
    /// @notice The error thrown when mint count is zero
    error InvalidMintCount();
    /// @notice The error thrown when total mints would exceed limit
    error TotalMintsExceeded(uint256 requested, uint256 remaining);

    // --- EIP-3009 specific errors ---
    error AuthorizationStateInvalid(address authorizer, bytes32 nonce); // used or canceled
    error AuthorizationExpired(uint256 nowTime, uint256 validBefore);
    error AuthorizationNotYetValid(uint256 nowTime, uint256 validAfter);
    error InvalidSigner(address signer, address expected);
    error InvalidRecipient(address to);

    // --- EIP-3009 events ---
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    // --- EIP-3009 typehashes (per spec) ---
    bytes32 private constant _TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 private constant _RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 private constant _CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    // --- EIP-3009 authorization state tracking ---
    // 0 = Unused, 1 = Used, 2 = Canceled
    mapping(address => mapping(bytes32 => uint8)) private _authorizationStates;

    // ==================== TOKENOMICS CONFIGURATION ====================
    //
    // CONFIGURATION PHILOSOPHY:
    // Single-parameter system where MAX_MINT_COUNT determines all economics.
    // All other parameters are derived via mathematical formulas to maintain consistent ratios.
    //
    // DEPLOYMENT MODES:
    // - Testing: MAX_MINT_COUNT = 20 (small scale for development/testing)
    // - Production: MAX_MINT_COUNT = 2,000 (full production deployment)
    //
    // FORMULA RELATIONSHIPS:
    //   User Tokens = MAX_MINT_COUNT × MINT_AMOUNT
    //   Pool Tokens = User Tokens / 4  (maintains 20% of total supply in LP)
    //   Total Supply = User Tokens + Pool Tokens = User Tokens × 1.25
    //   Min Balance = MAX_MINT_COUNT × PAYMENT_PER_MINT × 0.95 (5% slippage tolerance)
    //
    // EXAMPLE CALCULATIONS:
    //   Testing Mode (MAX_MINT_COUNT = 20):
    //     User Tokens: 20 × 400,000 = 8,000,000 tokens
    //     Pool Tokens: 8,000,000 / 4 = 2,000,000 tokens (20%)
    //     Total Supply: 10,000,000 tokens
    //     Min Payment: 20 × 10 × 0.95 = 190 USDT
    //
    //   Production Mode (MAX_MINT_COUNT = 2,000):
    //     User Tokens: 2,000 × 400,000 = 800,000,000 tokens
    //     Pool Tokens: 800,000,000 / 4 = 200,000,000 tokens (20%)
    //     Total Supply: 1,000,000,000 tokens
    //     Min Payment: 2,000 × 10 × 0.95 = 19,000 USDT
    //
    // SECURITY NOTE: Formulas ensure consistent tokenomics across all deployments.
    // ======================================================================

    /// @notice Maximum number of mint operations allowed
    /// @dev CONFIGURATION POINT: Change this value to switch between testing and production
    /// @dev Testing: 20 | Production: 2,000
    /// @dev This is the ONLY parameter that should be manually changed
    uint256 public constant MAX_MINT_COUNT = 2000;

    // ==================== FIXED BASE PARAMETERS ====================
    // These parameters remain constant across all deployment configurations.
    // They define the fundamental economic unit of the token system.
    // ==============================================================

    /// @notice Tokens minted per operation (400,000 tokens with 18 decimals)
    /// @dev Fixed exchange rate: 10 USDT = 400,000 tokens
    /// @dev This establishes the base price of 0.000025 USDT per token
    uint256 public constant MINT_AMOUNT = 400_000 * 10**18;

    /// @notice Payment required per mint operation (10 USDT with 6 decimals)
    /// @dev Fixed at 10 USDT per mint to maintain consistent pricing
    /// @dev Decimal precision: USDT wrapper uses 6 decimals
    uint256 public constant PAYMENT_PER_MINT = 10 * 10**6;

    // ==================== AUTO-CALCULATED PARAMETERS ====================
    // These functions compute derived values based on MAX_MINT_COUNT.
    // They maintain mathematical consistency across all economic parameters.
    // WARNING: Do not modify these formulas without updating all related code.
    // ====================================================================

    /// @notice Tokens for liquidity pool (20% of total supply)
    /// Formula: (MAX_MINT_COUNT × MINT_AMOUNT) / 4
    /// Returns: 2M (testing) or 200M (production)
    function poolSeedAmount() public pure returns (uint256) {
        return (MAX_MINT_COUNT * MINT_AMOUNT) / 4;
    }

    /// @notice Minimum payment balance required for deployment
    /// Formula: MAX_MINT_COUNT × PAYMENT_PER_MINT × 0.95
    /// Returns: 190 USDT (testing) or 19,000 USDT (production)
    function minPaymentBalance() public pure returns (uint256) {
        return (MAX_MINT_COUNT * PAYMENT_PER_MINT * 95) / 100;
    }

    /// @notice Total token supply (users 80% + pool 20%)
    /// Formula: MAX_MINT_COUNT × MINT_AMOUNT × 1.25
    /// Returns: 10M (testing) or 1B (production)
    function maxTotalSupply() public pure returns (uint256) {
        return (MAX_MINT_COUNT * MINT_AMOUNT * 5) / 4;
    }

    // -- Configurable state (set in initialize) --

    /// @notice PancakeSwap V2 Router for liquidity operations
    IPancakeRouter02 internal ROUTER;

    /// @notice PancakeSwap V2 Factory for pair management
    IPancakeFactory internal FACTORY;

    /// @notice The payment token (e.g., wUSDT with EIP-3009 support)
    address internal PAYMENT_TOKEN;

    /// @notice The underlying token for liquidity pool (e.g., USDT when PAYMENT_TOKEN is wUSDT)
    /// @dev If PAYMENT_TOKEN is a wrapper, this is the unwrapped token used in LP
    /// @dev If no wrapper is used, this should be address(0) and PAYMENT_TOKEN is used directly
    address internal UNDERLYING_TOKEN;

    /// @notice The TokenFactory address that created this token
    address internal TOKEN_FACTORY;

    /// @notice The minter address (USD4 wrapped USDT contract with minting permission)
    /// @dev USD4 contract handles EIP-3009 gasless transfers and calls ai_batchMint
    address public MINTER;

    // -- State Variables --

    /// @notice Total refund fees collected (5% charged when users refund)
    uint256 public totalRefundFeesCollected;

    /// @notice Emitted when refund fees are withdrawn to TokenFactory
    event RefundFeesWithdrawn(address indexed recipient, uint256 amount);

    /// @notice Emitted when excess payment is withdrawn
    event ExcessPaymentWithdrawn(address indexed recipient, uint256 amount);

    /// @notice The number of mints completed
    uint256 internal _mintCount;

    /// @notice Tracks which tx hashes have already been minted
    mapping(bytes32 => bool) public hasMinted;

    /// @notice The LP token (PancakeSwap pair) address
    address public lpToken;

    /// @notice Flag indicating whether liquidity has been deployed
    bool internal _liquidityDeployed;

    /// @notice Deadline for liquidity deployment (402 minutes after token creation)
    /// @dev If liquidity not deployed by this time, users can refund their minted tokens
    /// PRODUCTION: 402 minutes for real launch
    uint256 public deploymentDeadline;

    /// @notice Refund fee percentage (5% = 500 basis points)
    /// @dev Charged when users refund their tokens if liquidity deployment fails
    uint256 public constant REFUND_FEE_PERCENTAGE = 500; // 5%

    /// @notice Emitted when deployment deadline is set during initialization
    event DeploymentDeadlineSet(uint256 deadline);

    /// @notice Emitted when liquidity is deployed to PancakeSwap
    event LiquidityDeployed(address indexed lpToken, uint256 liquidity);

    /// @notice Emitted when LP tokens are burned (permanently locked)
    /// @param lpToken Address of the LP token
    /// @param burnedAmount Amount of LP tokens burned
    event LiquidityBurned(
        address indexed lpToken,
        uint256 burnedAmount
    );

    /// @notice Emitted when a user refunds their tokens
    /// @param user The user who refunded
    /// @param tokenAmount The amount of tokens burned
    /// @param paymentRefunded The amount of USDT refunded to user (95%)
    /// @param feeAmount The refund fee sent to Factory (5%)
    event Refunded(address indexed user, uint256 tokenAmount, uint256 paymentRefunded, uint256 feeAmount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the X402Token contract (replaces constructor for Clone pattern)
    /// @param name The token name
    /// @param symbol The token symbol
    /// @param minter The minter address (USD4 wrapped USDT contract address)
    /// @param _router The PancakeSwap V2 Router address
    /// @param _paymentToken The payment token address (e.g., wUSDT with EIP-3009)
    /// @param _underlyingToken The underlying token for LP (e.g., USDT), or address(0) if not using wrapper
    /// @dev First parameter after symbol is unused (kept for interface compatibility)
    /// @dev Economics parameters are auto-calculated based on MAX_MINT_COUNT
    /// @dev LP tokens are permanently burned after liquidity deployment
    function initialize(
        string memory name,
        string memory symbol,
        address /* launchpad */,
        address minter,
        IPancakeRouter02 _router,
        address _paymentToken,
        address _underlyingToken
    ) external initializer {
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(symbol).length > 0, "Symbol cannot be empty");
        require(address(_router) != address(0), "Invalid router");
        require(_paymentToken != address(0), "Invalid payment token");
        require(minter != address(0), "Invalid minter");
        // Note: _underlyingToken can be address(0) if not using a wrapper

        __ERC20_init(name, symbol);
        __ERC20Burnable_init();
        __Ownable_init(msg.sender);  // Initialize with factory as temporary owner
        __EIP712_init(name, "1");
        __ReentrancyGuard_init();

        // Set authorized addresses
        // MINTER = USD4 wrapped USDT contract (handles EIP-3009 transfers and calls ai_batchMint)
        MINTER = minter;

        ROUTER = _router;
        FACTORY = IPancakeFactory(_router.factory());
        PAYMENT_TOKEN = _paymentToken;
        UNDERLYING_TOKEN = _underlyingToken;
        TOKEN_FACTORY = msg.sender;  // Factory is the caller of initialize

        // Set deployment deadline to 402 minutes from now - PRODUCTION
        // Solidity 0.8.26 has automatic overflow protection, addition will revert on overflow
        deploymentDeadline = block.timestamp + 402 minutes;
        emit DeploymentDeadlineSet(deploymentDeadline);

        // SECURITY: Immediately renounce ownership to make contract fully autonomous
        // No owner means no centralized control, enhancing decentralization
        // All critical functions use role-based access (MINTER) or specific addresses (TOKEN_FACTORY)
        renounceOwnership();
    }

    // ==================== EIP-3009 GASLESS TRANSFER IMPLEMENTATION ====================
    // This section implements EIP-3009 for x402 protocol integration.
    // Allows users to sign transfer authorizations off-chain, which facilitators execute on-chain.
    //
    // SECURITY FEATURES:
    // - Nonce-based replay protection (not sequential, supports parallel signatures)
    // - Time-window validation (validAfter < now < validBefore, exclusive bounds)
    // - EIP-712 structured data signing for domain separation
    // - Signature verification using ECDSA recovery
    // - Authorization state tracking (0=Unused, 1=Used, 2=Canceled)
    //
    // GAS OPTIMIZATION:
    // - Users sign off-chain (no gas cost)
    // - Facilitator pays gas for on-chain execution
    // - Enables micro-payments without user gas burden
    // =================================================================================

    /// @notice Returns the EIP-712 domain separator for signature verification
    /// @dev Used by off-chain tools to generate valid EIP-712 signatures
    /// @return Domain separator hash computed from chain ID and contract address
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Check if an authorization has been used or canceled
    /// @param authorizer Address of the user who created the authorization
    /// @param nonce Unique nonce for this authorization
    /// @return True if authorization is used/canceled, false if still valid
    /// @dev Returns false for unused authorizations (state = 0)
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce] != 0;
    }

    /// @notice Execute a signed transfer authorization (EIP-3009 standard)
    /// @param from Payer address (must have signed the authorization)
    /// @param to Payee address
    /// @param value Amount to transfer (in token units with 18 decimals)
    /// @param validAfter Timestamp after which signature is valid (exclusive)
    /// @param validBefore Timestamp before which signature is valid (exclusive)
    /// @param nonce Unique random nonce (prevents replay attacks)
    /// @param v ECDSA signature component
    /// @param r ECDSA signature component
    /// @param s ECDSA signature component
    /// @return True if transfer succeeds
    /// @dev SECURITY: Validates signature, timeframe, and nonce before executing transfer
    /// @dev Used by USD4 contract to execute user-authorized payments
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
    ) external returns (bool) {
        // CHECKS: Validate authorization parameters
        _validateTimeframe(validAfter, validBefore);
        _useAuthorization(from, nonce);

        bytes32 structHash = keccak256(
            abi.encode(_TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        _requireValidSignature(from, structHash, v, r, s);

        // INTERACTIONS: Execute transfer after all validations pass
        _transfer(from, to, value);
        return true;
    }

    /// @notice Execute a signed receive authorization with front-running protection
    /// @param from Payer address (must have signed the authorization)
    /// @param to Payee address (MUST equal msg.sender for security)
    /// @param value Amount to transfer
    /// @param validAfter Timestamp after which signature is valid (exclusive)
    /// @param validBefore Timestamp before which signature is valid (exclusive)
    /// @param nonce Unique random nonce
    /// @param v ECDSA signature component
    /// @param r ECDSA signature component
    /// @param s ECDSA signature component
    /// @return True if transfer succeeds
    /// @dev SECURITY: Requires to == msg.sender to prevent front-running attacks
    /// @dev Use this when you want to ensure only the intended recipient can claim funds
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
    ) external returns (bool) {
        // SECURITY: Prevent front-running by requiring caller to be recipient
        if (to != msg.sender) revert InvalidRecipient(to);

        // CHECKS: Validate authorization parameters
        _validateTimeframe(validAfter, validBefore);
        _useAuthorization(from, nonce);

        bytes32 structHash = keccak256(
            abi.encode(_RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        _requireValidSignature(from, structHash, v, r, s);

        // INTERACTIONS: Execute transfer after all validations pass
        _transfer(from, to, value);
        return true;
    }

    /// @notice Cancel an unused authorization to prevent future use
    /// @param authorizer Address of the user who created the authorization
    /// @param nonce Nonce of the authorization to cancel
    /// @param v ECDSA signature component
    /// @param r ECDSA signature component
    /// @param s ECDSA signature component
    /// @dev SECURITY: Only the authorizer can cancel their own authorizations
    /// @dev Reverts if authorization has already been used or canceled
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        // CHECKS: Verify authorization is still unused
        if (_authorizationStates[authorizer][nonce] != 0) {
            revert AuthorizationStateInvalid(authorizer, nonce);
        }

        // Validate cancellation signature
        bytes32 structHash = keccak256(abi.encode(_CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce));
        _requireValidSignature(authorizer, structHash, v, r, s);

        // EFFECTS: Mark authorization as canceled (state = 2)
        _authorizationStates[authorizer][nonce] = 2;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    // ==================== EIP-3009 INTERNAL HELPERS ====================
    // Internal functions for signature validation and nonce management.
    // These enforce the security guarantees of the EIP-3009 standard.
    // ==================================================================

    /// @dev Validate that current time is within authorization time window
    /// @param validAfter Authorization becomes valid after this time (exclusive)
    /// @param validBefore Authorization expires at this time (exclusive)
    /// @dev SECURITY: Time bounds are EXCLUSIVE on both ends
    /// @dev This prevents edge-case attacks at exact boundary timestamps
    function _validateTimeframe(uint256 validAfter, uint256 validBefore) internal view {
        uint256 nowTs = block.timestamp;
        // Authorization is ONLY valid when: validAfter < now < validBefore
        if (nowTs <= validAfter) revert AuthorizationNotYetValid(nowTs, validAfter);
        if (nowTs >= validBefore) revert AuthorizationExpired(nowTs, validBefore);
    }

    /// @dev Mark an authorization nonce as used
    /// @param authorizer Address of the authorization creator
    /// @param nonce Nonce to mark as used
    /// @dev SECURITY: Prevents replay attacks by tracking used nonces
    /// @dev State transition: 0 (Unused) → 1 (Used)
    function _useAuthorization(address authorizer, bytes32 nonce) internal {
        // Verify nonce hasn't been used or canceled
        if (_authorizationStates[authorizer][nonce] != 0) {
            revert AuthorizationStateInvalid(authorizer, nonce);
        }
        _authorizationStates[authorizer][nonce] = 1; // Mark as used
        emit AuthorizationUsed(authorizer, nonce);
    }

    /// @dev Verify EIP-712 signature matches expected signer
    /// @param expectedSigner Address that should have signed the message
    /// @param structHash Hash of the EIP-712 struct
    /// @param v ECDSA signature recovery id
    /// @param r ECDSA signature component
    /// @param s ECDSA signature component
    /// @dev SECURITY: Uses OpenZeppelin's ECDSA library for safe signature recovery
    /// @dev Reverts if recovered signer doesn't match expectedSigner
    function _requireValidSignature(address expectedSigner, bytes32 structHash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
    {
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, v, r, s);
        if (signer != expectedSigner) revert InvalidSigner(signer, expectedSigner);
    }

    // ==================== TRANSFER RESTRICTIONS ====================
    // Front-running protection during pre-deployment phase.
    // Ensures fair launch by preventing early liquidity additions or trading.
    // ==============================================================

    /// @notice Override _update to implement transfer restrictions before liquidity deployment
    /// @param from Sender address (address(0) for minting)
    /// @param to Recipient address (address(0) for burning)
    /// @param amount Amount of tokens to transfer
    /// @dev SECURITY: Prevents front-running attacks by restricting transfers before liquidity deployment
    /// @dev Allowed operations before deployment:
    ///      1. Minting (from == address(0)) - mint tokens to users
    ///      2. Burning (to == address(0)) - refund mechanism
    ///      3. Contract transfers (from/to == address(this)) - liquidity deployment prep
    /// @dev After deployment: all transfers are allowed (normal ERC20 behavior)
    /// @dev No transfer fees - clean transfer implementation
    function _update(address from, address to, uint256 amount) internal override {
        // ANTI-FRONT-RUNNING MECHANISM:
        // Before liquidity deployment, restrict all user-to-user transfers.
        // This prevents:
        // - Early traders from buying before official launch
        // - Malicious actors from creating competing liquidity pools
        // - Snipers from gaining unfair advantage
        if (!_liquidityDeployed) {
            // Allow only these safe operations:
            // 1. Minting: from == address(0) (batchMint creates tokens)
            // 2. Burning: to == address(0) (refund destroys tokens)
            // 3. Internal: from/to == address(this) (liquidity deployment)
            if (from != address(0) && to != address(0)) {
                require(
                    from == address(this) || to == address(this),
                    "Transfers disabled until liquidity deployed"
                );
            }
        }

        // SECURITY: No fee logic - clean CEI pattern
        // Solidity 0.8.26 has built-in overflow protection
        super._update(from, to, amount);
    }


    // -------------------------
    // Minting logic
    // -------------------------

    /// @notice Advanced batch mint with variable mint counts per address
    /// @param to Array of addresses to mint tokens to
    /// @param mintCounts Array of mint counts for each address (multiplier of MINT_AMOUNT)
    /// @param txHashes Array of tx hashes to prevent double minting
    /// @dev Each address receives mintCounts[i] * MINT_AMOUNT tokens
    /// @dev Total mints = sum(mintCounts), must not exceed MAX_MINT_COUNT
    /// @dev Allows flexible minting: user pays N * 10 USDT, gets N * MINT_AMOUNT tokens
    /// @dev Example: mintCount=1 → 400,000 tokens, mintCount=10 → 4,000,000 tokens
    function ai_batchMint(
        address[] memory to,
        uint256[] memory mintCounts,
        bytes32[] memory txHashes
    ) public nonReentrant {
        require(msg.sender == MINTER, "Only USD4 contract can call");

        // Prevent minting after deployment deadline to avoid fund lock scenarios
        require(block.timestamp < deploymentDeadline, "Minting period expired");
        require(!_liquidityDeployed, "Liquidity already deployed");

        // Validate array lengths - all three arrays must have same length
        if (to.length != mintCounts.length || to.length != txHashes.length) {
            revert ArrayLengthMismatch();
        }

        // Calculate total mints and validate each mintCount
        uint256 totalNewMints = 0;
        for (uint256 i = 0; i < mintCounts.length; i++) {
            // Each mintCount must be at least 1
            if (mintCounts[i] == 0) {
                revert InvalidMintCount();
            }
            totalNewMints += mintCounts[i];
        }

        // Check if total would exceed the global limit
        if (_mintCount + totalNewMints > MAX_MINT_COUNT) {
            revert TotalMintsExceeded(totalNewMints, MAX_MINT_COUNT - _mintCount);
        }

        // Process each address
        for (uint256 i = 0; i < to.length; i++) {
            // Check if the tx hash has already been minted
            if (hasMinted[txHashes[i]]) {
                revert AlreadyMinted(to[i], txHashes[i]);
            }

            hasMinted[txHashes[i]] = true;

            // Mint mintCounts[i] * MINT_AMOUNT tokens to the address
            // Example: mintCount=5 → 5 * 400,000 = 2,000,000 tokens
            uint256 tokensToMint = mintCounts[i] * MINT_AMOUNT;
            _mint(to[i], tokensToMint);
        }

        // Update global mint counter with total mints
        _mintCount += totalNewMints;

        require(block.timestamp < deploymentDeadline, "Deadline passed during minting");

        // Payment tokens are collected via x402 protocol (gasless EIP-3009 transfers)
        // When using wrapper (e.g., wUSDT on BSC): contract unwraps to underlying token before LP creation
        if (_mintCount == MAX_MINT_COUNT && !_liquidityDeployed) {
            uint256 paymentBalance = IERC20(PAYMENT_TOKEN).balanceOf(address(this));

            // Only deploy if we have sufficient payment tokens (95%+ of expected)
            // This allows for minor rounding differences while ensuring full liquidity
            if (paymentBalance >= minPaymentBalance()) {
                _deployLiquidity();
            }
        }
    }

    /// @dev Deploy liquidity to PancakeSwap V2 after minting phase completes
    /// @dev PAYMENT COLLECTION: Funds collected via x402 gasless EIP-3009 transfers (no gas cost for users)
    ///
    /// @dev WORKFLOW:
    ///      1. VALIDATION: Verify minting complete and sufficient payment tokens collected
    ///      2. TOKEN SELECTION: Determine LP pair token (unwrap wUSDT → USDT if using wrapper)
    ///      3. PAIR CREATION: Create or retrieve PancakeSwap LP pair
    ///      4. UNWRAPPING: Convert wUSDT to USDT via IWrappedUSDT.withdrawForAutoMint() if needed
    ///      5. TOKEN MINTING: Mint pool tokens (20% of total supply, auto-calculated)
    ///      6. APPROVALS: Approve PancakeSwap Router to spend tokens
    ///      7. LIQUIDITY ADD: Add liquidity with 95% slippage protection
    ///      8. LP LOCK: LP tokens sent to contract (locked for 402 days, not permanent)
    ///      9. STATE UPDATE: Mark liquidity as deployed (enables normal trading)
    ///
    /// @dev REQUIREMENTS:
    ///      - _mintCount == MAX_MINT_COUNT (all mints completed)
    ///      - Contract has >= minPaymentBalance() payment tokens (95% of expected)
    ///      - _liquidityDeployed == false (prevents double-deployment)
    ///
    /// @dev SECURITY FEATURES:
    ///      - CEI PATTERN: All state changes before external calls
    ///      - SLIPPAGE PROTECTION: Requires 95% of desired amounts (prevents sandwich attacks)
    ///      - FRONT-RUNNING PROTECTION: Transfers disabled until _liquidityDeployed = true
    ///      - LP TOKEN BURN: Tokens permanently burned to 0xdead address (permanent lock)
    ///      - OVERFLOW PROTECTION: Solidity 0.8.26 has built-in checked arithmetic
    ///      - PRECISION SAFETY: Uses actual received amounts from unwrap (not assumed values)
    ///
    /// @dev DECIMAL HANDLING:
    ///      - wUSDT: 6 decimals (compact format for gasless transfers)
    ///      - USDT: 18 decimals (BSC standard, used in LP)
    ///      - Project Token: 18 decimals (ERC20 standard)
    ///      - Conversion: 1 wUSDT (10^6) = 1 USDT (10^18) after unwrap
    function _deployLiquidity() internal {
        // STEP 1: CHECKS - Validate all preconditions
        require(!_liquidityDeployed, "Liquidity already deployed");
        require(_mintCount == MAX_MINT_COUNT, "Minting not complete");

        uint256 contractBalance = IERC20(PAYMENT_TOKEN).balanceOf(address(this));
        require(contractBalance >= minPaymentBalance(), "Insufficient payment tokens collected");

        // STEP 2: EFFECTS - Update state BEFORE any external calls (CEI pattern)
        // CRITICAL: This prevents reentrancy attacks by marking deployment complete first
        // If any external call tries to reenter, this flag will block it
        _liquidityDeployed = true;

        // STEP 3: DETERMINE LP PAIR TOKEN
        // When using wrapper (wUSDT): unwrap to underlying (USDT) for LP
        // When direct: use payment token directly in LP
        // RATIONALE: EIP-3009 requires special token, but LP uses standard token
        address lpPairToken;
        if (UNDERLYING_TOKEN != address(0)) {
            // Wrapper mode: wUSDT (EIP-3009) → USDT (LP)
            lpPairToken = UNDERLYING_TOKEN;
        } else {
            // Direct mode: USDT/BUSD used directly
            lpPairToken = PAYMENT_TOKEN;
        }

        // STEP 4: INTERACTIONS - Create or retrieve LP pair (first external call)
        // SECURITY: Check if pair exists to avoid duplicate pair creation
        // NOTE: If someone pre-creates pair, we safely use existing one
        address existingPair = FACTORY.getPair(address(this), lpPairToken);
        if (existingPair != address(0)) {
            lpToken = existingPair;
        } else {
            lpToken = FACTORY.createPair(address(this), lpPairToken);
        }
        require(lpToken != address(0), "Pair creation/retrieval failed");

        // STEP 5: UNWRAP PAYMENT TOKENS (if using wrapper)
        // CRITICAL: Use ACTUAL received amount, not assumed values
        // DECIMAL CONVERSION: wUSDT (6 decimals) → USDT (18 decimals)
        // SAFETY: IWrappedUSDT returns exact amount received (accounts for fees)
        uint256 actualPaymentAmount;

        if (UNDERLYING_TOKEN != address(0)) {
            // Unwrap all wUSDT to USDT
            // withdrawForAutoMint() burns wUSDT and returns actual USDT received
            uint256 actualWusdtBalance = IERC20(PAYMENT_TOKEN).balanceOf(address(this));
            uint256 usdtReceived = IWrappedUSDT(PAYMENT_TOKEN).withdrawForAutoMint(actualWusdtBalance);

            // Use actual received amount (accounts for wrapper fees, if any)
            actualPaymentAmount = usdtReceived;
        } else {
            // Direct mode: use payment token balance as-is
            actualPaymentAmount = IERC20(PAYMENT_TOKEN).balanceOf(address(this));
        }

        // STEP 6: MINT POOL TOKENS
        // FORMULA: poolSeedAmount() = (MAX_MINT_COUNT × MINT_AMOUNT) / 4
        // RESULT: 20% of total supply allocated to LP
        uint256 poolTokens = poolSeedAmount();
        _mint(address(this), poolTokens);

        // STEP 7: APPROVE ROUTER TO SPEND TOKENS
        // SECURITY: Use forceApprove to reset allowance (prevents approval race condition)
        // SAFETY: Approving exact amounts needed, no excess approval
        _approve(address(this), address(ROUTER), poolTokens);
        IERC20(lpPairToken).forceApprove(address(ROUTER), actualPaymentAmount);

        // STEP 8: CALCULATE SLIPPAGE PROTECTION
        // PROTECTION: 95% minimum guarantees protection against:
        // - Sandwich attacks (someone tries to manipulate price mid-transaction)
        // - Front-running bots
        // - Unexpected price movements
        // OVERFLOW SAFE: Solidity 0.8.26 has automatic overflow checking
        uint256 minTokenAmount = poolTokens * 95 / 100;
        uint256 minPaymentAmount = actualPaymentAmount * 95 / 100;

        // STEP 9: ADD LIQUIDITY TO PANCAKESWAP
        // SECURITY GUARANTEES:
        // - Transfers disabled until _liquidityDeployed = true (front-running protection)
        // - Slippage protection via minTokenAmount and minPaymentAmount
        // - LP tokens sent to this contract, then BURNED (permanent lock)
        // - Deadline prevents stale transactions (15-minute window)
        // REENTRANCY SAFE: nonReentrant modifier on batchMint (caller) protects this flow
        (uint256 amountToken, uint256 amountPayment, uint256 liquidity) = ROUTER.addLiquidity(
            address(this),                      // tokenA (this project token)
            lpPairToken,                        // tokenB (USDT or direct payment token)
            poolTokens,                         // amountADesired
            actualPaymentAmount,                // amountBDesired (actual received, not assumed)
            minTokenAmount,                     // amountAMin (95% slippage tolerance)
            minPaymentAmount,                   // amountBMin (95% slippage tolerance)
            address(this),                      // LP tokens sent to this contract (will be burned)
            block.timestamp + 15 minutes        // deadline (prevents stale transactions)
        );

        // STEP 10: VALIDATE LIQUIDITY AMOUNTS
        // ADDITIONAL SAFETY: Ensure Router didn't use less than minimum
        // This should never fail if Router is working correctly, but adds defense-in-depth
        require(amountToken >= minTokenAmount, "Insufficient token added to liquidity");
        require(amountPayment >= minPaymentAmount, "Insufficient payment added to liquidity");

        // STEP 11: BURN LP TOKENS (PERMANENT LOCK)
        // Transfer LP tokens to dead address for permanent lock
        // This ensures liquidity can NEVER be removed
        IERC20(lpToken).safeTransfer(address(0xdead), liquidity);

        // STEP 12: EMIT EVENTS
        // NOTE: _liquidityDeployed was already set to true in STEP 2 (before external calls)
        // This follows proper CEI pattern and prevents reentrancy attacks
        emit LiquidityDeployed(lpToken, liquidity);
        emit LiquidityBurned(lpToken, liquidity);
    }


    /// @notice Refund mechanism for failed liquidity deployments
    /// @dev AVAILABILITY: Only after deployment deadline AND if liquidity not deployed
    /// @dev REFUND RATE: 95% of original payment (5% platform fee)
    /// @dev PROCESS:
    ///      1. User burns their tokens
    ///      2. Receives 95% of payment in wUSDT/USDT
    ///      3. 5% fee sent to TokenFactory
    ///
    /// @dev SECURITY FEATURES:
    ///      - CEI PATTERN: State updates before external calls
    ///      - REENTRANCY PROTECTION: nonReentrant modifier
    ///      - BALANCE VALIDATION: User balance guaranteed accurate (transfers disabled pre-deployment)
    ///      - SOLVENCY CHECK: Ensures contract has sufficient funds before proceeding
    ///
    /// @dev CALCULATION LOGIC:
    ///      - Only complete mints are refunded (balance / MINT_AMOUNT)
    ///      - Partial tokens (remainder) stay with user as dust
    ///      - Each mint: 400,000 tokens = 10 USDT payment
    ///      - Refund: (mintCount × 10 USDT) × 95%
    ///
    /// @dev WHY SAFE: Transfers disabled before deployment means user balance = minted amount (no trading possible)
    function refund() external nonReentrant {
        // CHECKS: Validate refund conditions
        require(block.timestamp >= deploymentDeadline, "Deployment deadline not reached");
        require(!_liquidityDeployed, "Liquidity already deployed - refund unavailable");

        uint256 userBalance = balanceOf(msg.sender);
        require(userBalance > 0, "No tokens to refund");

        // Calculate complete mints: Only full MINT_AMOUNT units are refunded
        // Example: 850,000 tokens / 400,000 = 2 complete mints (50,000 tokens remain as dust)
        uint256 userMintCount = userBalance / MINT_AMOUNT;
        require(userMintCount > 0, "Insufficient balance for refund");

        // Calculate refund economics
        uint256 totalPaid = userMintCount * PAYMENT_PER_MINT; // Total user paid (10 USDT per mint)
        uint256 refundAmount = totalPaid * (10000 - REFUND_FEE_PERCENTAGE) / 10000; // 95% to user
        uint256 feeAmount = totalPaid - refundAmount; // 5% platform fee

        // Solvency check: Ensure contract has sufficient funds
        // SECURITY: Prevents partial refunds or failed transactions
        uint256 contractBalance = IERC20(PAYMENT_TOKEN).balanceOf(address(this));
        require(contractBalance >= totalPaid, "Insufficient contract balance for refund");

        uint256 burnAmount = userMintCount * MINT_AMOUNT;

        // EFFECTS: Update state before external calls (CEI pattern)
        // Accumulate fees for later withdrawal by Factory
        totalRefundFeesCollected += feeAmount;

        // INTERACTIONS: External calls after all state updates
        // SECURITY: _burn is OpenZeppelin's implementation (safe)
        // SECURITY: safeTransfer prevents silent failures and handles non-standard tokens
        _burn(msg.sender, burnAmount);
        IERC20(PAYMENT_TOKEN).safeTransfer(msg.sender, refundAmount);

        emit Refunded(msg.sender, burnAmount, refundAmount, feeAmount);
    }

    /// @notice Withdraw accumulated refund fees to TokenFactory
    /// @dev ACCESS CONTROL: Only callable by TokenFactory contract
    /// @dev SECURITY FEATURES:
    ///      - CEI PATTERN: State reset before transfer
    ///      - REENTRANCY PROTECTION: nonReentrant modifier
    ///      - ZERO-CHECK: Prevents wasteful transactions
    ///
    /// @dev USAGE: Factory calls this to collect platform revenue from failed deployments
    /// @dev FEES SOURCE: 5% charged on user refunds when liquidity deployment fails
    function withdrawRefundFees() external nonReentrant {
        // ACCESS CONTROL: Only Factory can withdraw (Factory is set during initialization)
        require(msg.sender == TOKEN_FACTORY, "Only Factory can withdraw refund fees");
        require(totalRefundFeesCollected > 0, "No refund fees to withdraw");

        // CEI PATTERN: Reset counter before transfer (prevents reentrancy)
        uint256 amount = totalRefundFeesCollected;
        totalRefundFeesCollected = 0;

        // SAFE TRANSFER: Uses SafeERC20 for secure token transfer
        IERC20(PAYMENT_TOKEN).safeTransfer(TOKEN_FACTORY, amount);

        emit RefundFeesWithdrawn(TOKEN_FACTORY, amount);
    }

    // -------------------------
    // Getters
    // -------------------------

    /// @notice Returns the maximum mint count
    /// @return Maximum number of mint operations allowed
    function maxMintCount() public pure returns (uint256) {
        return MAX_MINT_COUNT;
    }

    /// @notice Returns the mint count
    /// @return Current number of mints completed
    function mintCount() public view returns (uint256) {
        return _mintCount;
    }

    /// @notice Returns the mint amount of the token
    /// @return Amount of tokens minted per operation
    function mintAmount() public pure returns (uint256) {
        return MINT_AMOUNT;
    }

    /// @notice Returns the collected payment token balance
    /// @dev This is the amount that will be used for liquidity deployment
    /// @return Balance of payment tokens in the contract (in payment token decimals)
    function paymentSeed() public view returns (uint256) {
        return IERC20(PAYMENT_TOKEN).balanceOf(address(this));
    }

    /// @notice Returns whether liquidity has been deployed
    /// @return True if liquidity has been deployed, false otherwise
    function liquidityDeployed() public view returns (bool) {
        return _liquidityDeployed;
    }

    /// @notice Returns the payment token address
    /// @dev The token used for payments (e.g., wUSDT with EIP-3009 support)
    /// @return Address of the payment token contract
    function paymentToken() public view returns (address) {
        return PAYMENT_TOKEN;
    }

    /// @notice Returns the underlying token address
    /// @dev The token used for liquidity pool (e.g., USDT when PAYMENT_TOKEN is wUSDT)
    /// @dev Returns address(0) if not using a wrapper
    /// @return Address of the underlying token, or address(0) if not using wrapper
    function underlyingToken() public view returns (address) {
        return UNDERLYING_TOKEN;
    }
}
