// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IX402Token} from "./interfaces/IX402Token.sol";
import {IPancakeRouter02} from "./interfaces/IPancakeRouter02.sol";

/// @title TokenFactory
/// @notice Factory contract for deploying x402-compatible tokens using EIP-1167 Minimal Proxy
/// @dev Creates clones of X402Token implementation contract with PancakeSwap V2 integration
contract TokenFactory is Ownable {
    using SafeERC20 for IERC20;

    // ==================== Errors ====================

    error InsufficientCreationFee();
    error InvalidImplementation();
    error InvalidRouter();
    error InvalidPaymentToken();
    error TokenCreationDisabled();
    error NoSaltsAvailable();
    error InvalidSaltIndex();

    // ==================== Events ====================

    /// @notice Emitted when a new token is created
    /// @param tokenAddress Address of the newly created token
    /// @param creator Address of the token creator
    /// @param name Token name
    /// @param symbol Token symbol
    /// @param salt Salt used for CREATE2
    /// @param saltIndex Index of the salt used
    /// @param mintAmount Amount minted per batch
    /// @param maxMintCount Maximum number of mints allowed
    /// @param timestamp Creation timestamp
    event TokenCreated(
        address indexed tokenAddress,
        address indexed creator,
        string name,
        string symbol,
        bytes32 salt,
        uint256 saltIndex,
        uint256 mintAmount,
        uint256 maxMintCount,
        uint256 timestamp
    );

    /// @notice Emitted when creation fee is updated
    event CreationFeeUpdated(uint256 oldFee, uint256 newFee);

    /// @notice Emitted when implementation contract is updated
    event ImplementationUpdated(address indexed oldImplementation, address indexed newImplementation);

    /// @notice Emitted when token creation status is updated
    event TokenCreationStatusUpdated(bool enabled);

    /// @notice Emitted when platform fees are withdrawn
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /// @notice Emitted when refund fees (USDT) are withdrawn
    event RefundFeesWithdrawn(address indexed recipient, uint256 amount);

    /// @notice Emitted when minter address is updated
    event MinterUpdated(address indexed oldMinter, address indexed newMinter);

    /// @notice Emitted when salts are added
    event SaltsAdded(uint256 startIndex, uint256 count);

    /// @notice Emitted when salts are replaced
    event SaltsReplaced(uint256 startIndex, uint256 count);

    /// @notice Emitted when salts are skipped
    event SaltsSkipped(uint256 startIndex, uint256 count);

    // ==================== State Variables ====================

    /// @notice Implementation contract address for X402Token
    /// @dev UPGRADEABILITY: Can be updated by owner to deploy new tokens with upgraded logic
    /// @dev SECURITY: Only affects FUTURE token deployments, existing tokens remain unchanged
    /// @dev SAFETY: Implementation address validated to have code before being set
    address public implementation;

    /// @notice Current minter address (USD4 wrapped USDT contract that executes minting)
    /// @dev ROLE ASSIGNMENT: This address receives MINTER_ROLE on newly created tokens
    /// @dev UPGRADEABILITY: Can be updated by owner to change minter for future deployments
    /// @dev SECURITY: Only affects FUTURE token deployments, existing tokens keep their minters
    /// @dev USD4 contract handles EIP-3009 gasless transfers and calls ai_batchMint
    address public minter;

    /// @notice PancakeSwap V2 Router address
    IPancakeRouter02 public immutable router;

    /// @notice Payment token address (e.g., USDC, BUSD, or wUSDT wrapper)
    /// @dev When using wrapper, this is the EIP-3009 compatible wrapper token
    address public immutable paymentToken;

    /// @notice Underlying token for liquidity pool (e.g., USDT when paymentToken is wUSDT)
    /// @dev If using wrapper pattern: this is the unwrapped token used in LP
    /// @dev If no wrapper is used: this is address(0) and paymentToken is used directly in LP
    address public immutable underlyingToken;

    /// @notice Fee required to create a token (in wei)
    uint256 public creationFee;

    /// @notice Whether token creation is enabled for non-admin users
    /// @dev Admin can always create tokens regardless of this flag
    /// @dev Default: false (disabled)
    bool public tokenCreationEnabled;

    /// @notice Array of all created tokens
    address[] public tokens;

    /// @notice Mapping to check if an address is a token created by this factory
    mapping(address => bool) public isFactoryToken;

    /// @notice Mapping from creator to their created tokens
    mapping(address => address[]) public creatorTokens;

    // ==================== VANITY ADDRESS (CREATE2) MANAGEMENT ====================
    // Enables predictable, branded token addresses ending in ...402 via CREATE2 deployment.
    //
    // SECURITY FEATURES:
    // - Salts pre-calculated off-chain for gas efficiency
    // - Sequential salt consumption prevents reuse
    // - Salt replacement only allowed for unused salts
    // - Deterministic address generation via Clones.cloneDeterministic()
    //
    // WORKFLOW:
    // 1. Generate salts off-chain that produce ...402 addresses
    // 2. Admin adds salts via addSalts() or replaceSalts()
    // 3. createToken() consumes next salt sequentially
    // 4. Each salt produces unique, predictable token address
    //
    // WHY SAFE: CREATE2 guarantees address uniqueness per (deployer, bytecode, salt)
    // =================================================================================

    /// @notice Pre-calculated salts for CREATE2 deployment (generates ...402 addresses)
    /// @dev STORAGE: Indexed mapping for efficient access and management
    /// @dev CALCULATION: Salts computed off-chain via brute-force search
    /// @dev USAGE: Each salt used exactly once during token creation
    mapping(uint256 => bytes32) public salts;

    /// @notice Total number of salts available
    /// @dev MANAGEMENT: Incremented by addSalts(), potentially by replaceSalts()
    uint256 public totalSalts;

    /// @notice Number of salts that have been used
    /// @dev CONSUMPTION: Incremented each time createToken() is called
    /// @dev SAFETY: usedSaltCount < totalSalts ensures salts are available
    uint256 public usedSaltCount;

    // ==================== Constructor ====================

    /// @notice Initializes the TokenFactory
    /// @param _implementation Address of X402Token implementation contract
    /// @param _minter Address that will receive MINTER_ROLE on new tokens (USD4 wrapped USDT contract)
    /// @param _router Address of PancakeSwap V2 Router
    /// @param _paymentToken Address of payment token (USDC/BUSD or wUSDT wrapper)
    /// @param _underlyingToken Address of underlying token for LP (e.g., USDT when using wUSDT wrapper, or address(0) if not using wrapper)
    /// @param _creationFee Fee required to create a token
    constructor(
        address _implementation,
        address _minter,
        IPancakeRouter02 _router,
        address _paymentToken,
        address _underlyingToken,
        uint256 _creationFee
    ) Ownable(msg.sender) {
        if (_implementation == address(0)) revert InvalidImplementation();
        if (_minter == address(0)) revert InvalidImplementation(); // Using same error for simplicity
        if (address(_router) == address(0)) revert InvalidRouter();
        if (_paymentToken == address(0)) revert InvalidPaymentToken();

        implementation = _implementation;
        minter = _minter;
        router = _router;
        paymentToken = _paymentToken;
        underlyingToken = _underlyingToken;
        creationFee = _creationFee;
    }

    // ==================== External Functions ====================

    /// @notice Creates a new x402-compatible token with standardized economics
    /// @param name Token name
    /// @param symbol Token symbol
    /// @return tokenAddress Address of the newly created token
    /// @dev All tokens use fixed parameters based on X402Token.MAX_MINT_COUNT:
    ///      - MINT_AMOUNT: 400,000 tokens per mint
    ///      - MAX_MINT_COUNT: Configured in implementation (testing: 200, production: 20,000)
    ///      - Pool tokens: 20% of total supply
    ///      - Total supply: MAX_MINT_COUNT × MINT_AMOUNT × 1.25
    /// @dev Users pay 10 USDT per mint via x402, collected funds deploy liquidity automatically
    /// @dev Requires:
    ///      - msg.value >= creationFee
    ///      - tokenCreationEnabled == true (or msg.sender == owner)
    ///      - Sufficient salts available (usedSaltCount < totalSalts)
    function createToken(
        string memory name,
        string memory symbol
    ) external payable returns (address tokenAddress) {
        // Check creation fee
        if (msg.value < creationFee) revert InsufficientCreationFee();

        // Check if token creation is enabled (admin bypass)
        // Admin (owner) can always create tokens, even when creation is disabled
        if (msg.sender != owner() && !tokenCreationEnabled) {
            revert TokenCreationDisabled();
        }

        // 1. Check if salts are available
        if (usedSaltCount >= totalSalts) revert NoSaltsAvailable();

        // 2. Get the next salt
        bytes32 salt = salts[usedSaltCount];
        uint256 saltIndex = usedSaltCount;
        usedSaltCount++;

        // 3. Clone with CREATE2 using the salt
        tokenAddress = Clones.cloneDeterministic(implementation, salt);

        // 4. Initialize the cloned token with standardized parameters
        // Liquidity funded by user mints via x402 gasless payments (EIP-3009)
        // When using wrapper: users pay wUSDT, contract auto-unwraps to USDT for LP
        // launchpad = Token creator (msg.sender) - unused parameter (kept for interface compatibility)
        // minter = USD4 wrapped USDT contract (configured in Factory) - handles EIP-3009 and minting
        IX402Token(tokenAddress).initialize(
            name,
            symbol,
            msg.sender,        // launchpad = Token creator (unused parameter)
            minter,            // minter = USD4 contract (has MINTER_ROLE)
            router,            // PancakeSwap Router
            paymentToken,      // wUSDT wrapper or direct USDT/BUSD
            underlyingToken    // USDT (if wrapper) or address(0) (if direct)
        );

        // 5. Record the token
        tokens.push(tokenAddress);
        isFactoryToken[tokenAddress] = true;
        creatorTokens[msg.sender].push(tokenAddress);

        // 6. Emit event (hardcode standard economics in event)
        emit TokenCreated(
            tokenAddress,
            msg.sender,
            name,
            symbol,
            salt,              // salt used
            saltIndex,         // salt index
            400_000 * 10**18,  // mintAmount (constant)
            20_000,            // maxMintCount (constant)
            block.timestamp
        );

        // 7. Refund excess ETH
        if (msg.value > creationFee) {
            (bool success,) = msg.sender.call{value: msg.value - creationFee}("");
            require(success, "ETH refund failed");
        }

        return tokenAddress;
    }

    // ==================== View Functions ====================

    /// @notice Returns the total number of tokens created
    function tokenCount() external view returns (uint256) {
        return tokens.length;
    }

    /// @notice Returns all tokens created by this factory
    function getAllTokens() external view returns (address[] memory) {
        return tokens;
    }

    /// @notice Returns tokens created by a specific address
    /// @param creator Address of the token creator
    function getTokensByCreator(address creator) external view returns (address[] memory) {
        return creatorTokens[creator];
    }

    /// @notice Returns a paginated list of tokens
    /// @param offset Starting index
    /// @param limit Number of tokens to return
    function getTokens(uint256 offset, uint256 limit) external view returns (address[] memory) {
        if (offset >= tokens.length) {
            return new address[](0);
        }

        uint256 end = offset + limit;
        if (end > tokens.length) {
            end = tokens.length;
        }

        address[] memory result = new address[](end - offset);
        for (uint256 i = 0; i < end - offset; i++) {
            result[i] = tokens[offset + i];
        }

        return result;
    }

    // ==================== Admin Functions ====================

    /// @notice Updates the minter address for future token deployments
    /// @param newMinter New minter address (USD4 wrapped USDT contract)
    /// @dev Only affects tokens created after this update; existing tokens retain their minter
    /// @dev New minter must be a valid address (non-zero)
    function setMinter(address newMinter) external onlyOwner {
        if (newMinter == address(0)) revert InvalidImplementation(); // Using same error for simplicity

        address oldMinter = minter;
        minter = newMinter;

        emit MinterUpdated(oldMinter, newMinter);
    }

    /// @notice Updates the creation fee
    /// @param newFee New creation fee in wei
    function setCreationFee(uint256 newFee) external onlyOwner {
        uint256 oldFee = creationFee;
        creationFee = newFee;
        emit CreationFeeUpdated(oldFee, newFee);
    }

    /// @notice Enable or disable token creation for non-admin users
    /// @param enabled True to enable token creation, false to disable
    /// @dev Admin can always create tokens regardless of this setting
    function setTokenCreationEnabled(bool enabled) external onlyOwner {
        tokenCreationEnabled = enabled;
        emit TokenCreationStatusUpdated(enabled);
    }

    /// @notice Updates the implementation contract for future token deployments
    /// @param newImplementation Address of the new X402Token implementation contract
    /// @dev UPGRADEABILITY: Only affects tokens created AFTER this update
    /// @dev SECURITY: Existing tokens remain unchanged (no impact on deployed tokens)
    /// @dev VALIDATION: Ensures new implementation is a valid contract with code
    ///
    /// @dev WHY UPDATABLE:
    ///      - Allows bug fixes in future token deployments
    ///      - Enables feature additions without redeploying Factory
    ///      - Existing tokens unaffected (immutable after deployment)
    ///
    /// @dev SAFETY CHECKS:
    ///      1. Non-zero address validation
    ///      2. Code existence verification (extcodesize > 0)
    ///      3. Only owner can update (access control)
    function setImplementation(address newImplementation) external onlyOwner {
        if (newImplementation == address(0)) revert InvalidImplementation();

        // SECURITY: Verify address contains contract code
        // RATIONALE: Prevents setting EOA or undeployed address as implementation
        // TECHNIQUE: Assembly extcodesize returns 0 for EOAs and undeployed addresses
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(newImplementation)
        }
        if (codeSize == 0) revert InvalidImplementation();

        address oldImplementation = implementation;
        implementation = newImplementation;

        emit ImplementationUpdated(oldImplementation, newImplementation);
    }

    // ==================== Salt Management Functions ====================

    /// @notice Batch add pre-calculated salts for vanity addresses
    /// @param _salts Array of salts to add (calculated offchain to produce ...402 addresses)
    /// @dev Salts are appended to the end of the existing salts
    /// @dev Example: If totalSalts = 100, and you add 50 salts, they will be indexed 100-149
    function addSalts(bytes32[] calldata _salts) external onlyOwner {
        uint256 startIndex = totalSalts;
        uint256 count = _salts.length;

        for (uint256 i = 0; i < count; i++) {
            salts[startIndex + i] = _salts[i];
        }

        totalSalts += count;

        emit SaltsAdded(startIndex, count);
    }

    /// @notice Batch replace salts starting from a specific index
    /// @param startIndex Starting index to replace from
    /// @param newSalts Array of new salts to replace with
    /// @dev Can only replace unused salts (index >= usedSaltCount)
    /// @dev Example: replaceSalts(5, [salt1, salt2, salt3]) replaces salts at index 5, 6, 7
    function replaceSalts(uint256 startIndex, bytes32[] calldata newSalts) external onlyOwner {
        uint256 count = newSalts.length;

        // Validate: cannot replace salts that have already been used
        if (startIndex < usedSaltCount) revert InvalidSaltIndex();

        // Validate: startIndex must be within bounds
        if (startIndex >= totalSalts) revert InvalidSaltIndex();

        // Replace salts
        for (uint256 i = 0; i < count; i++) {
            uint256 index = startIndex + i;

            // If replacing beyond current totalSalts, expand the pool
            if (index >= totalSalts) {
                totalSalts = index + 1;
            }

            salts[index] = newSalts[i];
        }

        // Update totalSalts if we extended beyond
        if (startIndex + count > totalSalts) {
            totalSalts = startIndex + count;
        }

        emit SaltsReplaced(startIndex, count);
    }

    /// @notice Get remaining salts count
    /// @return Number of salts available for use
    function remainingSalts() external view returns (uint256) {
        return totalSalts - usedSaltCount;
    }

    /// @notice Predict the address for the next token to be created
    /// @return predicted The predicted address using the next available salt
    function predictNextTokenAddress() external view returns (address predicted) {
        if (usedSaltCount >= totalSalts) revert NoSaltsAvailable();

        bytes32 nextSalt = salts[usedSaltCount];
        return Clones.predictDeterministicAddress(implementation, nextSalt, address(this));
    }

    /// @notice Predict address for a specific salt index
    /// @param saltIndex Index of the salt to predict address for
    /// @return predicted The predicted address
    function predictAddressBySaltIndex(uint256 saltIndex) external view returns (address predicted) {
        if (saltIndex >= totalSalts) revert InvalidSaltIndex();

        bytes32 salt = salts[saltIndex];
        return Clones.predictDeterministicAddress(implementation, salt, address(this));
    }

    /// @notice Skip N salts (mark them as used without creating tokens)
    /// @param count Number of salts to skip
    /// @dev Only skips forward, cannot go backward
    /// @dev Useful for skipping incorrect salts or reserving salts for special purposes
    function skipSalts(uint256 count) external onlyOwner {
        require(count > 0, "Count must be greater than 0");
        require(usedSaltCount + count <= totalSalts, "Not enough salts to skip");

        uint256 startIndex = usedSaltCount;
        usedSaltCount += count;

        emit SaltsSkipped(startIndex, count);
    }

    /// @notice Withdraws accumulated creation fees (native currency - BNB/ETH)
    /// @param recipient Address to receive the fees
    /// @dev SECURITY FEATURES:
    ///      - ACCESS CONTROL: Only owner can withdraw
    ///      - ZERO-CHECK: Prevents wasteful transactions
    ///      - SAFE TRANSFER: Uses low-level call with success verification
    ///
    /// @dev FEES SOURCE: Collected during token creation (msg.value in createToken)
    /// @dev WHY SAFE: All checks passed before transfer, uses .call for compatibility
    function withdrawFees(address payable recipient) external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "No fees to withdraw");

        // SAFE TRANSFER: Using .call instead of .transfer for gas flexibility
        // RATIONALE: .transfer has 2300 gas stipend which may be insufficient
        (bool success,) = recipient.call{value: balance}("");
        require(success, "ETH transfer failed");

        emit FeesWithdrawn(recipient, balance);
    }


    /// @notice Withdraws accumulated refund fees from a specific token
    /// @param tokenAddress Address of the token to withdraw refund fees from
    /// @dev REFUND FEES: Charged when users refund their tokens after deployment failure
    /// @dev FEE RATE: 5% of refunded amount, paid in payment token (wUSDT or USDT)
    ///
    /// @dev TWO-STEP PROCESS:
    ///      1. Call token.withdrawRefundFees() → fees sent to this Factory
    ///      2. Forward fees from Factory to owner (msg.sender)
    ///
    /// @dev SECURITY FEATURES:
    ///      - ACCESS CONTROL: Only owner can withdraw
    ///      - FACTORY VALIDATION: Only works with factory-created tokens
    ///      - BALANCE TRACKING: Measures actual received amount via before/after comparison
    ///      - SAFE TRANSFER: Uses SafeERC20 for secure token handling
    ///
    /// @dev WHY SAFE:
    ///      - Token can only be factory-created (verified via isFactoryToken)
    ///      - Actual received amount calculated (no assumptions)
    ///      - SafeERC20 handles non-standard token implementations
    function withdrawRefundFees(address tokenAddress) external onlyOwner {
        // VALIDATION: Ensure token was created by this factory
        require(isFactoryToken[tokenAddress], "Not a factory token");

        // MEASUREMENT: Track balance change to get actual received amount
        // RATIONALE: Don't rely on token's totalRefundFeesCollected, measure actual transfer
        uint256 balanceBefore = IERC20(paymentToken).balanceOf(address(this));

        // INTERACTION: Call token's withdrawRefundFees() - fees sent to this Factory
        // NOTE: Token validates caller is Factory before sending fees
        IX402Token(tokenAddress).withdrawRefundFees();

        // CALCULATION: Compute actual received amount
        uint256 balanceAfter = IERC20(paymentToken).balanceOf(address(this));
        uint256 amount = balanceAfter - balanceBefore;

        require(amount > 0, "No refund fees withdrawn");

        // SAFE TRANSFER: Use SafeERC20 for secure payment token handling
        IERC20(paymentToken).safeTransfer(msg.sender, amount);

        emit RefundFeesWithdrawn(msg.sender, amount);
    }

    /// @notice Allows owner to recover any ERC20 tokens accidentally sent to this contract
    /// @param token Address of the token to recover
    /// @param amount Amount to recover
    function recoverERC20(address token, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(msg.sender, amount);
    }

    // ==================== Receive ETH ====================

    /// @notice Allows contract to receive ETH
    receive() external payable {}
}
