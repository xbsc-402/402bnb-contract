# X402 Token Launchpad - Smart Contract Suite

A decentralized token launchpad protocol on BNB Smart Chain (BSC) featuring EIP-3009 gasless payments, automated liquidity deployment, and fair launch mechanics.

## Overview

X402 Token Launchpad enables anyone to create and launch tokens with built-in liquidity management, gasless payment support, and anti-front-running protection. The protocol uses PancakeSwap V2 for liquidity deployment and implements EIP-3009 for gas-free user transactions.

### Key Features

- **Gasless Payments**: Users pay via EIP-3009 signatures (no gas fees for minting)
- **Automated Liquidity**: Automatic PancakeSwap liquidity deployment when mint target reached
- **Fair Launch Protection**: Transfer restrictions prevent front-running before liquidity deployment
- **Vanity Addresses**: CREATE2 deterministic deployment for branded token addresses (ending in ...402)
- **Refund Mechanism**: Built-in refund system if liquidity deployment fails
- **Low Deployment Cost**: EIP-1167 minimal proxy pattern for gas-efficient token creation

## Architecture

### Contract System

```
TokenFactory (EIP-1167 Deployer)
    │
    ├─→ X402Token Clone 1 (Initializable)
    ├─→ X402Token Clone 2 (Initializable)
    └─→ X402Token Clone 3 (Initializable)

WrappedUSDT (UUPS Upgradeable)
    │
    └─→ Bridges USDT to wUSDT (6 decimals for gasless transfers)

LPTokenTimelock (Simple Lock)
    │
    └─→ Locks LP tokens for 402 days
```

### Core Contracts

#### 1. TokenFactory.sol
Factory contract that deploys X402Token instances using EIP-1167 minimal proxy pattern.

**Key Features:**
- Clone-based deployment (saves ~95% gas vs. direct deployment)
- CREATE2 vanity address support (tokens ending in ...402)
- Configurable creation fees (paid in BNB)
- Salt management for predictable addresses
- Refund fee collection (5% platform fee on failed deployments)

**Configuration:**
- Creation Fee: Configurable (owner-adjustable)
- Payment Token: wUSDT (EIP-3009 compatible wrapper)
- Underlying Token: USDT (18 decimals on BSC)
- Router: PancakeSwap V2 Router

#### 2. X402Token.sol
EIP-3009 compatible token with automated liquidity deployment.

**Tokenomics:**
- Mint Amount: 400,000 tokens per mint operation
- Payment: 10 USDT per mint (via wUSDT wrapper)
- Max Mint Count: 2,000 mints (configurable: 20 for testing)
- Total Supply: 1,000,000,000 tokens (1B)
  - 80% to users: 800,000,000 tokens
  - 20% to liquidity pool: 200,000,000 tokens

**Lifecycle:**
1. **Minting Phase** (0 - 2,000 mints)
   - Users sign EIP-3009 authorizations off-chain
   - USD4 contract executes gasless transfers
   - Tokens minted to users immediately
   - All transfers disabled (anti-front-running)

2. **Liquidity Deployment** (at 2,000 mints)
   - Automatic PancakeSwap V2 liquidity addition
   - LP tokens permanently burned to 0xdead
   - Transfers enabled for normal trading

3. **Refund Window** (if deployment fails)
   - Available after 402 minutes deadline
   - Users burn tokens, receive 95% refund
   - 5% platform fee collected

**Security Features:**
- EIP-3009 nonce-based replay protection
- Time-window validation for authorizations
- Transfer restrictions before deployment
- Reentrancy protection
- Slippage protection (95% minimum on liquidity)

#### 3. WrappedUSDT.sol
UUPS upgradeable wrapper that converts USDT (18 decimals) to wUSDT (6 decimals) with EIP-3009 support.

**Why Wrapper:**
- BSC USDT has 18 decimals, but gasless transfers work better with 6 decimals
- Enables EIP-3009 signatures on BSC (native USDT doesn't support it)
- 1:1 value exchange: 1 USDT (10^18) = 1 wUSDT (10^6)

**Features:**
- Deposit: USDT → wUSDT (with optional fee)
- Withdraw: wUSDT → USDT (with optional fee)
- Auto-mint: Integrated with X402Token for seamless liquidity deployment
- Dust tracking: Precision loss from decimal conversion tracked per user

**Auto-Mint Flow:**
1. User signs EIP-3009 authorization (off-chain, no gas)
2. USD4 calls `transferWithAuthorization(from, X402Token, amount, ...)`
3. USD4 transfers wUSDT to X402Token
4. USD4 automatically calls `X402Token.ai_batchMint()`
5. X402Token mints tokens to user
6. When mint target reached, X402Token calls `withdrawForAutoMint()` to unwrap wUSDT → USDT
7. X402Token deploys liquidity to PancakeSwap

#### 4. LPTokenTimelock.sol
Simple timelock contract for locking LP tokens.

**Configuration:**
- Lock Duration: 402 days (configurable)
- Beneficiary: Set at deployment (immutable)
- Release: One-time withdrawal after lock period

**Note:** Current implementation uses permanent burn (0xdead), but timelock available if needed.

## Deployment Flow

### 1. Deploy Core Infrastructure

```bash
# Deploy WrappedUSDT (UUPS Proxy)
forge script script/DeployWrappedUSDT.s.sol \
    --rpc-url bsc-testnet \
    --broadcast \
    --verify

# Deploy X402Token Implementation
forge script script/DeployImplementation.s.sol \
    --rpc-url bsc-testnet \
    --broadcast \
    --verify

# Deploy TokenFactory
forge script script/DeployFactory.s.sol \
    --rpc-url bsc-testnet \
    --broadcast \
    --verify
```

### 2. Pre-calculate Vanity Salts (Off-chain)

Generate salts that produce addresses ending in ...402:

```javascript
// Example: brute-force search for vanity salts
for (let i = 0; i < 10000; i++) {
  const salt = randomBytes32();
  const predictedAddress = predictDeterministicAddress(implementation, salt, factory);
  if (predictedAddress.endsWith('402')) {
    salts.push(salt);
  }
}
```

### 3. Configure Factory

```bash
# Add pre-calculated salts
cast send $FACTORY "addSalts(bytes32[])" "[0x123..., 0x456...]" \
    --private-key $PRIVATE_KEY \
    --rpc-url bsc-testnet

# Set creation fee (e.g., 0.01 BNB)
cast send $FACTORY "setCreationFee(uint256)" "10000000000000000" \
    --private-key $PRIVATE_KEY \
    --rpc-url bsc-testnet

# Enable token creation for public
cast send $FACTORY "setTokenCreationEnabled(bool)" "true" \
    --private-key $PRIVATE_KEY \
    --rpc-url bsc-testnet
```

### 4. Connect WrappedUSDT to Factory

```bash
# Set TokenFactory in WrappedUSDT for auto-mint verification
cast send $WRAPPED_USDT "setTokenFactory(address)" $FACTORY \
    --private-key $PRIVATE_KEY \
    --rpc-url bsc-testnet
```

## Usage Examples

### Create a New Token

```solidity
// User calls TokenFactory
ITokenFactory factory = ITokenFactory(FACTORY_ADDRESS);
address newToken = factory.createToken{value: 0.01 ether}(
    "My Token",
    "MTK"
);
```

### Mint Tokens (Gasless via EIP-3009)

```javascript
// 1. User signs authorization off-chain (no gas cost)
const authorization = {
  from: userAddress,
  to: tokenAddress,
  value: parseUnits("10", 6), // 10 wUSDT
  validAfter: 0,
  validBefore: Math.floor(Date.now() / 1000) + 3600,
  nonce: randomBytes32()
};

const signature = await signEIP3009(authorization, userPrivateKey);

// 2. Backend calls WrappedUSDT.transferWithAuthorization (pays gas)
await wrappedUSDT.transferWithAuthorization(
  authorization.from,
  authorization.to,
  authorization.value,
  authorization.validAfter,
  authorization.validBefore,
  authorization.nonce,
  signature.v,
  signature.r,
  signature.s
);

// Auto-mint triggered automatically:
// - wUSDT transferred to X402Token
// - Tokens minted to user
// - Liquidity deployed when target reached
```

### Refund Tokens (If Deployment Failed)

```solidity
// After deployment deadline (402 minutes) if liquidity not deployed
IX402Token token = IX402Token(TOKEN_ADDRESS);
token.refund(); // Burns tokens, returns 95% of payment
```

## Economic Model

### Standard Token Economics

For production deployment (MAX_MINT_COUNT = 2,000):

| Parameter | Value | Calculation |
|-----------|-------|-------------|
| **Mint Amount** | 400,000 tokens | Fixed per mint |
| **Payment Per Mint** | 10 USDT | Fixed price |
| **Max Mints** | 2,000 | Configurable |
| **User Tokens** | 800,000,000 | 2,000 × 400,000 |
| **Pool Tokens** | 200,000,000 | User tokens / 4 (20%) |
| **Total Supply** | 1,000,000,000 | 800M + 200M |
| **Total Raised** | 20,000 USDT | 2,000 × 10 |
| **Initial Price** | 0.000025 USDT/token | 10 / 400,000 |

### Testing Configuration

For testing (MAX_MINT_COUNT = 20):

| Parameter | Value |
|-----------|-------|
| Max Mints | 20 |
| User Tokens | 8,000,000 |
| Pool Tokens | 2,000,000 |
| Total Supply | 10,000,000 |
| Total Raised | 200 USDT |

### Fee Structure

| Fee Type | Rate | Collected By |
|----------|------|--------------|
| Token Creation | Configurable (e.g., 0.01 BNB) | TokenFactory |
| Refund Fee | 5% | TokenFactory |
| Deposit Fee (wUSDT) | 0% (configurable, max 5%) | WrappedUSDT |
| Withdraw Fee (wUSDT) | 0% (configurable, max 5%) | WrappedUSDT |

## Security

### Audit Status
⚠️ **Not audited** - Use at your own risk

### Security Features

1. **EIP-3009 Protection**
   - Nonce-based replay attack prevention
   - Time-window validation (validAfter, validBefore)
   - EIP-712 structured data signing
   - Signature verification via ECDSA

2. **Front-running Prevention**
   - Transfer restrictions until liquidity deployed
   - CREATE2 deterministic addresses
   - Slippage protection on liquidity deployment

3. **Reentrancy Protection**
   - `nonReentrant` modifier on all critical functions
   - CEI pattern (Checks-Effects-Interactions)
   - State updates before external calls

4. **Access Control**
   - Ownership renounced after initialization (X402Token)
   - Role-based minting (only USD4 contract)
   - Factory-only refund fee withdrawal

5. **Upgrade Safety**
   - UUPS pattern for WrappedUSDT (owner-controlled)
   - Implementation upgradeability for TokenFactory
   - Storage gap for future upgrades

### Known Limitations

- LP tokens permanently burned (cannot retrieve liquidity)
- No emergency pause mechanism (by design for decentralization)
- Refund only available after deadline if deployment fails
- Decimal precision loss on USDT→wUSDT conversion (tracked as dust)

## Development

### Prerequisites

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
forge install
```

### Build

```bash
forge build
```

### Test

```bash
# Run all tests
forge test

# Run with gas report
forge test --gas-report

# Run specific test contract
forge test --match-contract X402TokenTest

# Run with verbosity
forge test -vvv
```

### Coverage

```bash
forge coverage
```

### Local Development

```bash
# Start local node
anvil

# Deploy to local network
forge script script/DeployAll.s.sol \
    --rpc-url http://localhost:8545 \
    --broadcast
```

## Contract Addresses

### BSC Testnet

| Contract | Address |
|----------|---------|
| WrappedUSDT (Proxy) | `TBD` |
| WrappedUSDT (Implementation) | `TBD` |
| X402Token (Implementation) | `TBD` |
| TokenFactory | `TBD` |

### BSC Mainnet

| Contract | Address |
|----------|---------|
| WrappedUSDT (Proxy) | `TBD` |
| WrappedUSDT (Implementation) | `TBD` |
| X402Token (Implementation) | `TBD` |
| TokenFactory | `TBD` |

## Technical Specifications

### Standards Implemented

- **ERC-20**: Standard token interface
- **EIP-3009**: Transfer with authorization (gasless transfers)
- **EIP-712**: Typed structured data hashing and signing
- **EIP-1167**: Minimal proxy contract (clone factory)
- **EIP-1967**: Standard proxy storage slots (UUPS)

### Dependencies

- OpenZeppelin Contracts v5.4.0
  - ERC20Upgradeable
  - OwnableUpgradeable
  - ReentrancyGuardUpgradeable
  - EIP712Upgradeable
  - UUPSUpgradeable
  - SafeERC20

### External Integrations

- **PancakeSwap V2**
  - Router: `0x10ED43C718714eb63d5aA57B78B54704E256024E` (BSC Mainnet)
  - Factory: Accessed via Router
  - LP Tokens: Automatically created pairs

- **USDT (BSC)**
  - Contract: `0x55d398326f99059fF775485246999027B3197955`
  - Decimals: 18 (BSC uses 18, not 6 like Ethereum)

## Deployment Checklist

### Pre-Deployment
- [ ] Configure MAX_MINT_COUNT (20 for testing, 2000 for production)
- [ ] Pre-calculate vanity salts off-chain
- [ ] Set creation fee amount
- [ ] Prepare USDT for initial testing

### Deployment Steps
- [ ] Deploy WrappedUSDT (UUPS Proxy + Implementation)
- [ ] Deploy X402Token Implementation
- [ ] Deploy TokenFactory with correct parameters
- [ ] Verify all contracts on BSCScan
- [ ] Add salts to TokenFactory
- [ ] Set TokenFactory in WrappedUSDT
- [ ] Enable token creation
- [ ] Test full flow on testnet

### Post-Deployment
- [ ] Monitor first token creation
- [ ] Verify vanity addresses working
- [ ] Test EIP-3009 gasless minting
- [ ] Verify liquidity deployment
- [ ] Test refund mechanism
- [ ] Document contract addresses

## FAQ

**Q: Why use a wrapper (wUSDT) instead of native USDT?**
A: BSC USDT (18 decimals) doesn't support EIP-3009. The wrapper enables gasless transfers while maintaining compatibility with PancakeSwap.

**Q: Can I change token economics after deployment?**
A: No. All economic parameters are constants or computed from MAX_MINT_COUNT. This ensures fairness and prevents rug pulls.

**Q: What happens if minting doesn't reach target?**
A: After 402 minutes, users can refund their tokens for 95% of payment. 5% fee covers gas costs.

**Q: Can liquidity be removed?**
A: No. LP tokens are permanently burned to 0xdead address. Liquidity is locked forever.

**Q: Why 402 everywhere?**
A: Project branding. 402 minutes deadline, 402 days lock (optional), addresses ending in ...402.

**Q: How are gas fees paid if users don't pay gas?**
A: Backend/facilitator pays gas for executing EIP-3009 `transferWithAuthorization()`. User only signs off-chain.

## License

MIT

## Support

For issues and feature requests, please open an issue on GitHub.

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. The contracts have not been audited. Do not use in production without thorough testing and professional audit.
