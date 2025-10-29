# Smart Contracts

Smart contract implementation for x402 Token Launchpad.

## 📋 Contract List

### Core Contracts

1. **TokenFactory.sol**
   - Factory contract that uses EIP-1167 Minimal Proxy to clone and deploy tokens
   - Charges creation fee (0.01 ETH)
   - Manages all created tokens
   - Transfers PAYMENT_SEED (USDC) to new token contracts

2. **X402Token.sol**
   - Initializable version modified from Ping contract
   - Implements complete EIP-3009 (x402 compatible)
   - Batch minting + automatic liquidity deployment
   - Integrates with Uniswap V4

3. **FeeCollectorHook.sol**
   - Uniswap V4 Hook
   - Charges 0.05% platform fee on each swap
   - Fees accumulate in platform treasury

### Interfaces

- `ITokenFactory.sol`: Factory contract interface
- `IX402Token.sol`: Token contract interface

## 🛠️ Development

### Install Dependencies

```bash
# Install Foundry dependencies
forge install OpenZeppelin/openzeppelin-contracts
forge install Uniswap/v4-core
forge install Uniswap/v4-periphery
forge install Uniswap/permit2
forge install foundry-rs/forge-std
```

### Compile

```bash
forge build
```

### Testing

```bash
# Run all tests
forge test

# Run specific tests
forge test --match-contract X402TokenTest

# View gas report
forge test --gas-report

# View coverage
forge coverage
```

### Deployment

#### Base Sepolia (Testnet)

```bash
# 1. Deploy implementation contract
forge script script/DeployImplementation.s.sol \
    --rpc-url base-sepolia \
    --broadcast \
    --verify

# 2. Deploy Hook
forge script script/DeployHook.s.sol \
    --rpc-url base-sepolia \
    --broadcast \
    --verify

# 3. Deploy factory contract
forge script script/DeployFactory.s.sol \
    --rpc-url base-sepolia \
    --broadcast \
    --verify
```

#### Base Mainnet

```bash
# Use the same scripts, replace with --rpc-url base
```

## 📝 Contract Addresses

### Base Sepolia

| Contract | Address |
|----------|---------|
| X402Token (Implementation) | `0x...` |
| FeeCollectorHook | `0x...` |
| TokenFactory | `0x...` |

### Base Mainnet

| Contract | Address |
|----------|---------|
| X402Token (Implementation) | `TBD` |
| FeeCollectorHook | `TBD` |
| TokenFactory | `TBD` |

## 🏗️ Architecture Overview

### EIP-1167 Clone Pattern

To reduce deployment costs, using Minimal Proxy (EIP-1167) clone pattern:

```
TokenFactory (deployed once)
    |
    ├─→ Clone 1 (X402Token instance)
    ├─→ Clone 2 (X402Token instance)
    └─→ Clone 3 (X402Token instance)

Each Clone is only ~200 bytes, deployment cost < 1000 gas
```

### Initializable Pattern

Since the Clone pattern doesn't support constructors, X402Token uses the Initializable pattern:

```solidity
// Traditional pattern
constructor(params) { ... }

// Initializable pattern
function initialize(params) external initializer {
    // Can only be called once
}
```

### Key Modifications

Modifications from Ping.sol to X402Token.sol:

1. **Inheritance changes**:
   ```solidity
   // Before
   contract Ping is ERC20, ...

   // After
   import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
   contract X402Token is Initializable, ERC20Upgradeable, ...
   ```

2. **immutable → storage**:
   ```solidity
   // Before
   uint256 internal immutable MINT_AMOUNT;

   // After
   uint256 internal MINT_AMOUNT;  // Set in initialize()
   ```

3. **constructor → initialize**:
   ```solidity
   // Before
   constructor(uint256 _mintAmount, ...) ERC20("Ping", "PING") { ... }

   // After
   function initialize(
       string memory name,
       string memory symbol,
       uint256 _mintAmount,
       ...
   ) external initializer {
       __ERC20_init(name, symbol);
       __EIP712_init(name, "1");
       ...
   }
   ```

## 🔒 Security Considerations

### EIP-3009 Security

- ✅ Time window validation (validAfter, validBefore)
- ✅ Nonce prevents replay attacks
- ✅ EIP-712 structured signatures
- ✅ receiveWithAuthorization prevents front-running

### Clone Security

- ✅ initialize() uses `initializer` modifier to prevent re-initialization
- ✅ Global constants remain in implementation contract
- ✅ Validates initialization parameters

### Access Control

- ✅ MINTER_ROLE held by backend
- ✅ DEFAULT_ADMIN_ROLE transferred to multi-sig wallet
- ✅ Hook only allows tokens created by Factory

## 📚 References

- [EIP-3009 Specification](https://eips.ethereum.org/EIPS/eip-3009)
- [EIP-1167 Minimal Proxy](https://eips.ethereum.org/EIPS/eip-1167)
- [Uniswap V4 Hooks](https://docs.uniswap.org/contracts/v4/overview)
- [OpenZeppelin Initializable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#Initializable)
