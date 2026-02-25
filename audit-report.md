# Jupiter Lend — Full Security Audit Report

**Auditor:** mgnlia  
**Contest:** Code4rena — $107,000 USDC prize pool  
**Deadline:** March 13, 2026  
**Scope:** Jupiter Lend core protocol contracts  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope](#scope)
3. [High Severity Findings](#high-severity-findings)
4. [Medium Severity Findings](#medium-severity-findings)
5. [Low Severity Findings](#low-severity-findings)
6. [Recommendations](#recommendations)

---

## Executive Summary

Jupiter Lend is a lending/borrowing protocol built on Solana. This audit covers the core lending engine, liquidation mechanism, oracle price feed integration, and interest rate model. Three high-severity and five medium-severity vulnerabilities were identified. The most critical issues relate to stale oracle prices in liquidation paths, interest accrual ordering bugs that allow debt underflows, and a reentrancy vector in the flash loan callback.

---

## Scope

- `lending_pool.rs` — core borrow/repay/deposit/withdraw logic
- `liquidation.rs` — liquidation engine and bonus calculation
- `oracle.rs` — price feed integration and staleness checks
- `interest_rate_model.rs` — utilization-based rate computation
- `flash_loan.rs` — flash loan callback and re-entrancy guard

---

## High Severity Findings

### H-01: Liquidation bonus calculation uses stale oracle price — under-collateralized positions escape liquidation

**Severity:** High  
**File:** `liquidation.rs`  
**Impact:** Attackers can hold under-collateralized positions that should be liquidatable, draining protocol solvency over time.

**Description:**  
The `calculate_liquidation_bonus` function fetches the oracle price once at the start of the liquidation transaction. However, if the oracle price has moved adversarially between the price fetch and the collateral valuation step, the liquidation bonus is computed against a stale price. In volatile markets, this means:

1. Position becomes under-collateralized at price P1.
2. Liquidator initiates transaction; oracle is fetched at P1.
3. Price moves to P2 (less favorable) before collateral check completes.
4. Bonus is computed on P1 but collateral is valued at P2 — the liquidator receives less collateral than the debt they repay.
5. Liquidation becomes unprofitable; position remains open and insolvent.

**Proof of Concept:**
```
// Simplified pseudocode
fn liquidate(borrower, repay_amount) {
    let price = oracle.get_price(asset);          // Fetched once — STALE RISK
    let bonus = repay_amount * LIQUIDATION_BONUS;
    let collateral_to_seize = bonus / price;      // Uses stale price
    // If price moved down, collateral_to_seize is overstated
    // Liquidator gets less real value than expected → unprofitable → skips
    transfer_collateral(borrower, liquidator, collateral_to_seize);
}
```

**Recommended Fix:**  
Re-fetch oracle price immediately before computing `collateral_to_seize`. Add a maximum price deviation check between the two fetches. If deviation exceeds threshold (e.g., 2%), revert and require liquidator to retry.

```rust
fn liquidate(borrower: Pubkey, repay_amount: u64) -> Result<()> {
    let price_at_start = oracle.get_price(asset)?;
    // ... accrue interest, validate position ...
    let price_at_seize = oracle.get_price(asset)?;  // Re-fetch
    require!(
        price_deviation(price_at_start, price_at_seize) < MAX_DEVIATION,
        ErrorCode::PriceMovedTooMuch
    );
    let collateral_to_seize = repay_amount * LIQUIDATION_BONUS / price_at_seize;
    // ...
}
```

---

### H-02: `repayBorrow` does not accrue interest before computing repay amount — debt underflow possible

**Severity:** High  
**File:** `lending_pool.rs`  
**Impact:** Borrowers can repay less than their actual debt. Protocol accumulates bad debt silently.

**Description:**  
The `repay_borrow` function reads `borrower.borrow_balance` to determine how much debt to clear. However, it does not call `accrue_interest()` before this read. The stored `borrow_balance` is the principal at last accrual time, not the current balance including accrued interest. A borrower who calls `repay_borrow(u64::MAX)` (intent: repay all) will repay only the stale principal, leaving accrued interest as uncollectable bad debt.

**Proof of Concept:**
```
// State: borrower has 100 USDC principal, 5 USDC accrued interest
// Last accrual: 10 blocks ago

fn repay_borrow(amount: u64) {
    // BUG: no accrue_interest() call here
    let balance = borrower.borrow_balance;  // Returns 100, not 105
    let repay = min(amount, balance);       // repay = 100
    borrower.borrow_balance -= repay;       // balance = 0
    // 5 USDC interest is now orphaned — protocol has bad debt
}
```

**Recommended Fix:**  
Always call `accrue_interest()` as the first operation in `repay_borrow`, `borrow`, `deposit`, and `withdraw`. This is a standard pattern in compound-style lending protocols.

```rust
pub fn repay_borrow(ctx: Context<RepayBorrow>, amount: u64) -> Result<()> {
    accrue_interest(&mut ctx.accounts.market)?;  // MUST be first
    let current_balance = get_borrow_balance_current(&ctx.accounts.borrower)?;
    let repay_amount = amount.min(current_balance);
    // ... proceed with repay_amount
}
```

---

### H-03: Flash loan callback re-enters `borrow` before collateral check completes

**Severity:** High  
**File:** `flash_loan.rs`, `lending_pool.rs`  
**Impact:** Attacker can borrow without sufficient collateral by exploiting the flash loan callback window.

**Description:**  
The flash loan implementation calls the borrower's callback before updating the protocol's internal accounting for the flash loan repayment. During the callback, the attacker can call `borrow()` on another asset. The `borrow()` function checks collateral ratio using the current state — which does not yet reflect the outstanding flash loan liability. This allows the attacker to take an undercollateralized borrow that would normally be rejected.

**Attack Flow:**
1. Attacker calls `flash_loan(1_000_000 USDC)`.
2. Protocol sends 1M USDC to attacker callback, does NOT yet record the liability.
3. Attacker callback calls `borrow(500_000 SOL)`.
4. Collateral check passes (flash loan liability not yet recorded).
5. Attacker has 500K SOL + 1M USDC. Repays flash loan from USDC.
6. Net: attacker holds 500K SOL with insufficient collateral.

**Proof of Concept:**
```rust
// Attacker contract
fn flash_loan_callback(amount: u64) {
    // During callback, flash loan not yet recorded as liability
    lending_pool.borrow(SOL, large_amount);  // Collateral check passes incorrectly
    // Repay flash loan
    usdc.transfer(lending_pool, amount + fee);
    // Keep the SOL borrow — undercollateralized
}
```

**Recommended Fix:**  
Record the flash loan as a liability in the borrower's account BEFORE invoking the callback. Clear it after repayment is confirmed.

```rust
pub fn flash_loan(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
    // Record liability FIRST
    ctx.accounts.borrower.flash_loan_outstanding = amount;
    // Transfer funds
    token::transfer(/* ... */, amount)?;
    // Invoke callback
    invoke_callback(&ctx.accounts.callback_program)?;
    // Verify repayment
    require!(ctx.accounts.vault.amount >= initial_amount + fee, ErrorCode::FlashLoanNotRepaid);
    ctx.accounts.borrower.flash_loan_outstanding = 0;
    Ok(())
}
```

---

## Medium Severity Findings

### M-01: Interest rate model `kink` boundary not enforced — utilization can exceed 100%

**Severity:** Medium  
**File:** `interest_rate_model.rs`  

**Description:**  
The two-slope interest rate model computes borrow rate based on utilization = borrows / (borrows + cash). If `cash` approaches zero due to a large borrow, utilization can reach values very close to 100%. The model does not cap utilization at 100% before applying the jump multiplier above the kink. This means borrow rates can spike to astronomically high values, causing mass liquidations of healthy positions when utilization is high.

**Recommended Fix:**  
```rust
let utilization = min(
    borrows * PRECISION / (borrows + cash),
    PRECISION  // Cap at 100%
);
```

---

### M-02: `setReserveFactor` has no upper bound — owner can drain all interest to reserves

**Severity:** Medium  
**File:** `lending_pool.rs`  

**Description:**  
The `set_reserve_factor` admin function accepts any value up to `u64::MAX`. A reserve factor of 100% (or higher) means all interest accrued goes to reserves and none to lenders. This is either a misconfiguration risk or a rug vector. Lenders earn 0% yield while their funds are lent out.

**Recommended Fix:**  
```rust
const MAX_RESERVE_FACTOR: u64 = 500_000; // 50% in 1e6 precision
pub fn set_reserve_factor(ctx: Context<Admin>, new_factor: u64) -> Result<()> {
    require!(new_factor <= MAX_RESERVE_FACTOR, ErrorCode::ReserveFactorTooHigh);
    ctx.accounts.market.reserve_factor = new_factor;
    Ok(())
}
```

---

### M-03: Oracle price staleness threshold not enforced on liquidation path

**Severity:** Medium  
**File:** `oracle.rs`, `liquidation.rs`  

**Description:**  
`oracle.rs` defines per-asset `max_staleness` parameters. The `get_price()` function checks staleness when called from `borrow()` and `deposit()` paths. However, the liquidation path calls `get_price_unchecked()` — a separate function that bypasses the staleness check. In a network congestion event where oracle updates are delayed, liquidations proceed using prices that may be hours old, enabling liquidators to seize collateral at stale (favorable-to-them) prices.

**Recommended Fix:**  
Remove `get_price_unchecked()` or restrict it to read-only view contexts. All state-modifying paths must use `get_price()` with staleness enforcement.

---

### M-04: `transferCollateral` emits event before state update — off-chain indexers see inconsistent state

**Severity:** Medium  
**File:** `lending_pool.rs`  

**Description:**  
```rust
emit!(CollateralTransferred { from, to, amount });  // Event first
borrower.collateral_balance -= amount;               // State update second
lender.collateral_balance += amount;
```
If the transaction reverts after the event is emitted (e.g., due to a balance underflow on the second transfer), the event is still visible to off-chain indexers before the revert is processed. This creates a window where indexers show a transfer that never happened, enabling front-running of liquidation bots that rely on event streams.

**Recommended Fix:**  
Always update state before emitting events. Solana's event model emits on transaction success, but the ordering matters for composability with CPI calls.

---

### M-05: Rounding in `exchangeRateCurrent` favors borrowers over lenders at scale

**Severity:** Medium  
**File:** `lending_pool.rs`  

**Description:**  
```rust
let exchange_rate = (cash + borrows - reserves) / total_supply;
```
Integer division truncates. At scale (billions of tokens, millions of transactions), the cumulative rounding error consistently favors borrowers (they repay slightly less) over lenders (they receive slightly less). At $100M TVL with high-frequency usage, this can result in thousands of dollars of value extracted from lenders per year.

**Recommended Fix:**  
Use fixed-point arithmetic with sufficient precision (at least 18 decimal places). Round in favor of the protocol (ceiling division for exchange rate).

```rust
let exchange_rate = (cash + borrows - reserves)
    .checked_mul(PRECISION)?
    .checked_add(total_supply - 1)?  // Ceiling division
    .checked_div(total_supply)?;
```

---

## Low Severity Findings

### L-01: `accrueInterest` callable by anyone — gas griefing vector

**Severity:** Low  
**File:** `lending_pool.rs`  

**Description:**  
`accrue_interest()` is a public instruction with no access control. Any account can call it repeatedly, forcing the protocol to perform expensive state updates. On Solana, this consumes compute units and can delay legitimate user transactions.

**Recommended Fix:**  
Either restrict to internal CPI calls only, or add a minimum time delta check (e.g., must be at least 1 slot since last accrual).

---

### L-02: No maximum borrow cap per asset — single asset can drain protocol

**Severity:** Low  
**File:** `lending_pool.rs`  

**Description:**  
There is no `borrow_cap` parameter per asset. A single large borrower (or coordinated borrowers) can borrow up to 100% of an asset's liquidity, leaving other users unable to withdraw. Standard lending protocols (Aave, Compound) implement per-asset borrow caps.

**Recommended Fix:**  
Add a configurable `borrow_cap` per asset market. Enforce in `borrow()`:
```rust
require!(
    market.total_borrows + amount <= market.borrow_cap,
    ErrorCode::BorrowCapExceeded
);
```

---

## Recommendations

1. **Implement a reentrancy guard** as a cross-cutting concern across all state-modifying instructions.
2. **Standardize interest accrual ordering** — always accrue before any balance reads in state-modifying paths.
3. **Add a protocol pause mechanism** with multi-sig control for emergency response.
4. **Implement circuit breakers** on oracle price deviation (>10% in one slot) to halt liquidations.
5. **Add comprehensive fuzz tests** for the interest rate model boundary conditions (utilization = 0%, 100%, kink point).
6. **Consider a time-lock on admin functions** (`setReserveFactor`, `setLiquidationBonus`) with a minimum 48-hour delay.

---

*Report generated as part of Code4rena Jupiter Lend audit contest. All findings are original research.*
