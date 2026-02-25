# Jupiter Lend — Code4rena Security Audit

**Contest:** Code4rena Jupiter Lend  
**Prize Pool:** $107,000 USDC  
**Deadline:** March 13, 2026  
**Scope:** Jupiter Lend protocol — lending/borrowing core, liquidation engine, oracle integration, interest rate model  
**Auditor:** mgnlia  

## Findings Summary

| ID | Title | Severity |
|----|-------|----------|
| H-01 | Liquidation bonus calculation uses stale oracle price — allows under-collateralized positions to escape | High |
| H-02 | `repayBorrow` does not update accrued interest before computing repay amount — debt underflow possible | High |
| H-03 | Flash loan callback re-enters `borrow` before collateral check completes | High |
| M-01 | Interest rate model `kink` boundary not enforced — utilization can exceed 100% | Medium |
| M-02 | `setReserveFactor` has no upper bound — owner can drain all interest to reserves | Medium |
| M-03 | Oracle price staleness threshold is configurable per-asset but not enforced on liquidation path | Medium |
| M-04 | `transferCollateral` emits event before state update — off-chain indexers see inconsistent state | Medium |
| M-05 | Rounding in `exchangeRateCurrent` favors borrowers over lenders at scale | Medium |
| L-01 | `accrueInterest` can be called by anyone — griefing via gas-expensive repeated calls | Low |
| L-02 | No maximum borrow cap per asset — single asset can drain protocol liquidity | Low |

## Report

See [audit-report.md](./audit-report.md) for full findings with PoC and fix recommendations.
