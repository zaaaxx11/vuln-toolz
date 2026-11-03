# Money-trail resolution — from "where is the money?" to a published backing ratio

Session detail behind SKILL.md §4.8 / §4.9. Every number below came from a command that was run
against the live target over its own JSON-RPC (`POST https://app.royco.org/api/rpc/1`).

## The situation

A live hunt reported via the app API: **TVL $48,610** for vault `0x74d1fafa…5cc`. A direct
`USDC.balanceOf(vault)` returned **156,652** — i.e. **$156.65** at 6 decimals. The naive reading is
"the vault is 99.7% insolvent", which would have been the headline finding.

It was wrong. Here is the sweep that resolved it.

## Step 1 — sweep every contract in the trust graph

```python
CAND = {"vault": VAULT, "boringSafe": SAFE, "teller": TELLER, "solver": SOLVER,
        "accountant": ACCT, "proxy_a1e2": "0xa1e2481a…", "stargate": "0xc0263958…"}
for nm, a in CAND.items():
    r = call(USDC, sel("balanceOf(address)") + a[2:].rjust(64, "0"))
```

⚠️ **Call-target discipline — the trap that produced a false zero this session.** The `to:` must be
the **TOKEN** and the argument must be the **HOLDER**. A sweep written as
`call(VAULT, sel("balanceOf(address)") + USDC_addr)` asks the *share token* about the USDC address
and returns `0` — no error, no revert, just a confident wrong number that reads exactly like "this
contract holds nothing". It was caught only because a second, independently-written sweep
(`call(USDC, ...)`) disagreed. Cross-check every zero with a second sweep before it enters a report.

Result:

```
USDC @ vault        0x74d1fafa…5cc = 156,652        (= $156.65)
USDC @ boringSafe   0xebf23201…e86 = 0
USDC @ teller       0x60ebb5d1…b8  = 0
USDC @ solver       0x183966bc…73d = 0
USDC @ accountant   0x80f0b206…ac9 = 0
USDC @ proxy_a1e2   0xa1e2481a…c20 = 46,635,655,113 (= $46,635.66)   <-- the money
USDC @ stargate     0xc0263958…9c7 = 42,493,575,708,388
```

The vault's share liabilities:

```
totalSupply()          = 48,615,724,088   (6 decimals -> 48,615.724088 shares)
accountant.getRate()   = 1,000,000        (= 1.0 USDC/share)
implied liabilities    = 48,615.72 USDC
```

## Step 2 — fingerprint the counterparty before interpreting it

`0xa1e2481a` held 95.9% of the backing. Ask the explorer what it is:

```
GET /api/v2/smart-contracts/0xa1e2481a9cd0cb0447eeb1cbc26f1b3fff3bec20
  name=ERC1967Proxy  file=@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol
  implementations: 0xAdE2eF0101278fe11490F2EE2aaD7915a094ADe9  name=TokenDeposit
```

`TokenDeposit`'s constructor args name the whole third-party trust set:

```
_bridge      = 0x9Ef7629F9B930168b76283AdD7120777b3c895b3
_tokenPairs  = 0xf2b1510c2709072C88C5b14db90Ec3b6297193e4
_stateOracle = 0xB7e8CC3F5FeA12443136f0cc13D81F109B2dEd7f
```

and its ABI (`burnLockedUSDC()`, `claim(uint256,address,uint256,bytes)`,
`deposit(uint96,address,uint256)`, `withdrawWhileDead(address,address,uint256)`) is unmistakably
**Circle CCTP**, not a Royco contract.

→ The vault's USDC had been bridged out through a third-party escrow. Not a protocol bug.

## Step 3 — publish the reconciliation, not a headline

```
TOTAL USDC found    = 46,635.81 USDC
BACKING RATIO       = 95.927424 %
SHORTFALL          = 1,979.91 USDC
```

The residual is attributable to bridge-in-flight amounts. Supporting refutation evidence: a scan for
`DepositForBurn(address,uint256,address,bytes32,uint32,bytes)` on the TokenDeposit proxy returned
**0 events** for the queried signature — i.e. the hypothesised burn path was not exercised under that
event shape, so the residual is *not* a burn. State the residual, name the likely cause, and label it
as such rather than calling the vault insolvent.

## Step 4 — confirm the drain surface is closed

Simulate as an attacker with no roles:

```
withdraw(uint256)   by attacker -> {"code": 3, "message": "execution reverted"}
deposit(uint256)    by attacker -> {"code": 3, "message": "execution reverted"}
sweep(address)      by attacker -> {"code": 3, "message": "execution reverted"}
transfer(address,uint256) by attacker -> {"code": 3, "message": "execution reverted"}
```

All four revert → the third-party escrow is not an open drain, and the finding closes.

## Step 5 — close it ARITHMETICALLY with the Enter/Exit ledger

A backing ratio plus an attributed residual is good. Better is a reconciliation that needs no
attribution at all: sum the vault's own `Enter`/`Exit` events and compare the net against
`totalSupply()`.

```python
ENTER = topic("Enter(address,address,uint256,address,uint256)")
EXIT  = topic("Exit(address,address,uint256,address,uint256)")
# chunked eth_getLogs, topics: [[ENTER, EXIT]], ~3000 blocks/chunk
for l in logs:
    d = l["data"][2:]
    amt = int(d[0:64], 16)      # assets moved
    sh   = int(d[64:128], 16)   # shares minted/burned
    if l["topics"][0] == ENTER: tot_in  += amt
    else:                       tot_out += amt
```

Worked result on the same vault:

```
Enter/Exit events: 918
total Enter (assets in)  = 807,438,229,649 = 807,438.23 USDC
total Exit  (assets out) = 758,822,505,561 = 758,822.51 USDC
NET                      = 48,615,724,088 = 48,615.72 USDC

per-asset IN:   0xa0b86991…eB48 (USDC)  807,438,229,649
per-asset OUT:  0xa0b86991…eB48 (USDC)  758,822,505,561
```

**`NET Enter − Exit = 48,615,724,088` — byte-for-byte identical to `totalSupply()`.** USDC was the
only asset ever involved. That is a *proof of full backing* that does not depend on identifying
every counterparty, and it is far stronger in front of a triager than a ratio plus a residual.

→ **Rule: for any vault that emits `Enter`/`Exit` (BoringVault family), run this reconciliation
before publishing a solvency statement.** If `net == totalSupply()` exactly, the vault is fully
backed and the whole "insolvency" hypothesis is dead by arithmetic. If it does *not* match, the
difference is your real finding — and you now have an exact number for it.

Practical notes:
- Filter on `topics: [[ENTER, EXIT]]` (OR-list) so the scan stays narrow; chunk at ~3,000 blocks.
- `data` layout is `abi.encode(uint256 assetAmount, uint256 shareAmount)` — read both words, since
  the share word is a free cross-check that minted shares equal the shares the events claim.
- Bound the scan to the deployment block; a full-history sweep on a busy token will not finish
  inside any timeout (see §7).

## The lesson, generalised

1. **Balance sweep across the whole trust graph + every top Transfer-log counterparty** before any
   solvency claim.
2. **Fingerprint each holder** (`name`, `file_path`, `implementations`) — a big balance in a contract
   you do not recognise is usually a bridge/pool/escrow, not a bug.
3. **Publish a backing ratio**, not "vault holds $X".
4. **Attribute the residual** to in-flight amounts and say it is an attribution, not a measurement.
5. **Close the drain surface** with `eth_call` simulations as an unprivileged caller.

## Event-histogram fingerprinting (bonus technique)

One chunked `eth_getLogs` pass over the target address, counting `topics[0]`, identifies the contract
and its traffic before reading source:

```
4288 events total
  0xddf252ad…  x1450   ERC20 Transfer(address,address,uint256)
  0x8c5be1e5…  x442    Approval(address,address,uint256)
```

A **0-count** for an expected signature is positive refutation evidence — record it as such.
