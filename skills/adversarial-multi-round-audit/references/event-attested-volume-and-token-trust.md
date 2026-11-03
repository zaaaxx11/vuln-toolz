# Event-attested volume: when the contract trusts a token's RETURN VALUE as proof of transfer

The class of bug where a deposit/credit contract emits an accounting event using the
**requested `amount` parameter** instead of a **measured balance delta**, so a
non-standard token (lying `transferFrom`, fee-on-transfer, rebasing) produces an event
that over-states what actually arrived. This is the "backend credits from the event"
attack surface — the shape that turns a deposit endpoint into free credit.

Companion to `references/helper-exemption-and-allowance-bypass.md` (which covers
*allowance* trust) and `references/decode-and-proof-traps.md` (which covers decode
trust). This file covers **transfer-effect** trust.

---

## §1 — The source pattern, and how to spot it in 30 seconds

```solidity
// RelayDepository.sol L118-131 (live target pattern)
function depositErc20(address depositor, address token, uint256 amount, bytes32 id) public {
  token.safeTransferFrom(msg.sender, address(this), amount);       // L125
  address depositorAddress = depositor == address(0) ? msg.sender : depositor;  // L127
  emit RelayErc20Deposit(depositorAddress, token, amount, id);     // L130  <-- amount PARAM
}
```

Three independent weaknesses stack here, and each is separately reportable:

| # | Weakness | Why it matters |
|---|---|---|
| 1 | `amount` in the event is the **parameter**, not `balanceOf(this)` after − before | any token whose `transferFrom` moves less (or nothing) still emits the full figure |
| 2 | `safeTransferFrom` (Solady/OW) verifies **success + return data**, never the delta | a token returning `true` without moving passes cleanly |
| 3 | `depositor` is a **free parameter**, unvalidated against `msg.sender` | whoever the caller names gets the credit → attacker names themselves |

Add "no token whitelist" and you have four. Grep the source for the tell:

```
grep -n "emit .*Deposit\|emit .*Credit" -A2 -B6 contract.sol
# look for: emit X(depositor, token, amount, id) where `amount` is a function arg
# and no `uint256 balBefore = token.balanceOf(address(this));` anywhere above it
```

**Fix signature (what good code looks like):**

```solidity
uint256 before = IERC20(token).balanceOf(address(this));
token.safeTransferFrom(msg.sender, address(this), amount);
uint256 received = IERC20(token).balanceOf(address(this)) - before;
require(received > 0, ZeroReceived());
emit Deposit(depositorAddress, token, received, id);   // measured, not requested
```

---

## §2 — The forge PoC that makes it undeniable (two fixtures, both cheap)

Do not argue the mechanism from source. Two fixture tokens and two tests settle it.

```solidity
contract FakeToken {                    // returns true, moves NOTHING
  mapping(address=>uint256) public balanceOf;
  function mint(address t, uint256 a) external { balanceOf[t] += a; }
  function approve(address s, uint256 a) external returns (bool) { return true; }
  function transferFrom(address, address, uint256) external pure returns (bool) { return true; }
  function transfer(address, uint256) external pure returns (bool) { return true; }
}

contract FeeToken {                     // moves 90%
  mapping(address=>uint256) public balanceOf;
  function transferFrom(address f, address t, uint256 a) external returns (bool) {
    balanceOf[f] -= a;
    balanceOf[t] += a - (a / 10);
    return true;
  }
}
```

Test A — lying token: deposit 1,000,000e6, then assert **both** facts:

```solidity
vm.recordLogs();
dep.depositErc20(victim, address(fake), 1_000_000e6, id);
Vm.Log[] memory logs = vm.getRecordedLogs();
assertEq(fake.balanceOf(address(dep)), 0, "no funds moved");        // EFFECT
// parse the log and print amount -> 1000000000000                    // ATTESTATION
```

Test B — fee token: `assertEq(fee.balanceOf(address(dep)), 900_000e6)` while the event
says `1_000_000e6`. The **gap between the two numbers is the bug**, printed side by side.

Foundry gotchas hit while writing this (both cost a compile cycle):

- `Vm.Log[]` needs `import {Test, console, Vm} from "forge-std/Test.sol";` — `Vm` is not
  re-exported by the bare `Test` import in some forge-std versions.
- `bytes memory` does **not** support slice syntax (`data[0:32]`); slicing is
  calldata-only. Use an assembly word reader instead:

```solidity
function word(bytes memory d, uint256 i) internal pure returns (bytes32 r) {
  assembly { r := mload(add(add(d, 32), mul(i, 32))) }
}
```

---

## §3 — Grading: why this is MEDIUM and not CRITICAL (say it in the finding)

The contract-side defect is **PROVEN**. The exploit is **not**, because the credit logic
lives off-chain:

```
PROVEN (in-code)     : event over-states received volume for non-standard tokens;
                       depositor field is caller-controlled with no verification.
UNPROVEN (external)  : the backend indexes `RelayErc20Deposit.amount` and credits on it.
                       Backend source/endpoint not reachable from the audit.
```

Exploitation needs **both**: (a) a non-standard / attacker-deployed token accepted by
the system, **and** (b) a backend that trusts the event's `amount`. Neither is
demonstrable on-chain alone.

Rules for the report:

- Label `IN-CODE PROVEN / EXTERNAL-DEPENDENT — UNPROVEN`, and name exactly which external
  fact would promote it. Do not let the forge PASS imply end-to-end exploitability.
- **Support the negative with a census.** If every token actually observed on mainnet is
  a standard one (4 tokens, 0 zero-amount events, 0 duplicate ids across 19k events), say
  that — it converts "theoretical" into "no historical exploitation observed", which is
  the honest and more useful statement.
- The `depositor`-free-parameter half is graded separately: by itself it is a
  **donation/attribution** feature (aggregators, relayers, payment processors legitimately
  name themselves or a third party), not theft — because funds still land in the
  depository, not in `depositor`. Keep the two halves on separate lines.

---

## §4 — Distinguishing a legit volume processor from a victim (decides the whole round)

The same ledger question — "who is this address receiving 678 deposits / 19.4M" — reads
as victim-drain or as infrastructure depending on three measurements. Take all three
before writing a single word.

```
tx.from of the deposit txs  == the credited depositor   -> self-deposit loop, legit
                            all distinct (N senders)    -> aggregator/relayer, legit
                            MIXED, from a small set     -> investigate further
amount distribution         tightly clustered, repetitive -> settlement / same order size
                            wildly scattered, round     -> retail user flow
token                       one dominant token           -> processor
                            spread of unrelated tokens   -> investigate (possible junk airdrop farming)
```

Real data from the session: 40/40 sampled `tx.from == depositor` (self-deposit), all 678
events on one token (USDC native), amounts clustered in a ~12k-unit band → **payment
processor**, verdict REFUTED/architecture. The earlier round had seen `depositor != tx.from`
in 35/40 **of a different address's** events — both patterns are legitimate, they are just
different roles. Never assume one arm's sample describes the other.

---

## §5 — Vanity-constant dependencies: verify the impl, not just the code size

A dependency pinned as a `constant` in the audited source (`GATEWAY_MINTER = 0x2222…`)
must be verified **live**, and a small/odd code size must be resolved to an
implementation address before you judge it.

Two failure modes that look identical at the RPC layer:

```
163-byte code + nonce 1 + 0 balance   -> could be  (a) EIP-1167 clone
                                                    (b) EIP-7702 designator
                                                    (c) ERC-1967 proxy
```

Decode in this order, and never stop at "163 bytes, looks like a stub":

```python
b = bytes.fromhex(code[2:])
if b[:3] == b'\xef\x01\x00':                 impl = '0x'+b[3:23].hex()      # EIP-7702
elif b[:10] == bytes.fromhex('363d3d373d3d3d363d73'): impl = '0x'+b[10:30].hex()  # 1167
else:                                        # ERC-1967 → read the slot
    impl = '0x' + rpc('eth_getStorageAt',[addr,
        '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc','latest'])[-40:]
```

Then **confirm the expected function exists on the impl** by hashing its signature and
intersecting with the impl's PUSH4 set:

```text
GATEWAY_WALLET impl 0xeb4ea463…  depositFor(address,address,uint256)  0xb3db428b ✅
                                 isTransferSpecHashUsed(bytes32)      0x17580158 ✅
GATEWAY_MINTER impl 0xc2ff6806…  gatewayMint(bytes,bytes)             0x9fb01cc5 ✅
                                 mint(address,uint256)                0x40c10f19 ✅
```

**Two proxies with identical runtime code and different impls is normal** — report both
impls separately; never infer "same code ⇒ same contract". And a presence-hit on
`mint(address,uint256)` in the impl's selector set is a **hypothesis**, not a finding:
the gate may be `onlyMinter`/circle-attestation offline. Probe it (`eth_call` from an
attacker address, expect a revert whose selector names the gate) before writing anything.

---

## §6 — A `call{value}` sink after an external mint is a reentrancy question, every time

Pattern seen in the Gateway variant:

```solidity
callRequests[structHash] = true;                 // L270 dedup set BEFORE
GATEWAY_MINTER.gatewayMint(payload, sig);        // L273 EXTERNAL CALL
_executeCalls(structHash, request.calls);        // L288 → c.to.call{value}(c.data)  L350
```

Two facts worth checking, and one thing worth *not* claiming:

1. `callRequests[structHash]` set **before** the call ⇒ same-structHash replay is closed.
   Verify it, don't assume — evaluate the mapping on a fork for sampled historical
   requests and bucket `{sig valid} × {already used} × {not expired}`.
2. No global `nonReentrant` ⇒ nested `execute()` with a **different** structHash lands.
   Proven cheaply by signing **two** requests in a local harness and re-entering from
   `receive()`. Output shape: `depth = 2`, beneficiary paid twice from one tx.
3. **Do not upgrade that to HIGH.** Nesting requires two valid allocator signatures. It is
   a defense-in-depth gap for a batching allocator, and the prerequisite belongs in the
   same sentence as the severity (`MEDIUM — requires 2 signatures`).

Also: `_validateGatewayAttestation`-style helpers that only compare
`keccak256(payload[HEADER:]) == expectedHash` are **pre-checks**, not signature
verification. The real verification is the downstream `gatewayMint`
(Circle/attestation service). Reading the helper alone and declaring "attestation can be
forged" is wrong — check whether the call that consumes the payload verifies it, and
check `isTransferSpecHashUsed` both **pre** and **post** consume.

---

## §7 — Sub-selector mismatch symptom: when the interesting function is present but gated away

A `depositErc20` overload that **skips** a `depositsEnabled` gate present on the sibling
overload is a real asymmetry worth a LOW:

```text
depositErc20(address,address,uint256,bytes32) L186  checks depositsEnabled (L192)  ✅ gated
depositErc20(address,address,bytes32)         L218  NO check; amount = allowance(msg.sender, this) (L223)
```

Impact framing that survives scrutiny: it lets anyone trigger a deposit **for another
user's own allowance** — funds still flow to the protocol, `depositor` in the event is
whatever the caller names. Grade `LOW (gas griefing + wrong-name event)`, never
"allowance theft": the allowance read is `msg.sender`'s own budget, matching the rule in
`helper-exemption-and-allowance-bypass.md` §2.
