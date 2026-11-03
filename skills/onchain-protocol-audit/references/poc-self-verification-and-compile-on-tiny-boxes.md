# PoC self-verification: kill your own result before reporting it

Condensed from a Relay Protocol session where **two separate self-inflicted PoC bugs**
produced a "PROVEN CRITICAL" that did not exist, and a "dead contract" verdict on a
contract that was live. Both were caught only by deliberately re-testing the exact same
probe with clean inputs. Read this before writing any finding whose evidence is
"`eth_call` returned 0x…01".

---

## 1. The empty-argument trap (cost: one fake CRITICAL)

A verifier built its calldata as:

```python
data = '0x' + selector + '00' * ((4 + 32 * nargs) - 4)   # ← all zeros, worst case
```

That encodes **zero addresses for every argument**. The contract then answers about
`isOperator(0x0, 0x0)` — which is legitimately `false` — and the operator sees a clean
`0x0000…0000`. A second script that used a proper `ad(addr).rjust(64,'0')` helper returned
`0x…01` for the *same question*. **Two scripts, same contract, opposite answers.**

Rules that prevent this class of error permanently:

- **Never hand-format calldata inline in a one-liner.** One helper, used by every probe:
  ```python
  def a(x): return x[2:].lower().rjust(64, "0")   # address → 32-byte word
  def w(n): return int(n).to_bytes(32, "big").hex()
  ```
- **Assert the calldata length before sending.** Expected `4 + 32*nargs` bytes. A serial
  audit probe should print `len(bytes.fromhex(data[2:]))` next to the result.
- **Re-run every "0x0 / false / not found" result through a known-positive control.** If
  you can't make the function return `true` for an input where it *must* be true, your
  encoder is broken — not the contract.
- **Duplicate results are not confirmation.** When the runtime says
  `[duplicate tool result]`, that call did not execute. Re-issue it; never cite it.

### Cross-script disagreement is a hard stop
If script A says `true` and script B says `false` for the same address pair, **stop and
reconcile before reporting either**. Print the raw `data` hex and the raw JSON response
side by side. It is always an encoding difference, never a chain-state difference.

---

## 2. The "value moved between two calls" illusion

`eth_call` **state overrides reset on every call**. Sequence below looks like a failed
transfer but proves nothing:

```
call 1: transferFrom(victim→attacker, 600000) from=ALLOC   → 0x…01  (true)
call 2: balanceOf(victim)                                  → 1000000   ← unchanged!
call 3: balanceOf(attacker)                                → 0         ← unchanged!
```

Nothing is broken; each call started from the same overridden state. **You cannot observe
a mutation across `eth_call` boundaries.** Options, in order of preference:

1. **Bracket with arithmetic instead of observation.** If `balanceOf[sender] -= amount`
   really ran, then a *separate* call with the post-state override (`balance − amount`)
   attempting to move `amount` again must **underflow-revert**:
   ```
   override slot = 400000   → transferFrom(…, 600000) → panic 0x11   ✅ balance really decreased
   ```
   This is the cheapest atomic proof and needs no deployed helper contract.
2. Deploy a probe contract (or Multicall3) **in the same call chain**. Do not assume
   canonical `Multicall3 0xcA11bde05977b3631167028862bE2a173976CA11` exists — on many L2/app
   chains `eth_getCode` returns `0x` and every `aggregate3` call silently returns `0x`.
   **Check `codesize > 0` before trusting a multicall probe.**
3. Run `anvil --fork-url`, where state genuinely persists between RPC calls.

### Authorization vs. effect — always test both
"Returned `true`" is an authorization result. "Balance decreased" is an effect result.
Report them as separate claims with separate evidence, and include a **negative control**:

| Probe | Expected |
|---|---|
| `transferFrom` from role-less EOA | revert (`panic 0x11` or custom error) |
| `transferFrom` from role holder, allowance 0 | `true` |
| post-state underflow probe | revert ⇒ arithmetic really ran |

If the negative control does not revert, the whole test is invalid.

---

## 3. Read the revert, not just the failure

- `panic 0x11` = arithmetic underflow/overflow → the code **reached** the balance
  arithmetic. Authorization was not the blocker.
- Empty revert data `0x` → selector missing, wrong ABI, or a proxy/fallback. **Not** an
  auth failure. Immediately diff live selectors against the repo ABI (see §5).
- Custom selector → brute it against the repo ABI + OpenZeppelin/Solady error strings
  before inventing an explanation. `0x0964dde4` resolving to *no* known signature in any
  contract in scope meant the error came from a *downstream* call target, not the batcher.
- A revert that appears for a **self-transfer** (`sender == msg.sender`) means the function
  is not the one you think it is. Stop and re-identify the contract.
- **A `0x…01` return is only evidence if you parsed it as a return.** See §8 — a script that
  reads `.get("result")` without checking for `{"error": …}` will happily print "SUCCESS"
  for a call that panicked. Assert the response shape *before* parsing the value.

### Assert the response shape, not just the value

```python
res = rpc("eth_call", [{"to": TO, "data": data}, "latest"])
if "error" in res:                      # ← the bug was not having these two lines
    raise SystemExit(f"REVERT: {res['error']}")
out = res.get("result") or ""
if len(out) < 66:                        # "0x" or truncated
    raise SystemExit(f"NO RETURN DATA: {out!r}")
print(int(out, 16))                      # only now is the number meaningful
```

A boundary sweep is the cheapest way to prove an arithmetic guard is real (§9).

---

## 4. Never accept a subagent's PoC claim; never accept your own

Both bugs above were mine, and the session also had a subagent retract its own
authorization-bypass claim after it discovered its override had patched a **copy** of the
bytecode rather than the tested artifact. Standing rules:

- Independently re-run every decisive probe from a clean script before it enters a report.
- A finding's status is `PROVEN` only with **zero errors and zero blockers**, and only if
  the exact probe you will quote was executed by you, in this session, with visible output.
- When a subagent (or you) later refutes a claim, **downgrade it in the same report** —
  never leave an inflated severity standing next to a corrected one.

---

## 5. Source ≠ deployed bytecode: always reconcile ABIs before believing a PoC

The session's fork test called `balanceOf(address,uint256)` (ERC6909) and got clean
`0x0` returns plus empty reverts. Root cause: the deployed contract at the audited address
did not expose that function at all.

Reconciliation recipe — **but read the contamination warning first.**

> **PUSH4 scanning produces false positives AND false negatives. Do not trust it alone.**
> The naive `PUSH4 == 0x63` sweep below picks up every 4-byte constant that *looks* like a
> selector — memory offsets, Solady/Panic codes, event topic fragments, immutables, and
> selectors belonging to *other* contracts whose creation code is embedded. In one session
> this produced a confident claim that the live Hub "lacks `balanceOf(address,uint256)`
> and `setTokenMetadata`" — **both were present and working.** The scan saw 71 selectors,
> 38 "unknown", and 3 "missing"; the verified explorer source showed 36 functions, all
> present, identical to the repo. The finding was pure instrumentation noise.
>
> **Ground truth order — use the FIRST one that works:**
> 1. **Verified source from the explorer API.** Far cheaper and more reliable than
>    disassembly. e.g. Blockscout: `GET {explorer}/api/v2/smart-contracts/{addr}` →
>    `is_verified`, `abi`, `source_code`. If `is_verified: true`, diff that source against
>    the repo and **skip selector scanning entirely**.
> 2. **Behavioural proof** — call each function and check you get a well-formed return
>    word. `totalSupply` returning `0x…01a7f064` proves the dispatcher entry is real; a
>    PUSH4 constant proves nothing.
> 3. **Linear disassembly** with an actual opcode walker (not a hex substring sweep), so
>    `PUSH32` payloads are consumed as data instead of being re-scanned.
>
> Treat a PUSH4-only result as a *hypothesis generator*, never as a finding. If it claims a
> function is missing, prove it two ways (verified source + a call that reverts `0x`) before
> writing it down.

```python
# Hypotheses only — see warning above before believing any output from this.
code = eth_getCode(addr, 'latest')[2:]
sels = {code[i+2:i+10] for i in range(0, len(code)-8, 2) if code[i:i+2] == '63'}

# 2. Build the repo's selector set from compiled ABI
repo = {keccak(text=f"{e['name']}({','.join(i['type'] for i in e['inputs'])})")[:4].hex(): e
        for e in abi if e['type'] == 'function'}

# 3. Report the three sets
print("in repo, missing live :", sorted(set(repo) - sels))
print("in live, not in repo  :", sorted(sels - set(repo)))
print("bytes  repo/live      :", len(compiled_bytecode)//2, len(code)//2)
```

Interpretation guide:

- **Live has only ERC20 selectors (`70a08231`, `a9059cbb`, `095ea7b3`, `23b872dd`,
  `dd62ed3e`, `18160ddd`, `06fdde03`) while the repo is ERC6909** ⇒ *different contract
  entirely*. Any PoC written against the repo ABI is fiction here.
- **A handful of repo functions missing live** ⇒ the published source is newer/older than
  the deployment. Report this explicitly as an audit caveat; it invalidates every
  source-line-based finding that touches a missing function.
- **Selector present but every call reverts `0x`** ⇒ proxy without EIP-1967 slots, or a
  different contract at that address. Check `eth_getStorageAt` on
  `0x360894a1…382bbc` and scan for the minimal-proxy prefix `363d3d373d3d3d363d73`.
- **`codesize` equal but behaviour differs** ⇒ not a proxy; treat as a separate deployment.

Always state the deployed bytecode size and the repo-compiled size in the report so the
reader can judge whether source-based claims apply.

---

## 6. Compiling a big Foundry monorepo on a 1 GB box

`forge build` over a monorepo with ~200 contracts will OOM-kill a small VPS and take SSH
down with it. Workable recipe found in-session:

```bash
# 1. Provide forge-std without `forge install` (works offline / on air-gapped forks)
ln -sfn /path/to/existing/forge-std  smart-contracts/lib/forge-std

# 2. Pull Solidity deps as tarballs instead of yarn/npm workspaces
npm pack solady@0.1.26
npm pack @openzeppelin/contracts@5.3.0
mkdir -p node_modules/@openzeppelin
tar xzf solady-0.1.26.tgz -C /tmp/e1 && cp -r /tmp/e1/package node_modules/solady
tar xzf openzeppelin-contracts-5.3.0.tgz -C /tmp/e2 && cp -r /tmp/e2/package node_modules/@openzeppelin/contracts

# 3. Compile ONLY what you need — skip tests and scripts
forge build --skip test --skip script

# 4. Read the artifact straight from out/ instead of running the suite
python3 -c "import json;d=json.load(open('out/RelayHub.sol/RelayHub.json'));print(len(d['abi']),len(d['bytecode']['object'])//2)"
```

Key insight: **you rarely need `forge test` — you need the compiled ABI + bytecode** to do
selector reconciliation and calldata encoding. `--skip test` is usually sufficient and
fits in far less memory than a fork run.

If you *do* need a fork: budget **≥2 GB RAM** for a single `--match-test` run and
**≥4 GB** for a suite, plus disk cache. Verify free RAM **before** starting, because an
OOM-killed box loses your uncommitted PoC with it. On shared production hosts, stage work
under a dedicated directory (e.g. `/opt/poc/<target>`) and clean it up afterwards.

---

## 6b. Storage slots: `forge inspect` is ground truth, guessing is not

Every `stateOverride` PoC depends on computing the right slot. In this session three
different slot tables were in play and **two of them were wrong**, which silently
invalidated every override-based result:

- brief assumption: `totalSupply`=5, `_isOperator`=6, `allowance`=7
- another script: `totalSupply`=5, `erc20Views`=6
- **actual** (verified by probe): `_isOperator`=3, `balanceOf`=4, `allowance`=5,
  `totalSupply`=6, `nonces`=7, `erc20Views`=8

An override on the wrong slot doesn't error — it writes to unused storage and your probe
reads the *organic* value, so you get a plausible-looking wrong answer. Never guess.

```bash
forge inspect RelayHub storage-layout            # authoritative, from the compiler
forge inspect RelayHub storage-layout --json
```

**When source is unavailable**, derive by *override-and-observe*, and require a two-sided
result before trusting a base:

1. Override candidate slot with a sentinel (`0x777`) and call the getter → must return `777`.
2. Override a *sibling* candidate and call the same getter → must be **unchanged**.
3. Override the slot and read a **different contract** that proxies to it (e.g. the ERC20
   view calling `hub.balanceOf`) → the value must propagate. This proves you patched the
   dependency's storage, not a lookalike.

Mapping slot derivations for the common ERC6909/1155-ish shapes:

```
nested  m[a][b]      = keccak(abi.encode(b, keccak(abi.encode(a, uint256(BASE)))))
triple  m[a][b][c]   = keccak(abi.encode(c, keccak(abi.encode(b, keccak(abi.encode(a, uint256(BASE)))))))
plain   m[x]         = keccak(abi.encode(x, uint256(BASE)))       # x packed to 32B
```
Note the **inner key is hashed first** in nested mappings — writing it the other way is the
single most common slot-derivation bug.

---

## 6c. Event decoding: `topic0` is not always `keccak(name(types))`

An event's `topic0` is the keccak of the signature **including parameter names? No — only
types.** But a *different contract/version* can emit an event with the same name and types
in a different order, holding a different `topic0`. In this session the Hub's `Transfer`
had `topic0 = 0x1b3d7edb…`, **not** `keccak("Transfer(address,address,address,uint256,uint256)")`.

Before decoding any event, do all three:

1. **Read `topic0` from a real log**, never compute it from the ABI and assume a match.
2. **Read one raw log in full** and count topics / data words, instead of trusting the ABI's
   `indexed` flags. This session's log had **4 topics + 64 bytes of data**, because the
   first param `caller` was *not* indexed (it sat in `data`), while `from/to/id` were. A
   decode that assumed "data[0:32]=id, data[32:64]=amount" produced **96/96 phantom
   mismatches** with absurd 1e48 values — a 100% "failure rate" is the tell that the decoder,
   not the contract, is broken.
3. **Sanity-check magnitudes.** If a replayed `mint` totals `1e48` for a token whose
   `totalSupply` is `1e9`, stop immediately — that is a parsing bug, not a finding.

**Rule of thumb: a metric that fails on ~100% of samples is an instrument bug. A metric that
fails on a small, explainable subset is a real finding.**

---

## 6d. Fetching logs when `eth_getLogs` misbehaves

Two independent failure modes showed up, and they need different fallbacks:

| Symptom | Likely cause | Fallback |
|---|---|---|
| `ERR Response size exceeds limit` / timeouts on wide ranges | range too big | shrink to 30–50 blocks per chunk, sleep between calls, or use `eth_getLogsWithCursor` |
| Returns `[]` for **every** range including `fromBlock: 0x0` on a chain that clearly has logs | method unsupported / silently no-op'd by that RPC | `eth_getBlockReceipts(blockNumber)` → filter `log.address` client-side |

Always **assert `log.address == target`** client-side: some RPCs ignore the `address` filter
and return the whole block's logs. A log count of 0 across a window where you *know* value
moved is a method bug, not chain state — cross-check with a single `eth_getBlockReceipts`
before concluding "no events exist".

Rate-limit hygiene for long replays: `HTTP 429` mid-scan means you have a **partial** dataset.
Never report totals from a run that ended in 429/timeout — persist each chunk's result to
disk as you go, and record the exact `[START, END]` range that completed.

---

## 7. Report-discipline checklist (run literally, in order)
1. [ ] Every probe re-run from a clean script with the shared `a()` / `w()` helpers
2. [ ] Calldata length asserted = `4 + 32*nargs`
3. [ ] **Every RPC response checked for `error` before reading `result`**; a "success" was
    never inferred from a missing exception
4. [ ] Known-positive control passes (function returns `true` where it must)
5. [ ] Negative control reverts (role-less caller rejected)
6. [ ] Effect proven (balance arithmetic bracketed), not just authorization returned
7. [ ] **Storage slots taken from `forge inspect storage-layout`** (or two-sided
    override-and-observe), not from a brief or a guess
8. [ ] **Event `topic0` read from a real log** and one raw log decoded by hand before any
    bulk replay; replayed magnitudes are physically plausible
9. [ ] Log-replay run completed a declared `[START, END]` range with no 429/timeout —
    otherwise totals are labelled partial
10. [ ] Live selectors reconciled against repo ABI **via verified explorer source first**;
    any "missing function" claim backed by two independent methods
11. [ ] Deployed vs compiled bytecode sizes stated
12. [ ] Any earlier claim this session refuted, corrected **in the same report**
13. [ ] Severity re-derived from the actual precondition (role required ⇒ not "no-keys")
14. [ ] Status is `PROVEN` only if every line above is green; else label
    `UNPROVEN-BLOCKED` / `INCONCLUSIVE` and say exactly which line failed

A chain that requires holding `OPERATOR_ROLE`, `ADMIN`, an oracle key, or an HSM is **not**
a stealth auth-spoof finding — say so plainly rather than dressing a privilege-escalation
bug as a Bitget-style backend compromise.
