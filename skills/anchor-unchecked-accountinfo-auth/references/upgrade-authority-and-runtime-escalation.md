# Runtime-Level Escalation: Upgrade Authority + ProgramData Recon

Session detail for the `sol-messenger` + `svt-agent` engagement (mainnet-beta).
Companion to `authorization-graph-closure-analysis.md` — that file closes the
*in-program* privilege graph; this one covers the layer **above** the program.

---

## 1. There are TWO privileged keys, and they are not the same key

The single most important structural fact from this session. A Solana program's
authorization surface has two independent tiers:

| Tier | Key | What it controls | How to read it |
|---|---|---|---|
| **In-program** | `ADMIN_AUTHORITY` in `constants.rs`, compared by `Channel::authorize()` | `add_member` / `authorize_member` / `delete_member` / `delete_channel` / `delete_meta` as "super admin" | source read |
| **Runtime** | ProgramData `upgrade authority` | **replacing the entire program binary** | decode ProgramData account (§3) |

In the worked case these were **different keys**:

```
in-code  ADMIN_AUTHORITY = AuthxkATW25YDWX4kyDLh5qFMV1VhxKtRC9FBHh2JwZR
on-chain upgrade auth    = HUsJRv7yzLECt4mTR3NY5u9TX2ZJc5E89xHW9uWr2Dr7
```

**Why the runtime tier subsumes the in-program tier.** Anyone holding the upgrade
authority can deploy a program whose `authorize()` returns `true` unconditionally,
or whose `post_message` skips the membership check entirely. Every in-program gate
becomes decorative. So when both exist, **the upgrade authority is the higher-severity
finding** even though it is the less "interesting" bug — it is a centralization /
key-management finding, not a logic flaw, and it should be reported as such with the
key named.

**Do not assume the in-code admin key is the upgrade authority.** Verify separately.
Also verify the in-code key is *live* before dismissing it (see
`authorization-graph-closure-analysis.md` — a funded, unrotatable hardcoded admin key
was the most serious finding of that engagement and was found last).

**Also check: is the program still upgradeable at all?** `getAccountInfo(program_id)`
→ `owner == BPFLoaderUpgradeab1e...` and `executable == true` means yes. If the
ProgramData has `authority option == 0`, the program is immutable and this whole tier
collapses to a non-finding. Check that first; it is one RPC call.

---

## 2. Read the ProgramData address out of the Program account — do NOT derive it

`find_program_address` with the `b"upgradeable"` seed is easy to get wrong (seed
order, whether the program id is included). In this session the derivation returned
`3v8VN7ZZiPGCfJAAPqi3Zu6s3kBD6dSTrm7g167yu8wm` while the real address was
`H891uXm2StaYWq8jrYM3XGA1R4qqSj9JHxSgeQDevmwB` — a silent wrong answer, not an error.

**The reliable path:** the *Program* account carries the ProgramData address in its
own data. Layout is 36 bytes:

```
[0..4]   u32 LE  = 2        (ProgramAccount discriminant)
[4..36]  32 bytes = ProgramData address
```

```python
acc = get_account(PROGRAM_ID)                       # 36 bytes, executable, owner = BPFLoader
raw = base64.b64decode(acc["data"][0])
assert struct.unpack("<I", raw[:4])[0] == 2
progdata = b58encode(raw[4:36])                     # <- authoritative
```

Then decode ProgramData (see §3) and cross-check that the derived address is *not*
needed.

---

## 3. Decoding ProgramData for the upgrade authority

```python
pd  = get_account(progdata)
raw = base64.b64decode(pd["data"][0])

disc      = struct.unpack("<I", raw[:4])[0]   # 3 = ProgramData
slot      = struct.unpack("<Q", raw[4:12])[0] # last deploy slot
has_auth  = raw[12]                            # 0 = immutable, 1 = has authority
auth      = raw[13:45]                         # 32 bytes, only meaningful if has_auth == 1
```

Worked values (mainnet): `disc=3`, `slot=190751384`, `has_auth=1`,
`auth=HUsJRv7yzLECt4mTR3NY5u9TX2ZJc5E89xHW9uWr2Dr7`, datalen 867,821,
lamports 6,040,925,040 (≈6.04 SOL held by the ProgramData account).

**Sanity checks that catch a mis-decode:**
- `disc` must be 3. Anything else means you decoded the *Program* account (disc 2).
- `len(raw)` should be large (hundreds of KB) for a real deployed program.
- If `has_auth == 0`, stop — immutable, no finding here.

**Confirm the authority actually signed a deploy** (proves it is live, not a stale
field): `getSignaturesForAddress(progdata, {limit: 5})` → `getTransaction` each →
look for a `BPFLoaderUpgradeab1e...` instruction whose first account is the authority.
In this session the deploy at slot 190751384 had the authority as account[0] and
account[0] of the final (spill) slot, and the log line `Deployed program <id>`.

---

## 4. Do not decode BPFLoader instruction data — read the log line

I burned ~10 tool calls trying to borsh-decode the loader instruction's 4-byte enum
discriminant to distinguish `Upgrade` from `DeployWithMaxDataLen`. The decoded bytes
did not match any enum index and I started theorising about double-base64 and
URL-safe alphabets.

**The log line answers it unambiguously and for free:**

```
Program log: ... "Deployed program CgRaMXqqRHNT3Zo2uVZfX72TuxUgcLb8E3A8KrXnbXAC"
```

`Deployed program <id>` ⇒ `DeployWithMaxDataLen`. An in-place upgrade logs
`Program <id>> upgraded` / no such line. Read `meta.logMessages`; never decode
loader ix data to answer a semantic question the logs already answer.

---

## 5. ⚠️ PITFALL — Solana RPC base64 is UNPADDED, and a wrong-length decode is the tell

`getTransaction` / `getAccountInfo` return base64 **with `=` padding stripped**.
Python's `base64.b64decode` raises `Incorrect padding`, and the naive fix
(`s += '=' * (-len(s) % 4)`) silently produces garbage if you are looking at the
wrong field.

**Always sanity-check the decoded length against the expected instruction size:**

| Instruction | Expected decoded length |
|---|---|
| `SystemInstruction::Transfer` | 12 (4 enum + 8 lamports) |
| `DeployWithMaxDataLen` | 12 (4 enum + 8 max_len) |
| Anchor ix with one `String` arg | 8 disc + 4 len + N |

If the length does not match, **you have the wrong field or the wrong encoding —
stop and re-extract.** Do not start theorising about alphabets or double-encoding.
In this session a 12-byte system transfer decoded to 52 bytes, which was the signal
that I was mis-reading the instruction, and I burned ten rounds ignoring it.

Correct decode helper:

```python
def b64d(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))
```

---

## 6. Rank forges by PAYOFF, not by discovery order

When several instructions share the same unchecked-`AccountInfo` +
`assert_valid_membership` helper, they are **not** equally valuable. In the worked
program:

| Instruction | What a successful forge of `authority_membership` buys |
|---|---|
| `post_message` | post one message into the channel |
| `update_message` / `delete_message` | edit/remove an existing message |
| `authorize_member` | flip a *Pending* membership to Authorized |
| **`add_member`** | **`init` a brand-new membership with `status = Authorized` for an arbitrary `invitee`, plus a device** |

`add_member` is the highest-payoff target because it mints a *fresh, program-owned,
Authorized* membership — it does not depend on any pre-existing victim state, and the
resulting account passes every ownership check that killed the hand-forged account.
`post_message` only reuses an existing membership.

**Heuristic:** when you find the unchecked-account pattern, grep for every caller of
the shared helper and rank by *what the successful call constructs*, preferring
instructions that `init` new state over ones that mutate existing state. Test the
highest-payoff one first — a single `simulateTransaction` settles it.

Note the same ownership caveat still applies: `add_member`'s `authority_membership`
is a bare `AccountInfo`, so a system-owned forge may still die at deserialize. But
`invitee_membership` is `init`-ed by the *program*, so the thing you end up holding
is genuine. Run the error-code pairing test from
`exploitability-proof-method.md` §6 before claiming anything.

---

## 7. `#[account(zero)]` without seeds — the collision needs a second instruction

`init_channel` declares `channel: #[account(zero)]` with **no seeds**, so the caller
chooses the channel address. The membership PDA is `[channel, authority]` and the
device PDA is `[membership, key]`.

A naive PDA-collision theory ("grind a channel address whose membership PDA equals a
victim address") does not work directly, because `init_channel`'s membership is
`init`-constrained: if anything already exists at that address, `init` fails and the
whole transaction aborts.

**The collision only pays off through a *different* instruction that writes to an
already-existing membership** — i.e. it reduces to the unchecked-`AccountInfo`
question in §6, not to a seed-grinding exercise. Do not spend budget grinding seeds
before checking whether the write path is even reachable. (See
`authorization-graph-closure-analysis.md` for the `#[account(zero)]` smell in general.)

---

## 8. Closed-account reuse is not an escalation

`leave_channel` / `delete_member` / `delete_channel` use `close = authority`, which
routes through `utils::close()`: zero lamports → `assign(system_program)` → `realloc(0)`.
The freed address is then reusable by anyone via `join_channel`'s `init`.

But the replacement membership is created with `status = Pending`, so address reuse
buys nothing. Report the close primitive as an availability / rent-recovery note
(multiplied by fleet size), not as an escalation path.
