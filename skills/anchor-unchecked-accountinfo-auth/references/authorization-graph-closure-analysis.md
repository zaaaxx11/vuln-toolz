# Authorization-Graph Closure Analysis — how to prove a chain is (un)reachable

Worked session: `pointgroup-labs/sol-messenger`, after the self-authorize chain was
disproven. This is the systematic method that replaced guesswork, plus the
architectural findings it surfaced.

---

## 1. Enumerate EVERY writer of the privilege field — not just the obvious one

The decisive move. Grep for all writes to the field that grants access:

```bash
grep -rn "status = \|status=" src/instructions/ | grep -v "^.*//"
```

Worked-case result — four writers of `membership.status`:

| Writer | Sets | First gate |
|---|---|---|
| `join_channel.rs:24` | `Pending` | **none** |
| `authorize_member.rs:44` | `Authorized` | `auth_membership.is_authorized() && can_authorize_member()` |
| `add_member.rs:49` | `Authorized` | `auth_membership.is_authorized() && can_add_member()` |
| `init_channel.rs:42` | `Authorized` | **none** — but only for a channel you create yourself |

**The closure test:** if every writer that grants `Authorized` requires an
already-Authorized caller, the authorization graph is **closed** and no escalation
exists. That is a *proof of absence*, which is a far stronger deliverable than "I
couldn't find it."

`init_channel` is the instructive near-miss: it grants `Authorized` + `Owner` with no
gate — but only inside a channel you just created, so it buys you nothing on a
victim's channel. **Always ask "does this writer operate on a channel I don't own?"**

---

## 2. Capability-flag amplification — a flag that is universally true is a design smell

```rust
pub fn can_authorize_member(&self, channel: &Channel) -> bool {
    channel.is_permissionless() || self.flags & ChannelMembershipAccess::AuthorizeMember > 0
}
```

`init_channel` unconditionally sets `Permissionless`:

```rust
channel.flags = 0;                              // reset, not |=
if data.permissionless { channel.flags |= ChannelFlags::Permissionless; }
```

Census result: **232 / 232 channels on mainnet had `flags = 0b00000010`** — i.e.
`is_permissionless()` was true everywhere and `is_public()` false everywhere.

**Consequence:** the per-member `AuthorizeMember` / `AddMember` / `DeleteMember`
capability bits are **dead code** — the channel-level flag short-circuits them for
every member. So the moment any single member is Authorized, that member can
authorize, add, and delete *anyone*. One compromised membership = full channel
takeover, with no privilege separation in between.

**Report this as blast-radius amplification**, not as a standalone vuln: it does not
create access, but it removes the speed bump between "one member compromised" and
"channel owned." Worth a Medium on its own because it defeats least-privilege design.

---

## 3. `#[account(zero)]` with no seeds — no canonical address

```rust
#[derive(Accounts)]
pub struct InitChannel<'info> {
    #[account(zero)]                              // <-- no seeds, no bump
    channel: Account<'info, Channel>,
    ...
}
```

The channel address is **entirely caller-chosen**. Not directly exploitable (`init`
requires an empty account, so an existing channel cannot be overwritten), but it means:

- No canonical/PDA address for a channel — nothing binds a channel to its name or creator.
- Any client that assumes "the channel for X lives at a derivable address" is wrong.
- Combined with a `close =` destruction primitive, address unpredictability complicates
  incident response and revocation.

**Audit question for every `#[account(zero)]` / `init` without `seeds`:** *is there any
downstream logic that assumes the address is canonical or derivable?* If yes, that
assumption is unverified and is your entry point.

---

## 4. Hardcoded admin key — verify liveness before dismissing it

```rust
pub const ADMIN_AUTHORITY: &[&str] = &["AuthxkATW25YDWX4kyDLh5qFMV1VhxKtRC9FBHh2JwZR"];
```

`channel.authorize()` treats this key as super-admin on **every** channel:

```rust
pub fn authorize(&self, key: &Pubkey) -> bool {
    self.creator == *key || ADMIN_AUTHORITY.contains(&key.to_string().as_str())
}
```

Verified live on mainnet: **the key exists, holds 8,475,708 lamports, and has recent
transactions** (newest at slot ~386.8M). It holds **zero** memberships — it never needs
any, because `authorize()` short-circuits before the membership check.

**Two findings here, and they are different:**

1. **Single point of total compromise.** One key controls all 232 channels. There is no
   rotation mechanism, no multisig, no timelock in the code. If it leaks, the entire
   fleet's command channel is owned. Report as High (key-management / architecture).
2. **It is a live, funded, active key** — so it is a real target, not a theoretical one.
   Do not dismiss hardcoded admin keys as "test leftovers" without checking
   `getAccountInfo` + `getSignaturesForAddress` first.

Note the asymmetry that makes this powerful: because `authorize()` bypasses the
membership path entirely, the admin key needs no membership, no device, and no CEK to
post to any channel. **A key that can act without holding any account state is the
highest-value target in the whole system.**

---

## 5. Method: prove absence, don't just fail to find

The sequence that closed this out:

1. **Grep every writer** of the privilege field (`status`, `flags`, `role`).
2. **For each writer, read the FIRST gate** top-to-bottom — not the most interesting one.
3. **Classify each writer:** does it operate on a channel/scope the attacker doesn't own?
   - `init_channel` → own channel only → useless for escalation.
   - `authorize_member` / `add_member` → requires already-Authorized → closed.
   - `join_channel` → no gate → real finding, but grants only `Pending`.
4. **Build the capability matrix by simulation** (free) to confirm the code reading.
5. **Conclude with the closure argument**, stated explicitly so a reviewer can check it.

The deliverable is then: *"the authorization graph is closed because every
Authorized-granting writer requires an already-Authorized caller, except
`init_channel` which only operates on caller-created channels"* — plus the two real
pre-auth findings and the amplification/architecture issues above.

That is a complete answer to "is there a chain?" even though the answer is no.

---

## 6. What this changes about reporting

When the chain is dead, the report is **not** empty. From this session the honest
finding list was:

| # | Finding | Severity | Proof |
|---|---|---|---|
| 1 | `join_channel` — no permission gate, stranger joins any of 232 production channels | Medium | mainnet, finalized tx |
| 2 | `add_device` — no status check, Pending member registers device key + CEK | Medium | simulated |
| 3 | `can_authorize_member` universally true — capability bits are dead code, one member = full channel | Medium | census + code |
| 4 | `init_channel` `#[account(zero)]` no seeds — no canonical channel address | Low | code |
| 5 | `ADMIN_AUTHORITY` single hardcoded key, live and funded, no rotation — total fleet compromise on leak | High | live chain |
| 6 | Jinja2 `lookup('pipe')` sink — PROVEN executing, but gated on membership | Critical-if-reached | executed locally |

Findings 1–2 are pre-auth and real. Finding 5 is arguably the most serious thing in the
whole engagement and was found *last*, by following the closure analysis to its
conclusion. **Do not stop looking when the chain dies — the closure argument usually
surfaces the architectural finding that matters more.**
