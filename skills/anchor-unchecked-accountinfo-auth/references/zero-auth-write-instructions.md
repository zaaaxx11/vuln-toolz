# Zero-Auth Write Instructions Found Late In The Sweep

These two were found **after** the main chain hunt was declared closed, by reading the
instructions nobody had opened. They are the reason a "closed" authorization graph is
only closed for the fields you swept.

## `add_meta` — no gate whatsoever

`sol-messenger/programs/messenger/src/instructions/add_meta.rs`:

```rust
pub fn handler(ctx: Context<AddMeta>, data: AddMetaData) -> Result<()> {
    let channel = &mut ctx.accounts.channel;
    if channel.to_account_info().data_is_empty() {
        return Err(MessengerError::InvalidChannel.into());
    }
    let authority = &ctx.accounts.authority;
    let meta = &mut ctx.accounts.meta;
    meta.channel  = channel.key();
    meta.authority = authority.key();
    meta.key      = data.key;
    meta.value    = data.value;      // <-- Vec<u8>, caller-controlled, unbounded
    meta.bump     = ctx.bumps.meta;
    Ok(())
}
```

**No membership lookup. No status check. No permission check. No `is_owner`.** The only
gate is `channel` must not be empty. Anyone can write an arbitrary-length `value` into a
`ChannelMeta` PDA on **any** channel — including all 232 production channels.

Accounts struct confirms it — `authority` is just a `Signer`, there is no membership
account in the context at all:

```rust
pub struct AddMeta<'info> {
    pub channel: Box<Account<'info, Channel>>,
    #[account(init, seeds = [ChannelMeta::SEED, channel.key().as_ref(),
                             authority.key().as_ref(), &data.key.to_le_bytes()], bump,
              payer = authority, space = ChannelMeta::space(data.value.len()))]
    pub meta: Box<Account<'info, ChannelMeta>>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

## `delete_meta` — rent redirect to the caller

`delete_meta.rs` pairs with it:

```rust
let is_super_admin = channel.authorize(authority.key);
if !is_super_admin && meta.authority.key() != meta_authority.key() {
    return Err(MessengerError::Unauthorized.into());
}
```

with

```rust
#[account(mut, has_one = channel, close = meta_authority)]
pub meta: Box<Account<'info, ChannelMeta>>,
/// CHECK:
#[account(mut)]
pub meta_authority: AccountInfo<'info>,
```

`meta_authority` is `/// CHECK:` with **no constraint**. Since `add_meta` sets
`meta.authority = authority.key()` (the caller), the caller can always satisfy
`meta.authority == meta_authority` and receive the rent refund. So the pair is a
**write-anything-then-reclaim-your-own-rent** loop.

## Impact (honest)

- **Storage spam / rent griefing** across the whole fleet — 232 channels, unbounded
  `value` length, caller pays rent so it costs them, but it bloats every channel's meta
  set and pollutes any indexer that enumerates `ChannelMeta`.
- **NOT RCE.** Verified: `grep -rn "ChannelMeta\|meta" svt-agent/src/` returns nothing
  that reads it. The daemon never consumes these accounts, so there is no sink.

## Why this class gets missed

The hunt had already enumerated the 16 instructions that touch `ChannelMembership` and
declared the graph closed. `add_meta`/`delete_meta` operate on a **different state
struct** (`ChannelMeta`, not `ChannelMembership`) and were never in the privilege-field
sweep. **A closure argument over one state type says nothing about the others.**

## The rule this establishes

> When you conclude "the authorization graph is closed," state the scope of that claim
> explicitly: *closed for writers of `membership.status` and `membership.flags`.* Then
> enumerate **every state struct in `state.rs`** and ask, for each one, whether any
> instruction writes it without a gate. The grep that finds this class is not
> `grep -rn "status"` — it is `grep -rn "pub struct" state.rs` followed by a per-struct
> handler sweep.

A second grep that catches it cheaply: list every handler and check which ones have **no
membership/role account in their `#[derive(Accounts)]` context at all**. In this program
that was `add_meta` and `init_channel` — and `init_channel` is safe only because it
operates on a scope the caller creates themselves.
