# Solana On-Chain Recon — Anchor Program Account Enumeration

Working recipe from the pointgroup-labs svt-agent engagement (mainnet-beta, 2026-10-28).
Program `CgRaMXqqRHNT3Zo2uVZfX72TuxUgcLb8E3A8KrXnbXAC` → 1,876 accounts, 232 channels,
702 memberships, 711 devices, all `workspace='svt'`.

## 1. Confirm deployment + scale
```python
rpc("getAccountInfo", [PROGRAM_ID, {"encoding":"base64"}])              # executable? owner=BPFLoaderUpgradeable
rpc("getProgramAccounts", [PROGRAM_ID,
    {"encoding":"base64","dataSlice":{"offset":0,"length":0}}])        # total count
```

## 2. Enumerate by account type
`Account::space()` from the source is the only reliable `dataSize` filter
(`Channel::space(max_messages)`, `ChannelMembership::space()`, `ChannelDevice::space()`).
If unsure, fetch ALL accounts and classify by length + structural parse — a wrong
`dataSize` silently returns 0 accounts, which reads as "not found" rather than "bad filter".

## 3. Decode an Anchor account
Layout = 8-byte discriminator, then fields in declaration order:
- `Pubkey` = 32 raw bytes
- `String` = u32 len + utf8
- `Option<Pubkey>` = 1-byte tag (0 = None, **no bytes follow**; 1 = Some + 32 bytes)
- `enum` = 1-byte variant index
- `Vec<T>` = u32 len + elements

```python
def rd_str(d, o):
    n = struct.unpack_from("<I", d, o)[0]; o += 4
    return d[o:o+n].decode("utf-8","replace"), o+n
```

## 4. Field-offset memcmp filters
`{"memcmp": {"offset": N, "bytes": "<b58 pubkey>"}}` — offset counts from the START of
account data, so the first struct field sits at offset **8** (after the discriminator).

## 5. Find the live agent (the RCE target)
Join memberships → channels → devices:
- membership `name == 'agent'` → that authority is the daemon
- `last_read_message_id == channel.message_count` → agent is caught up = LIVE and polling
- the device account leaks the agent's PUBLIC device key → sufficient for ECDH-ES encryption,
  no secret required

Operator/creator memberships are NOT execution paths — do not target them for RCE.

## 6. Abandoned-authority scan
`getMultipleAccounts` in chunks of 100 over unique membership authorities; zero-balance
= key lost. Useful as an availability finding (channel owner can no longer sign, rotate,
or delete). Does NOT yield task execution.

## 7. Base58 gotcha
Solana keypair files are **64 bytes** (secret ‖ pubkey). `int.to_bytes(32)` raises
OverflowError — use `to_bytes(64)` and split at 32. Verify with
`nacl.signing.SigningKey(seed).verify_key`.

## 8. Cost model before broadcasting
- `getRecentPrioritizationFees` → current market (often 0 off-peak)
- `getMinimumBalanceForRentExemption[space]` → refundable deposit
- CU estimate: create_account ~3k, `Box<Account<Channel>>` deserialize ~30k,
  sig verify ~1.5k, tx overhead ~5k
- Real burn = base fee (5,000 lamports/sig) + priority; rent is reclaimed by closing
  the forged account afterwards

## 9. Channel flags decode
```python
IS_PUBLIC       = 0b001   # no membership required to post
PERMISSIONLESS  = 0b010   # skip permission checks on member ops
```
All-private fleets still fall to the unchecked-membership forge.
