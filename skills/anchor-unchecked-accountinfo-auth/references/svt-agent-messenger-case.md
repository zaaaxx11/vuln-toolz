# Case Study — svt-agent × sol-messenger (pointgroup-labs), mainnet-beta

> ## ⛔ RETRACTION — the exploit chain below is DISPROVEN
>
> The "forged membership → post to private channel → RCE" chain in this file was
> reported as PROVEN from source reading. **Live `simulateTransaction` disproved it.**
>
> **Final verdict (supersedes an intermediate wrong theory):**
> `assert_valid_membership` works **correctly**. It validates `channel` AND `authority`
> against the real account, and the deserializer handles the discriminator properly.
> 15 successful `PostMessage` transactions exist on-chain (all by the channel creator
> using its own membership), and simulating the genuine account with a mismatched
> `authority` returns `"Error: Invalid membership authority"`.
>
> **Why the forge fails:** the account must be **owned by the messenger program** for
> the deserialize + field comparison to succeed, and only the program can write such an
> account. An attacker-created system-owned account with hand-written bytes cannot pass.
> Account ownership is the security boundary that makes field-equality checks sound here.
>
> **Consequence:** the chain below is unreachable. The real finding is a **hardening /
> defense-in-depth** gap (missing PDA constraint), NOT an auth bypass and NOT RCE.
>
> **Still valid in this file:** the fleet census, the verified account layout, the crypto
> verification recipe, the systemic spread sweep, and the bonus credential finding.
> **Invalid:** Bug A's "fully forgeable" claim, the chain diagram, and any "dead
> instruction" framing — the instruction works fine for legitimate members.
>
> Full analysis: `references/anchor-deserializer-offset-trap.md`

Program `CgRaMXqqRHNT3Zo2uVZfX72TuxUgcLb8E3A8KrXnbXAC`, live on mainnet-beta.
Repos: `pointgroup-labs/sol-messenger` (Anchor program), `pointgroup-labs/svt-agent`
(Rust daemon, runs as root on validator hosts, controls Docker + Ansible).

## Fleet census (executed 2026-10-28)

| Metric | Value |
|---|---|
| Program accounts | 1,876 |
| Channels | 232 — all `workspace='svt'`, named `svt_<validator-identity>` |
| Memberships | 702 |
| Devices | 711 |
| Channel flags | all 232 = `0b00000010` (Permissionless, NOT public) |
| Channel rent | 49,193,280 lamports each → ~11.4 SOL total stealable via `delete_channel` |

Census recipe: `getProgramAccounts` with `encoding:"base64"` (no filters) then bucket by
`len(decoded)` — 160 = ChannelMembership, 285 = ChannelDevice, channels identified by
attempting a `workspace`/`name` String parse and sanity-checking `created_at` range and
`nmsg <= max_messages`. Use `dataSlice` first if the payload is huge.

## Verified ChannelMembership layout (decoded from a real mainnet account)

```
[0..8)    anchor discriminator
[8..40)   channel    Pubkey
[40..72)  authority  Pubkey
[72]      status     enum        0 = Authorized, 1 = Pending
[73]      status_target Option tag  0 = None (NO pubkey follows), 1 = Some
[74..106) status_target Pubkey    (present only when tag == 1)
[106..)   String name (u32 len + utf8)
          u64  last_read_message_id
          i64  created_at
          u8   flags
          u8   bump
[..160)   trailing zero padding (MAX_MEMBER_NAME_LENGTH allocation)
```
Real account observed: `name_len=5 name=b'agent'`, consumed 133 of 160, pad = 27 zero bytes.
A `name_len=0` account consumes 128 of 160.

## The three bugs

**A — `post_message.rs`**: `membership` is `/// CHECK: AccountInfo`, no seeds/bump/has_one.
`assert_valid_membership()` (utils.rs) compares only `channel` + `authority` fields, then
`is_authorized()` reads `status`. `authorize_member.rs` gets it right with
`#[account(mut, has_one = channel)]` — the inconsistency is the evidence.

**~~Fully forgeable~~ — DISPROVEN.** The check validates `channel` and `authority`
correctly against real accounts, and the account must be **program-owned** for the
deserialize to succeed — which an attacker cannot forge. This is a hardening gap
(missing PDA constraint), not an auth bypass. See the retraction above.

**B — `svt-agent/src/utils/converter.rs`**: `task.name` taken from decrypted JSON with zero
validation.

**C — `svt-agent/src/task_runner.rs`**: `format!("./playbooks/{}.yaml", task.name)` plus
`network_mode("host")`, `volumes_from(CONTAINER_NAME)`, running as root.

## Chain — ⛔ DISPROVEN, DO NOT REUSE

```
forged membership (authority=attacker signer, status=Authorized)
 -> post_message on a PRIVATE channel        (no real membership)     <-- FAILS: InvalidMembership
 -> NewMessageEvent
 -> agent logsSubscribe(Mentions(channel))   (no sender check)
 -> ECDH-ES decrypt                          (device pubkey is PUBLIC on-chain)
 -> Task{name: "../../../../tmp/pwn"}
 -> ansible-playbook ./playbooks/../../../../tmp/pwn.yaml   as ROOT
```

Step 2 never succeeds. B and C are real weaknesses but **unreachable** through this path.
The correct deliverable is the dead-path defect, not an RCE chain.

## Crypto verification (do this before claiming a decrypt path)

1. Pull the repo's own unit-test vector from `encryption.rs` (`test_decrypt_message`) and
   decrypt it with your implementation. Format match = necessary precondition.
2. Prove ECDH-ES symmetry with a simulated pair:
   - agent x25519 secret = `clamp(sha512(ed25519_secret))[:32]`
   - agent x25519 public = `crypto_sign_ed25519_pk_to_curve25519(ed_pub)`
   - assert `scalarmult(eph_priv, agent_x_pub) == scalarmult(agent_x_secret, eph_pub)`
   - **Trap:** deriving the simulated public via `scalarmult_base(x_secret)` does NOT equal
     the montgomery conversion in general — convert through the ed25519 public key.
3. Concat KDF (SHA-256, 1 round, 256-bit): `counter(4BE) || Z || algid_len(4BE) || alg ||
   apu_len(4BE) || apu || apv_len(4BE) || apv || keylen(4BE)`, alg = `ECDH-ES+XC20PKW`.
4. Message blob = `nonce(24) || ciphertext || tag(16)`, base64-encoded. Agent splits as
   `nonce = b[0..24]`, `tag = b[-16:]`, `ct = b[24..-16]`.

## Systemic spread (same flaw, 5 instructions)

| Instruction | Unconstrained account | Check that *would* be bypassed if the account were attacker-writable | Actual status |
|---|---|---|---|
| `post_message` | `membership` | `is_authorized()` | **not exploitable** — program-owned requirement blocks the forge |
| `update_message` | `membership` | `is_authorized()` | **not exploitable** — same helper |
| `delete_message` | `membership` | `is_authorized()` | **not exploitable** — same helper |
| `delete_channel` | `authority_membership` | `is_owner()` | **not exploitable** — same helper |
| `add_member` | `authority_membership` | `is_authorized() && can_add_member()` | **not exploitable** — same helper |

Always run this sweep — one instance looks like a typo, five looks like a pattern and
materially raises severity. But **verify one instance end-to-end before extrapolating the
impact column across the table.** Here the sweep found a shared *pattern* (missing PDA
constraints) that is a legitimate hardening finding across all five, not five
exploitable instructions. Report it as defense-in-depth with the ownership argument
stated explicitly.

## Bonus finding pattern

`svt-agent/src/constants.rs` hardcoded InfluxDB credentials (`v_user` / `thepassword`)
sent over **plain HTTP** to `influx.thevalidators.io:8086`. Grep daemon repos for
credential-shaped constants and check the transport scheme, not just the presence of a
secret.
