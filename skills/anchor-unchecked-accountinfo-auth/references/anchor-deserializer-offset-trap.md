# The Anchor Unchecked-Account Trap — worked FALSE POSITIVE (final verdict)

**Engagement:** pointgroup-labs `sol-messenger` + `svt-agent`, mainnet-beta.
**Outcome:** theorised "pre-auth RCE via forged membership" was **WRONG**. No auth bypass,
no RCE. The finding was retracted after live simulation.

This file exists because the wrong conclusion was reported with high confidence from
code reading alone, and only execution exposed it — **twice**. The first correction
(deserializer offset mismatch) was itself wrong; the second correction is final.

---

## Timeline of the error (read this as a cautionary sequence)

### Stage 1 — Source read → confident "PROVEN RCE"
`post_message` takes `membership` as a bare `/// CHECK: AccountInfo` with no
seeds/bump/has_one, and `assert_valid_membership` compares only *fields*. Sibling
`authorize_member.rs` correctly used `has_one = channel`, which looked like proof of an
oversight. Reported as: forge membership → post to private channel → daemon RCE.

### Stage 2 — Live simulation killed it
`simulateTransaction` on the forged account returned `InvalidMembership` (6002).
Six runs isolating one variable each:

| # | Account contents | Result |
|---|---|---|
| 1 | forged, authority=burner, signed | `InvalidMembership` (6002) |
| 2 | **exact clone of the real account, zero edits** | `AccountNotSigner` (3010) — **passed the membership check** |
| 3 | clone, only `authority`→burner | `InvalidMembership` (6002) |
| 4 | clone, authority+status+flags patched | `InvalidMembership` (6002) |
| 5 | no-disc layout, `[0:32]`=channel, `[32:64]`=authority | `AccountNotSigner` (3010) — **passed** |
| 6 | no-disc layout + authority=burner, signed | `InvalidMembership` (6002) |

Run #2 was the tell: an **unedited real account** passes the membership check, so the
check itself is not the weakness.

### Stage 3 — WRONG root cause (do not repeat this)
A local `cargo test` probe was written that built accounts **in memory** and compared
`m.channel == channel`. It printed:

```
A disc+fields (REAL anchor layout):  channel_ok=false  authority_ok=false
B fields@0:                         channel_ok=true   authority_ok=true
```

This was read as "the deserializer doesn't skip the discriminator, so the check is dead
for everyone." **That conclusion was false** — the probe was tautological. It fed the
deserializer bytes *it had constructed*, so "passes" only meant "the bytes I chose happen
to match the values I chose." It proved nothing about the deployed program.

### Stage 4 — Final verdict (correct)
Two live checks settled it:

**(a) On-chain census.** 39 transactions touching the channel, decoded via
`getTransaction` + `logMessages`:
```
PostMessage 15 · ReadMessage 14 · UpdateMessage 4 · AuthorizeMember 2
JoinChannel 2 · DeleteMember 1 · InitChannel 1 · AddMeta 1
```
15 successful `PostMessage` — the instruction demonstrably **works**. All were sent by
the channel creator using **its own** membership
(`eeTRvPYcvCc8D9aR2nNWSSYXQT77Ld36mQ1BsgCkrKa`), with `authority == signer == creator`.

**(b) Direct simulation with the real membership.** Pointing `post_message` at the genuine
account `eeTRvPYc…` but with `authority = burner`:
```
Program log: Error: Invalid membership authority
AnchorError occurred. Error Code: InvalidMembership. Error Number: 6002
```
`channel` matched; `authority` did not. The check validates **both** fields correctly
against real accounts. **There is no offset bug. The deserializer is fine.**

## Corrected finding

- **Real bug:** `membership` is an unconstrained `AccountInfo` — a **hardening /
  defense-in-depth** finding (missing PDA constraint). NOT an exploitable auth bypass.
- **Why not exploitable:** the account must be **owned by the messenger program** for
  the deserialize + field comparison to succeed, and only the program can write such an
  account. An attacker creating a system-owned account with hand-written bytes cannot
  satisfy the check. Field equality here *is* backed by account ownership.
- **The downstream RCE was never reached.** `svt-agent` does contain genuine weaknesses
  (unvalidated `task.name` into `format!("./playbooks/{}.yaml", task.name)`,
  `network_mode("host")`, `volumes_from` the keypair container, root, hardcoded
  InfluxDB creds `v_user`/`thepassword` in `constants.rs`) — but with no way to post a
  message, they are unreachable through this path.
- **Fix (still worth doing):** replace the `AccountInfo` + manual deserialize with
  `#[account(mut, seeds = [channel.key().as_ref(), authority.key().as_ref()], bump,
  seeds::program = crate::ID)]` on all five affected instructions.

## Lessons encoded in the parent SKILL.md

1. **Never claim PROVEN from source reading.** Local probe + `simulateTransaction` +
   on-chain census, all three, before the word "PROVEN" appears.
2. **An unedited real account passing validation means your *forge* is wrong, not that
   the check is weak.** Invert your hypothesis when you see this.
3. **A self-built test fixture is tautological.** Constructing the account bytes yourself
   and then "verifying" your own deserializer reads them back proves nothing about the
   deployed binary. Only live-chain accounts and live simulation are evidence.
4. **Census the population before theorising.** "15 PostMessage succeeded" / "0 of 46
   messages from non-creators" is decisive data. Dead code paths and unexploited ones
   look identical in source.
5. **Account ownership is a real security boundary.** "Caller supplies the account" is
   not automatically exploitable — ask *who can write that account* before concluding.
6. Retract loudly and early. The cost of a wrong "PROVEN" is the user's trust and a
   wasted funded wallet.
