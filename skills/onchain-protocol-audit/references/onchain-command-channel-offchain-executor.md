# On-Chain Command Channel → Off-Chain Executor (the "agent RCE" pattern)

Session detail from the pointgroup-labs hunt (2026-10-28): `svt-agent` (Rust) +
`sol-messenger` (Anchor program). Companion to
`references/offchain-supply-chain-rce-hunt.md` (supply chain) and
`references/rce-hunt-onchain-target.md` (RCE brief). This file owns a distinct
architecture: **the protocol's own off-chain agent takes its commands from an on-chain
program**, so the on-chain authorization model IS the off-chain RCE gate. When the brief
says "pre-auth RCE" against a validator/keeper fleet, this is the surface to check first.

---

## 1. Recognising the architecture

Signals that a target has this surface:

- A repo with `listener.rs` / `agent.rs` / `task_runner.rs` + `anchor-client` +
  `shiplift` (Docker control) + `chacha20poly1305` / `x25519_dalek` deps
- An `install.sh` that must run as root, pulls a container, and requires a `CID=`
  (channel id) argument — **the channel id is the command-bus address**
- `constants.rs` holding `MESSENGER_PROGRAM_ID` + `DEFAULT_CHANNEL_ID`
- A companion Anchor program repo with `instructions/post_message.rs` and a `state.rs`
  containing `Channel`, `ChannelMembership`, `ChannelDevice`, `CEKData`
- Operator-fleet vocabulary in repo descriptions: "validators upload their info",
  "validator manager", "monad node" — a uniform agent across many hosts

The data flow, end to end:

```
logsSubscribe(Mentions(channel_id))
  → NewMessageEvent (Program data: base64)
  → decrypt CEK (ECDH-ES + XChaCha20Poly1305)
  → Task { id, name, args, action }
  → ansible-playbook ./playbooks/{name}.yaml --extra-vars={json}
      inside a root container, network_mode: host, volumes_from(agent container)
```

## 2. The gate is on-chain — read it before theorizing

`post_message` handler (`sol-messenger/programs/messenger/src/instructions/post_message.rs`):

```rust
if !channel.is_public() {
    let membership = assert_valid_membership(
        &ctx.accounts.membership.to_account_info(),
        &channel.key(),
        authority_key,
    )?;
    if !membership.is_authorized() {
        return Err(MessengerError::Unauthorized.into());
    }
}
let message = channel.add_message(content, authority_key)?;
```

`is_public()` = `self.flags & ChannelFlags::IsPublic > 0` where `IsPublic = 0b001`
(`state.rs`). **A public channel accepts a message from any signer with no membership
whatsoever** — the membership/authorized branch is skipped entirely.

The agent side compounds it: `command_listener` in `agent.rs` dispatches every
`NewMessageEvent` on the channel to the processor with **no check on
`message.sender`**. There is no allowlist of permitted posters anywhere in the agent.

So the entry question is a single on-chain read: **fetch the channel account and inspect
the flags byte.** `svt-agent check-channel --channel <id>` does exactly this
(`Commands::CheckChannel` → `load_channel` → prints `OK`/`INVALID`). Run it from a clean
box with a throwaway keypair — read-only, no transaction, no cost, no rate-limit risk.

## 3. Why encryption is not a barrier to posting

`ChannelDevice { channel, authority, key: Pubkey, cek: CEKData }` stores the content
encryption key on-chain, wrapped to the device key. The agent's `load_cek` →
`decrypt_cek` unwraps it with the agent's own private key via ECDH-ES+XC20PKW
(`messenger/encryption.rs`).

To *post* a task, the attacker needs no secret at all:

1. Read the agent's device pubkey from the `ChannelDevice` PDA — public on-chain state.
2. Generate an ephemeral x25519 keypair; ECDH against the device pubkey; run the same
   Concat-KDF the agent runs (`concat_kdf`, SHA-256, `ECDH-ES+XC20PKW`, 256-bit).
3. Wrap a fresh CEK with XChaCha20Poly1305 under the derived KEK.
4. Encrypt `{"task":"<name>","args":"k=v","action":""}` under that CEK.
5. `post_message` with `content = flags_byte || base64(ciphertext)` (the first byte of
   `content` is the message flags field — `MessageFlags::IsEncrypted = 0b001`).

The agent decrypts with its private key and queues the task. **Public-key encryption to a
published key is not access control.** The only access control in the whole system is the
channel flag plus the membership check, and the flag is the entire game.

## 4. The sink: unsanitized task name → arbitrary playbook

`build_cmd` in `task_runner.rs`:

```rust
cmd.push(format!("./playbooks/{}.yaml", task.name));
```

`task.name` originates in `convert_message_to_task` (`utils/converter.rs`) as
`obj.get("task").as_str()` — **no validation, no allowlist, no path normalisation,
nothing between decrypt and exec**. A name of `../../../../tmp/evil` (or any traversal
reaching an attacker-writable path, or a name colliding with a real playbook while
`--extra-vars` carries hostile values) selects an arbitrary playbook.

`task.args` flows into `--extra-vars={json}` — JSON-serialised, so shell-safe, but fully
attacker-controlled Ansible variables (any `{{ }}`-reachable playbook variable is
reachable, including ones that reach `command`/`shell` modules inside the playbook).

Container options that raise the impact: `network_mode("host")`,
`volumes_from(vec![CONTAINER_NAME])` (inherits the agent's mounts, keypair volume
included), `env(["ANSIBLE_HOST_KEY_CHECKING=False"])`.

**Generic rule for this class:** in any "message → task → command" pipeline, grep the
sink for `format!` / f-string / sprintf interpolation of a field that arrived from the
decrypted payload, then check whether that field is validated against an allowlist
anywhere between decrypt and exec. Here it is not.

## 5. Hardcoded credentials in agent constants

`constants.rs` carried, verbatim, in a public repo:

```
NOTIFY_INFLUX_URL  = "http://influx.thevalidators.io:8086"
NOTIFY_INFLUX_USER = "v_user"
NOTIFY_INFLUX_PASS = "thepassword"
```

Plain **HTTP**, so the credential is exposed on the wire as well as in the repo. Sweep
Rust/Go/TS agent repos for credential-shaped assignments in `constants` / `config`
source files — the plaintext `.env` grep misses `const X: &str = "..."` completely.
Test liveness with ONE read-only GET (`/ping` or `/health` on the InfluxDB host) and
report 200-vs-401 honestly; mask the value in the report (prefix + `***MASKED***`).

Also audit test modules for **keypairs that are not test-only**.
`messenger/encryption.rs` tests embed a base58 secret key; if that key is used for any
real device or channel, message forgery follows. Verify by checking whether its pubkey
appears in any on-chain `ChannelDevice.key` before claiming impact.

## 6. Verdict discipline — conditional critical, stated as such

This pattern yields a *conditional* critical. Split the claim:

- **PROVEN** — unsanitised `task.name` → arbitrary playbook path; public-channel post
  requires no authorization (code evidence, file:line, both repos)
- **CONDITIONAL** — live RCE requires the deployed channel to have `IsPublic` set; one
  read-only `check-channel` call answers it
- **UNTESTED-with-reason** — whether the deployed program matches this source (no
  deploy records in scope); whether the fleet runs the vulnerable version

Never upgrade the conditional to PROVEN without the flags byte. One `getAccountInfo` on
the channel PDA is the entire difference between "architecture is broken" and "it is
broken in production".

## 7. Pitfalls

- **Do not assume the program is deployed from this repo.** Take the program id from
  `constants.rs` (`CgRaMXqqRHNT3Zo2uVZfX72TuxUgcLb8E3A8KrXnbXAC`) and verify the
  on-chain program's deployed source (explorer verified-build, or
  `solana program dump` + local rebuild) before claiming the audited code is the live
  code.
- **A funded keypair is not authorization.** The agent's keypair signs
  `join_channel` / `read_message`; posting needs only a fee-payer. Do not conflate
  "needs lamports for tx fees" with "needs credentials".
- **Check the sibling repos for the same agent.** Validator fleets install one agent
  image; `sv-manager` / `mv-manager` (Ansible) and the `ANSIBLE_IMAGE` constant
  (`ghcr.io/mfactory-lab/sv-manager`) point at the same operator stack — the playbook
  repo the container pulls is part of the trust graph.
- Related CI-shape discards for this org are in
  `offchain-supply-chain-rce-hunt.md` §2.3 — read it before writing up any workflow
  finding from the same target.
