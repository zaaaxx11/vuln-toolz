# Off-Chain Execution Surface & Supply-Chain RCE Hunt

Companion to the on-chain half. Use when the brief says *"hunt LITERAL RCE via the off-chain
execution surface and supply chain"* — i.e. find a path from attacker-controlled input
(on-chain state, npm package, CI config, public repo, subdomain) to **code execution on
protocol infrastructure**. Budget ~15 min. No brute force, no destructive actions, every claim
needs real evidence.

The honest verdict is usually **"no literal RCE"** — and that is a complete deliverable when
the refutations are documented. Rank what you did find and label the residual.

---

## 1. The five surfaces, in yield order

| Surface | What you are looking for | Cost |
|---|---|---|
| **CI config** | PR-triggered install without lockfile guard → runner RCE | 2 curls + grep |
| **npm / dependency** | unpublished-scope dependency confusion; install hooks | 1 curl + grep |
| **Public repos** | leaked secrets, wiped history, `.env`/`.npmrc`, `git log -S` | clone + grep |
| **Public repos** | **obfuscated** credentials — Caesar/base64/`charCodeAt` decoders in tracked source (§3.1) | clone + grep |
| **Live subdomains** | unauth debug endpoints, framework fingerprint, input sinks | paced probes |
| **Production bundle** | shell-out primitives, internal hosts, SDK consumption | 1 download + grep |

Do them in that order. CI config is the highest-yield-per-minute and the one people skip.
The two **Public repos** rows are one surface with two greps — run both, because the
plaintext sweep alone misses obfuscated credentials (§3.1).

---

## 2. CI supply chain — the asymmetry proof

The finding is almost never "CI runs code". It is **"CI runs attacker-influenced code without
the guard the team already wrote elsewhere"**.

```bash
# 1. enumerate workflows and their triggers
find <repo> -path "*/.github/workflows/*" -type f

# 2. for each: trigger, install command, guard, permissions
grep -n "on:\|pnpm install\|npm ci\|frozen\|permissions\|pull_request_target" <workflow>

# 3. the guard, when it exists, looks like this (DefiLlama-Adapters/test.yml):
if [[ $FILES_MODIFIED == *"package.json"* || $FILES_MODIFIED == *"package-lock.json"* \
   || $FILES_MODIFIED == *"pnpm-lock.yaml"* || $FILES_MODIFIED == *"pnpm-workspace.yaml"* ]]; then
  echo "------ ERROR ------ > Please revert changes to package.json / ..." > output.txt
  exit 1
fi
```

**Checklist per workflow:**
- `on: [pull_request]` (or `pull_request_target` — worse, runs with secrets + write token)
- bare `pnpm install` / `npm install` → **resolves** whatever the PR's lockfile says
- `--frozen-lockfile` / `npm ci` absent → lockfile drift is resolved, not rejected
- no `permissions:` block → default `GITHUB_TOKEN` (contents: write on the repo)
- third-party actions pinned by mutable tag (`ncipollo/release-action@v1`) instead of SHA
- release job publishes an artifact (`artifacts: cli/dimensionModules.json`,
  `allowUpdates: true`) → **downstream artifact-poisoning path**

### 2.3 Three injection shapes, and the two that are NOT findings

Pointgroup-labs run (2026-10-28), 22 repos, 55 workflows. Three candidates surfaced from
the `github.event.*` grep; **two died on adversarial validation** and the third was
upstream-inherited (§2.1). Record the discards — they are what stops the next session
re-reporting them.

**(a) Env-var indirection — SAFE, do not report.** The common shape:

```yaml
env:
  TITLE: ${{ github.event.pull_request.title }}
jobs:
  check:
    steps:
      - run: |
          if [[ "$TITLE" =~ ^(feat|fix|chore|build|ci|docs|style|refactor|perf|test)(\([-a-zA-Z0-9,]+\\))?\\!?\\: ]]; then
              echo pass
          else
              exit 1
          fi
```

The untrusted value lands in an `env:` var and the script expands `"$TITLE"`. Shell
variable expansion inside double quotes cannot break out — no injection. Seen in
`alula/conventional-commits.yml` and `alula-liquidator/conventional-commits.yml`, both
with `permissions: {}` and a regex-only body. **Report only when the template expression
is interpolated directly into the `run:` script text**
(`run: echo ${{ github.event.issue.title }}`), not when it passes through `env:`.

**(b) Dead refs on the wrong trigger — NOT exploitable as written.**
`fogo-locker/generate-idl.yml` checks out
`ref: ${{ github.event.pull_request.head.ref }}` +
`repository: ${{ github.event.pull_request.head.repo.full_name }}` — textbook
untrusted-PR-checkout with `contents: write` — but the workflow's only triggers are
`push: branches: [main]` and `workflow_dispatch`. On those events
`github.event.pull_request` is **null**, so both refs resolve empty and the step checks
out the default branch of the base repo. **Always read the `on:` block before scoring a
checkout ref.** A dangerous ref on a trigger that never populates it is dead code, not a
finding.

**(c) Step-output injection — the one real shape.** `on: pull_request` plus
`${{ steps.<id>.outputs.<name> }}` interpolated into a `run:` block
(`DefiLlama-Adapters/test.yml`:
`MODIFIED=${{ steps.file_changes.outputs.files_modified }}`). The output derives from
the PR's changed **file names**, which the attacker controls by committing a file whose
name carries shell metacharacters. This is the only one of the three worth writing up —
and per §2.1 it is upstream-inherited, so the severity is the fork's blast radius, not a
novel team regression.

**Triage command that found all three:**

```bash
for f in $(find . -path "*/.github/workflows/*" \( -name "*.yml" -o -name "*.yaml" \) | grep -v "/.git/"); do
  grep -qE 'github\.event\.(issue|pull_request|comment|review|discussion|head_commit|commits)' "$f" \
    && { echo "!!! $f"; grep -nE 'github\.event\.' "$f" | head -10; }
done
```

Then, per hit, answer in order: (1) does the trigger ever populate that event context?
(2) does the value pass through `env:` (safe) or land in script text (live)? (3) is the
workflow a fork of a public repo, and what did the fork change (§2.1)?

**The asymmetry IS the evidence — but only after you verify WHO wrote the guard.** Same org,
same fork lineage, one repo hardened and the sibling not. Always diff the sibling repo's
workflows before writing it up. **But resolve the fork's real parent from the API first** and
diff against *that*, not against the repo you assume is upstream — see §2.1.

**Blast-radius honesty.** A fork of a third-party repo (e.g. DefiLlama adapters) is an
org-owned asset, not core protocol infra. Compromise yields the fork's `GITHUB_TOKEN`, the
published release asset, and CI minutes — **not** deploy keys, the hot wallet, or the
oracle/keeper hosts unless you found those in a repo. Say so explicitly; check
`pulls?state=all` for whether the repo has ever received a PR (0 PRs → low real-world
exploitability, severity drops).

### 2.1 Resolve the fork's parent from the API BEFORE diffing — and read the diff's direction

The most expensive mistake in this class. A prior session on this target diffed
`current-finance/DefiLlama-Adapters` against `DefiLlama/adapters` — the wrong repo. The real
parent is `DefiLlama/DefiLlama-Adapters`. The wrong diff produced a plausible but false
"the team deleted the guard" narrative.

```bash
curl -s -H "User-Agent: <browser UA>" https://api.github.com/repos/<org>/<repo> \
  -o /tmp/repo.json
python3 -c "import json; d=json.load(open('/tmp/repo.json')); print(d['fork'], d['parent']['full_name'])"
```

Then clone **that** parent (`git clone --depth 1`) and diff. Two directions matter, and they
are *different* findings:

- **Guard present in fork, absent upstream** → the team hardened it. Strongest asymmetry.
- **Guard present in fork AND byte-identical to upstream** → the guard is
  **upstream-inherited, not team-authored**. The claim "the team knows the risk and left the
  sibling unpatched" is then **false** and must be retracted. What survives instead is a
  **regression the fork introduced**: diff the *unguarded* sibling against its own parent and
  show what the fork removed or rewrote. In the worked case the fork had deleted the
  artifact-upload steps and rewritten a helper from "write a local file" to "POST to the
  GitHub API with a hardcoded token". That regression is the real finding, and it is
  *stronger* than the inherited-guard framing because it names code the org itself changed.

Also diff the **helper scripts** (`getFileList.js`, `commentResult.js`), not just the YAML. A
prior session flagged `execSync(\`git diff ${file}\`)` in a helper as possible command
injection; the fork diff showed the fork had **deleted** that code entirely (131 → 16 lines),
which *confirmed* the downgrade to non-finding. **A removal is a refutation you can cite.**

### 2.2 An empty diff is a finding about authorship

`diff -u <parent>/<file> <fork>/<file>` returning **empty** means the file is upstream's.
Empty diff on the *guarded* repo + non-empty diff on the *unguarded* repo is the exact shape
of "upstream shipped the control, the fork regressed the sibling". Report it that way — it
converts a weak "they should have known" into a concrete "here is the code they changed".

---

## 3. npm / dependency confusion

```bash
# scoped package existence — %2F is the encoded slash
curl -s "https://registry.npmjs.org/@scope%2Fpkg"     # -> {"error":"Not found"} = unpublished
curl -s "https://registry.npmjs.org/-/v1/search?text=<scope>&size=10"
```

**Unpublished is a REFUTATION, not a finding** — nothing to confuse. Then run the inverse
check, which is the one that matters:

```bash
grep -c "@scope/pkg" app_bundle.js      # 0 hits = bundle never consumes it
```

If the frontend bundle does not import the package, SDK compromise cannot reach production
through the bundle. A prebuilt SPA bundle is decoupled from the published SDK — verify with
the count before claiming any SDK→frontend path.

**Install hooks census** across every package.json in every cloned repo:

```bash
grep -rn '"postinstall"\|"preinstall"\|"prepare"' --include="package.json" .
```

**Secret sweep** (both must be run; either alone is incomplete):

```bash
find . -name ".env*" -o -name ".npmrc" | grep -v node_modules
git log --all --oneline          # single squashed commit = nothing recoverable
git log -S"<pattern>" -- <file>  # pattern search through history
```

### 3.1 Obfuscated credentials — the plaintext grep will miss them

A plaintext-pattern sweep returning **0 hits is NOT "no secrets"**. The worked session found a
GitHub PAT in a tracked CI helper that every `ghp_` / `sk-` / `AKIA` / `BEGIN RSA` grep missed,
because it was stored **Caesar-shifted by +2** and decoded at runtime by a helper function.

```js
const junk = 'rmicl\x1Eefn]JsfjoHoGRpWOt3_u@L_LpTUc_BLf0T/i/mXC';   // line 3
...
Authorization: scramble(junk),                                        // line 37
...
function scramble(str) {                                              // lines 42-46
  return str.split('').reduce((a, b) =>
    a + String.fromCharCode(b.charCodeAt(0) + 2), '');
}
```

**The tell is the helper, not the string.** Grep for the *decoder* pattern, which survives any
obfuscation scheme:

```bash
grep -rn "String.fromCharCode\|charCodeAt\|atob\|Buffer.from(.*base64\|rot13\|fromCharCode" \
  --include="*.js" --include="*.ts" . | grep -v node_modules
```

Any `charCodeAt` + `String.fromCharCode` pair in a file that also builds an `Authorization`
header is a credential until disproven. Then invert the transform in one `node -e` and
**always test both directions** (`+2` and `-2`) — the stored constant is usually the
*scrambled* form and the function produces the real value, but not always.

**Verify liveness with ONE read-only GET, and keep the plaintext out of the command line.**
The security scanner blocks any command containing a credential-shaped string, so decode and
call inside a single `node -e` — the token never appears in the command text:

```bash
node -e "
const junk='<literal from the file>';
let t=''; for(const ch of junk) t+=String.fromCharCode(ch.charCodeAt(0)+2);
require('https').request('https://api.github.com/user',
  {headers:{'Authorization':'token '+t,'User-Agent':'<browser UA>'}},
  r=>{console.log('STATUS',r.statusCode,'SCOPES',r.headers['x-oauth-scopes'])}).end();
"
```

**Read the result honestly.** `401` = the credential is **revoked/expired** → it is a
*historical* leak (report the hygiene failure + rotation/audit-log advice, not live impact).
`200` + a login = **live credential**, and that is a critical. `403` with scopes present can
mean a scope problem rather than revocation — say which you observed rather than assuming.

**Mask in the report** exactly as for plaintext secrets: prefix + `***MASKED***`, plus a hex
dump of the decoded bytes so the claim is checkable without reprinting the value.

**Also sweep for the *encoder* being dead code.** In the worked case `scramble()` was defined
but never called anywhere except the header line — a function whose only purpose is decoding a
constant is the signature of this pattern regardless of whether it is wired up.

---

## 4. Live service fingerprinting — framework by error shape

Probe paced (~1 req/sec, browser UA). The 404 and health shapes identify the stack without
any exploit:

| Shape | Stack |
|---|---|
| `{"message":"Route GET:/x not found","error":"Not Found","statusCode":404}` | **Express** |
| `{"timestamp":"...","status":404,"error":"Not Found","path":"/"}` | **Spring Boot** |
| `x-powered-by: Next.js`, `vary: rsc, next-router-state-tree...`, `/_next/static/chunks/` | **Next.js** |
| bare `Not found` (plain text) + `ok` health | minimal/custom |

Mixed signatures in one host (Spring-shaped 404, non-Spring envelope on the real route) mean
a gateway fronting a different backend — name it as unresolved rather than guessing.

**Auth-gate probe.** Fire the sensitive paths and read the redirect:

```
/health  /api  /actuator  /swagger-ui.html  /v3/api-docs  /debug/pprof  /metrics
```

- `307 → /login?from=<path>` = **gated** (refutes "unauthenticated debug endpoint")
- `200` on one of them = real finding
- the one intentionally-public endpoint (usually a health/status boolean) is not a finding —
  read its body and say what it actually returns

**Verb test** on any interesting endpoint: POST/PUT/DELETE reaching the same handler as GET
is a genuine observation (method-agnostic routing); `OPTIONS → 204` is just CORS preflight.

---

## 5. The WAF differential — how to REFUTE an injection sink

This is the single most useful technique in the class. For every input-reflection candidate,
send a ladder and read **which of two shapes** comes back:

```
symbol=<script>        -> 403 + 5,489-byte Cloudflare challenge page   (WAF tripped)
symbol='; ls           -> 403 + same challenge page                    (WAF tripped)
symbol=SUI'            -> 200 {"code":-1,"message":"System error","data":null}
symbol=SUI%00          -> 200 identical generic envelope
symbol=<5000 chars>    -> 200 identical generic envelope
symbol=../../etc/passwd-> 200 identical generic envelope
```

- **403 + fixed-size challenge page** = the WAF caught a marker. Confirms WAF presence and
  that the value is processed far enough to trip a rule — but tells you nothing about a sink.
- **identical generic error envelope for every non-tripping payload** = flat, well-handled
  error path. **No differential behaviour = no injection sink.** That is the refutation.
- A **stack trace, origin error, or payload echoed in a distinguishable way** = keep digging.

Record the exact byte size of the challenge page — it is stable and makes the claim checkable.

**Reflection-without-sink is still worth reporting (LOW/INFO).** If raw bytes survive into a
response body — newline (`%0A`) preserved, NUL (`%00` preserved as `\u0000`) — that proves
attacker bytes reach the handler, which is the primitive any future refactor into a
shell/SQL/template would need. Report it as hygiene with the exact reproduction, never as RCE.

**Edge DoS protection is a positive finding too.** An oversized URL (87 KB) returning
**431** in ~0.2 s with the origin never hit means the edge caps request size — record it, it
closes the resource-exhaustion hypothesis.

---

## 6. Vendor / pooled RPC endpoints

A private RPC pool hostname in the bundle is usually a commercial node, not an open relay:

```
GET /            -> 200 <title>Triton One RPC</title> "RPC service operated by Triton One."
POST (any method)-> 403 {"error":{"code":403,"message":"Your IP or provider is blocked from this endpoint"}}
header           -> x-rpc-node: lb-sg9
```

GET the root — the vendor title page identifies the operator in one call and refutes
"exposed internal node". The 403 is IP allowlisting, not a proxy you can use.

---

## 7. Report shape for a negative verdict

Skeleton on disk FIRST (full section list + timestamp), then append every ~5 tool calls.
Sections: `VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE / MITIGATION /
VERIFICATION` + **claim-vs-proof table** (one row per claim, each with the file:line or exact
response) + **REFUTED** + **UNTESTED**.

- Lead the VERDICT with the negative: *"NO LITERAL RCE on protocol infrastructure"*, then
  rank the real findings at true severity.
- A **service fingerprint table** (host | stack | auth | notable) is the highest-value
  artifact for the next session — it stops anyone re-probing.
- REFUTED entries carry the exact error string or byte size that killed them.
- UNTESTED names the specific unresolved question (e.g. "Next.js RSC surface", "on-chain gas
  DoS needs a mainnet tx — out of no-destructive-actions scope"), not a vague "more testing".
- Never inflate a CI-supply-chain or reflection finding into "critical RCE". Evidenced
  LOW/MEDIUM > unproven critical.

---

## 8. Terminal-guard triggers hit in this class

All three are loud and cost one call each; all three are avoidable.

1. **`curl | python3` / `curl | interpreter`** — the security scanner blocks piping downloaded
   content into an interpreter. Fix: `curl -s <url> -o /tmp/x.json` then
   `python3 -c "...json.load(open('/tmp/x.json'))..."`. This also produces the evidence
   artefact for free, so it is strictly better than the pipe.
2. **"Schemeless URL in sink context"** — a command substitution inside a URL string
   (`"https://host/path?q=$(python3 -c ...)"`) trips the same scanner even though nothing is
   piped. Fix: write the encoded value to a file first
   (`python3 -c "...urllib.parse.quote(x)..." > /tmp/q.txt`), then
   `Q=$(cat /tmp/q.txt); curl -s -G --data-urlencode "param@/tmp/file" <url>`.
   `-G --data-urlencode "name@file"` is the clean form for large/encoded query values.
3. **"Credential detected in text"** — the scanner pattern-matches the *command string*, so
   `curl -H "Authorization: token ghp_..."` is blocked before it runs, even for a legitimate
   one-shot liveness check on a credential you just found. Fix: never put the secret in the
   command. Decode and use it inside a single `node -e` (or write it to a file and read it via
   `$(cat)`), so the plaintext exists only in the process, never in the command text. This is
   the same fix as §3.1's liveness check, and it doubles as the evidence artefact.

---

## 9. Quick negative-verdict checklist

Before writing "no RCE", all of these should be answered on the record:

- [ ] CI: every workflow's trigger, install command, guard, permissions, action pinning
- [ ] CI: **fork parent resolved from the API**, and diffed against that parent (§2.1)
- [ ] CI: sibling-repo asymmetry diff — and its DIRECTION read (team-authored vs
      upstream-inherited vs fork-regression) (§2.2)
- [ ] CI: helper scripts (`getFileList.js`, `commentResult.js`) diffed too, not just YAML
- [ ] npm: scoped package published? bundle consumes it? install hooks anywhere?
- [ ] Repos: `.env`/`.npmrc`/history secrets; squashed vs real history
- [ ] Repos: **obfuscated-credential grep** (`charCodeAt`/`fromCharCode`/`atob`/base64 decoders),
      not just plaintext key patterns (§3.1)
- [ ] Any credential found: liveness tested with ONE read-only GET, plaintext kept out of the
      command line, result (401 vs 200) reported honestly (§3.1)
- [ ] Bundle + SDK: `child_process|execSync|spawnSync|spawn(|eval(` census (expect 0)
- [ ] Subdomains: framework fingerprint + auth-gate probe on the sensitive-path ladder
- [ ] Input sinks: WAF differential ladder (403-challenge vs generic-envelope)
- [ ] Edge: oversized-URL behaviour (431 = capped)
- [ ] Every live host in a fingerprint table with its stack and auth state
