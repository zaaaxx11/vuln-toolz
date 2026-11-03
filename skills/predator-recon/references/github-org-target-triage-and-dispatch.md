# GitHub-Org-as-Target: Repo Triage, Clone-All & Parallel Subagent Dispatch

Session detail from the pointgroup-labs hunt (2026-10-28): target given as
`github.com/orgs/<org>/repositories` + a live web app. Companion to the phase-based
pipeline in SKILL.md. This file owns the **org-scale repo target** variant: 20+ repos,
mixed languages, one live app, and the job is "find ONE chain across all of it".

---

## 1. Org enumeration — one call, all the triage metadata

```bash
curl -s "https://api.github.com/orgs/<org>/repos?per_page=100&sort=updated" \
  | jq -r '.[] | "\(.name) | \(.language) | pushed:\(.pushed_at) | \(.description)"'
curl -s https://api.github.com/orgs/<org> \
  | jq -r '{name, blog, location, email, public_repos, created_at}'
```

`sort=updated` is the triage axis. **`pushed_at` recency is the priority signal**: code pushed
in the last days is the least audited and most likely to still contain the bug. In this run
the two most recent pushes (`alula` — Rust credit layer, pushed the day before the hunt;
`alula-liquidator`) became the primary contract targets, while repos untouched for months
dropped in priority.

Also record `created_at` — a young org (here: Dec 2025) means a young codebase, which
correlates with thinner review, fewer audits, and more default-config exposure.

## 2. Clone-all, then size-rank

```bash
mkdir -p hunt/<org> && cd hunt/<org>
for r in $(curl -s "https://api.github.com/orgs/<org>/repos?per_page=100" | jq -r '.[].name'); do
  [ -d "$r" ] || git clone --depth 1 -q https://github.com/<org>/$r.git 2>/dev/null \
    && echo "OK $r" || echo "FAIL $r"
done
du -sh */ | sort -rh
```

`--depth 1` is correct here (no-history constraint anyway) and cuts clone time ~10x.
`du -sh | sort -rh` immediately separates the real codebases from asset-only repos
(here: two 47M/35M repos were adapter/asset dumps, not application code).

## 3. Structural peek before dispatch — the 30-second file inventory

```bash
find <repo> -type f -not -path "*/.git/*" | head -40
```

Run this on the 3-4 priority repos only. What it tells you:

- `roles/*/templates/*.j2` + `tasks/main.yml` → **Ansible infra** (Jinja templates → SSTI /
  shell-injection surface; `handlers/` often restart services)
- `scripts/*.py` + `.github/workflows/` → **CI/CD + upload path** (script injection,
  `pull_request_target`, untrusted-PR checkout with secrets)
- `Cargo.toml` + `programs/*/src/lib.rs` → **Anchor/Soroban program**
- `testnet/*.json` by the thousand → a **data repo**, not code (validator-info pattern)

The file inventory is what lets you write a *specific* subagent brief instead of a vague
one — and brief specificity is the difference between a subagent that returns a chain and
one that returns a summary.

## 4. Dispatch pattern: theory families, not repo splits

Split subagents by **attack-theory family**, never one-per-repo. Repo splits produce three
agents all doing the same recon on different directories; theory splits produce genuinely
divergent coverage (this is the CDC "divergent first" rule applied to delegation).

The split that worked here:

| Agent | Theory family | Brief focus |
|---|---|---|
| 1 | **On-chain fund theft** | account substitution, PDA seed collision, arbitrary CPI, unchecked arithmetic, liquidation logic, oracle manipulation |
| 2 | **Web2 pre-auth chain** | SPA bundle → API surface → auth bypass / IDOR / SSRF / server-action abuse |
| 3 | **Infra / CI/CD / secrets** | committed secrets, workflow script injection, Jinja→shell, upload-path eval |

Each brief must carry, verbatim: the clone path (subagents have no session memory), the
no-git-history / no-CVE-search constraint, the file:line evidence requirement, the
PROVEN-vs-THEORETICAL honesty rule, and the incremental output path
(`findings/<family>.md`). Without the output path, subagent results exist only in the
returned summary and are lost if the session dies.

## 5. Scope-boundary discipline

Third-party infrastructure discovered mid-hunt (here: the Douro Labs / Fogo paymaster at
`fogo-testnet.dourolabs-paymaster.xyz`, which co-signs sponsored transactions) is **not
automatically in scope**. Probe it to establish whether it is the real backend, record what
it reveals (its existence, its allowlist behaviour, its rejection messages), then name it
explicitly in the report as out-of-scope third-party infrastructure. An attacker reading the
report must be able to tell target-owned surface from vendor surface without guessing.

## 6. Pitfalls

- **Do not read git history** when the engagement says fresh-eyes — `--depth 1` at clone
  time enforces it structurally instead of relying on discipline.
- **Do not let a subagent's self-report stand as proof.** A subagent claiming "uploaded" /
  "written" / "confirmed" must return a verifiable handle (absolute path, HTTP status,
  tx hash) that you re-verify yourself before it enters the report.
- **Budget the parent's own workstream.** While subagents run, the parent should be doing
  the highest-value single-target work (here: live API surface mapping), not polling.
  Subagent results re-enter as their own message on completion.
- **A 404 on the SPA origin does not mean the endpoint is dead** — the backend is usually a
  separate host (see `web-api-recon` §7b). Cross-check every "dead" path against the
  org's other discovered hosts before filing it as refuted.

## 7. Brief quality is the whole game — and "mutual correction" needs structure

Observed across two dispatch batches in one engagement: **brief specificity, not agent
count, decides whether you get a chain.**

| Batch | Brief style | Outcome |
|---|---|---|
| 1 | Vague theory families ("hunt these repos for fund theft") | 1 proven chain, 1 honest-zero, 1 **timed out at 50 calls** |
| 2 | Named surfaces + explicit dead-ends + "PROVE IT or say UNPROVEN" | 3 substantive reports, all honest, no timeouts |

**What made batch-2 briefs work — put all of this in every brief:**

1. **Name the exact surfaces.** `svt-agent/src/monitor.rs`, `notifier.rs`,
   `task_runner.rs` — not "audit the daemon". A subagent that has to discover the file
   tree burns its whole budget on `find`.
2. **List the already-refuted theories verbatim.** "Prior round PROVED these are NOT
   exploitable, do not re-litigate: (a) forged membership → verified dead via live
   simulation; (b) PR-title injection → safe env-var pattern." Without this, three agents
   re-derive the same dead ends in parallel and you pay three times for nothing.
3. **State the honesty contract as an instruction, not a hope.** "NO THEORETICAL CLAIMS.
   Every finding must be verified by execution. If you cannot prove it, mark it UNPROVEN
   and say so." An agent told it may report UNPROVEN will; one left ambiguous will
   oversell to look productive.
4. **Give an incremental output path** (`findings/<family>.md`) so a timeout still leaves
   partial work on disk. The batch-1 timeout produced nothing recoverable; batch-2's
   incremental files survived.
5. **Cap the scope per agent.** "Find ONE chain, prioritize depth over breadth: one proven
   chain beats ten theories." Unbounded briefs produce breadth-first surveys that time out.

**When the user asks for agents to "mutually correct" each other over N hours with
looping rounds**, the practical shape is: dispatch divergent theory families in parallel,
then **re-dispatch a second batch whose briefs explicitly cite the first batch's refuted
theories**. That is the correction loop — agents correcting each other by inheritance of
refuted hypotheses, not by reading each other's live output. Do not build a literal
agent-to-agent debate loop; it burns budget re-litigating settled questions.

**Read the returned summaries against the artifacts on disk before believing them.** A
subagent that says "wrote findings to X" may have written a stub. `wc -l` the file.
