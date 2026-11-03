# Engagement Artifact Lifecycle — archive-before-purge disk cleanup

Load when the operator says **"bersihkan disk"**, **"clean up"**, **"next target"**, or any
post-engagement teardown. Also applies after any artifact-heavy session (scraping runs,
data processing, bundle mining) that leaves GB of raw captures on disk.

Distilled from the PornBox/AnalVids teardown (2026-10-23): ~4.3 GB reclaimed, 77% → 68%
disk, zero active tooling broken.

**Operator preference (embed this):** when asked to clean disk, default to **safe-only
purge** and present the ambiguous items as a decision table. "Bersihkan yang aman" means
provably-regenerable or provably-unreferenced — never "probably stale". Aggressive
deletion of anything that might be active work is a worse outcome than leaving 2 GB on
disk.

---

## The protocol (7 steps, in order)

### 1. Measure before touching anything
```bash
df -h / | tail -1
du -sh <engagement-dir>
du -sh <engagement-dir>/* | sort -rh | head -15
find <evidence-dir> -type f | wc -l
```
Report the actual breakdown first. The engagement that *feels* huge is often 23 MB while
the real hogs are elsewhere (`state.db`, playwright cache, old backups). Never purge
blindly off a vibe.

### 2. Classify every item into three buckets

| Bucket | Contents | Action |
|---|---|---|
| **ARCHIVE** | reports (`*.md`), findings, plans, probe scripts, PoCs | copy out first |
| **PURGE** | raw request/response captures, recon dumps, caches, orphan venvs, stale backups | delete |
| **KEEP-ACTIVE** | `state.db`, project dirs, browser binaries, anything referenced by config | leave, list in report |

### 3. Archive before purge — and archive the *analysis*, not just the top-level reports
```bash
mkdir -p ~/predator-recon/archive/<engagement>-<date>
cp *.md ~/predator-recon/archive/<engagement>-<date>/
cp -r findings manual rounds ~/predator-recon/archive/<engagement>-<date>/
# recon/ dirs: keep ONLY the .md analysis files, drop the raw captures
find <dir>/recon -name "*.md" -exec cp {} ~/predator-recon/archive/.../recon-md/ \;
```
**The `.md` files inside `recon/` are the real value** — 30 of them were 2.4 MB of analysis
against 850 MB of raw captures. A top-level-only archive (`cp *.md`) silently loses them.

### 4. Verify integrity BEFORE purging the source
```bash
md5sum ~/predator-recon/archive/<engagement>-<date>/*.md
ls -la ~/predator-recon/archive/<engagement>-<date>/
```
Confirm the archive is complete and readable, *then* delete. Reversing the order means a
failed copy is discovered after the source is gone.

### 5. Check references before purging a venv or project dir
```bash
grep -rl "<path>" ~/.hermes/config.yaml ~/.hermes/skills 2>/dev/null
```
No output = not referenced by Hermes config or any skill = safe. A venv named in a SKILL.md
(e.g. `mobile-app-static-analysis`) must survive.

### 6. Purge, then verify tooling still works
```bash
rm -rf <purged paths>
npm --version && node --version        # after npm cache purge
ls -la ~/.hermes/state.db              # must still exist
df -h / | tail -1
```
A cleanup that breaks `npm` or truncates `state.db` is a net loss. Always run the
post-purge smoke test.

### 7. Report: reclaimed space + what was kept and why
Give the operator (a) GB reclaimed and before/after disk %, (b) the archive location with
md5s, (c) a **"deliberately kept"** table with the reason for each, (d) a
**"needs your decision"** table for anything ambiguous.

---

## Safe-to-purge list (proven this session)

| Item | Size | Why it is safe |
|---|---|---|
| `<engagement>/evidence/` | 23 MB | raw captures; reports + scripts already archived + md5-verified |
| `<engagement>/rounds/`, `logs/` | 1 MB | probe scripts, archived |
| `<old-hunt>/evidence/`, `recon/` | 853 MB | raw; 30 `.md` analysis files + findings archived first |
| `<old-hunt>/venv` | 176 MB | `grep -rl` in `~/.hermes/config.yaml` + `~/.hermes/skills` → zero references |
| `~/.npm/_npx` | 845 MB | npx cache, regenerable on next run |
| `~/.npm/_cacache` | 329 MB | run `npm cache verify` first (it GC'd 63 entries / 119 MB), then purge |
| `hermes-backup-<date>.zip` | 950 MB | 2 days old; live `state.db` is the real source of truth |

## Deliberately KEPT (do not purge without explicit instruction)

| Item | Size | Reason |
|---|---|---|
| `~/.hermes/state.db` | 2.3 GB | **memory + `session_search` source of truth.** VACUUM can reclaim ~1 GB but only on request — never delete |
| `~/.cache/ms-playwright` | 2.6 GB | browser binaries used by scraping/automation skills |
| `zcrapers`, `venv-ag`, `royco`, `tropicana_scrape` | 1.3 GB | active project dirs, not cache |
| `~/.nvm` | 892 MB | Node versions; check for stale ones before pruning |

---

## Pitfalls

- **Never purge `state.db`.** It holds persistent memory and the session history that
  `session_search` reads. A truncated DB is unrecoverable context loss, not disk savings.
- **`cp *.md` is not an archive.** Recon dirs bury their analysis in subdirectories. Walk
  with `find -name "*.md"`.
- **Don't purge a venv on size alone.** Grep for references first; skills name venvs.
- **`npm cache verify` before `rm -rf _cacache`** — verify GCs safely and confirms npm
  still functions afterwards.
- **Don't delete project dirs to hit a space target.** `royco` / `tropicana_scrape` /
  `zcrapers` look like junk by name; they are active work.
- **Report the decision table, don't guess.** If an item is ambiguous, it goes in
  "needs your decision" with its size and why it is ambiguous. The operator said
  *"bersihkan yang aman"* — honour the word "aman".

## Archive layout convention

```
~/predator-recon/archive/
  ├── pornbox-2026-10-22/     FINAL_REPORT.md  FOLLOWUP_R2.md  rounds/ (34 scripts)
  └── lv-hunt-2026-10-19/     CHAIN.md  PLAN.md  ROUNDS.md  findings/  manual/  recon-md/ (30 files)
```

Engagement working dirs keep only their reports; raw evidence lives only in the archive
window and is then gone. This keeps `~/predator-recon/` at a few MB per engagement
instead of a few hundred.
