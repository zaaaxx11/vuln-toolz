# Docs extraction — read the SOURCE, not the rendered page

Bounty scope pages, protocol docs and vendor security pages are almost always
built on a docs framework. Fetching the rendered HTML gets you a 200 KB
React/RSC payload where the actual policy text is buried in JSON-escaped
`compiledSource` strings. **Never parse that.** Every major docs platform
publishes a clean source form alongside the HTML.

## The `.md` suffix (Mintlify, GitBook, Docusaurus-based docs)

Verified live: `docs.relay.link` is Mintlify. The rendered page was
**206,403 bytes** of RSC; appending `.md` returned **14,073 bytes** of clean
markdown with every table intact.

```bash
# rendered  -> 206 KB of RSC, text buried in compiledSource JSON string
curl -sL "https://docs.relay.link/security/bounties" -o page.html

# source    -> 14 KB clean markdown, tables readable, same content
curl -sL "https://docs.relay.link/security/bounties.md"
```

Discovery is the important half — do not guess, read the hint the page gives you:

```bash
# 1. Mintlify always advertises the markdown alternate in <head>
curl -sL "$URL" | grep -o '<link rel="alternate" type="text/markdown" href="[^"]*"'
#   -> href="/security/bounties.md"

# 2. Mintlify also exposes a full site index — enumerate scope/policy pages
curl -sL "https://docs.<host>/llms.txt"
```

`llms.txt` is the highest-leverage call on any Mintlify site: it lists every
page, so you can find `security/*`, `known-issues`, `audits`, `addresses`
without crawling. Use it before fetching individual pages.

## Framework cheat-sheet

| Framework | Clean source | Notes |
|---|---|---|
| **Mintlify** | `<path>.md` | Announced via `<link rel="alternate" type="text/markdown">`; index at `/llms.txt` |
| **GitBook** | often `<path>.md` or `/llms.txt` | Also `?format=md` on some spaces |
| **Docusaurus** | usually none; use the GitHub repo | Docs are MDX in a public repo — read it directly |
| **Next.js App Router (not a docs platform)** | `__next_f.push` / `__NEXT_DATA__` parse | Only fall back to this; see `rsc-payload-extraction.md` |

## Fallback when no `.md` exists

Strip tags from the HTML **after** removing `<script>`/`<style>`, and check
whether the content was actually server-rendered or is JS-only:

```python
import re, html
raw = open('/tmp/page.html').read()
body = re.sub(r"<script.*?</script>", " ", raw, flags=re.S)
body = re.sub(r"<style.*?</style>", " ", body, flags=re.S)
body = re.sub(r"<(br|/p|/div|/li|/h[1-6]|/tr)[^>]*>", "\n", body, flags=re.I)
body = re.sub(r"<li[^>]*>", "\n- ", body, flags=re.I)
body = re.sub(r"<td[^>]*>", " | ", body, flags=re.I)
text = html.unescape(re.sub(r"<[^>]+>", "", body))
text = re.sub(r"[ \t]+", " ", text)
text = re.sub(r"\n{3,}", "\n\n", text)
```

If the extracted text is mostly nav/menu strings and the real body is missing,
the page is client-rendered — go back to `.md`/`llms.txt` rather than reaching
for a browser.

## Why this matters for bounty work

Policy text is *exact*. Payout caps, tier thresholds, modifier multipliers and
"not eligible" lists have to be quoted verbatim, and a mis-transcribed
multiplier or an invented scope row is a fabricated finding. The `.md` source
gives you tables you can read as tables. Always cite the URL you actually read
(the `.md` variant is the same document — `lastModified` in the RSC confirms
the revision date).
