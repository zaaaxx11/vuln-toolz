# Independent-egress oracles & negative-proof methodology

Use when the target is **IP-firewalled** (packets dropped, not a WAF challenge) and you must
either reach it or *prove* no public path exists. Your own egress is only one data point —
you need oracles that observe from a **different network**. All of the below are free, keyless,
and give third-party evidence you can cite.

## Oracle 1 — DNSDumpster nmap (independent port-state scan)

```
GET https://dnsdumpster.com/quick/?tool=nmap&target=<ip>
Header: HX-Request: true
```

Returns plain-text nmap output scanned from **their** egress. This is the single strongest
piece of evidence that a block is IP-based and not local to you.

- All ports `filtered` = packets dropped = firewall, confirmed by a third party.
- **Sanity-check the oracle first**: scan an IP you know is open. A dead oracle looks identical
  to a firewalled target.
- **Caveat:** only 8 common ports (21, 22, 23, 80, 110, 143, 443, 3389). A service on a
  non-standard port reads as `filtered` even when open. Never claim "no services" — claim
  "no services on the 8 scanned ports".

## Oracle 2 — DNSDumpster reverse-IP (vhost enumeration)

```
GET https://dnsdumpster.com/quick/?tool=reverseiplookup&target=<ip>
Header: HX-Request: true
```

Returns every hostname their dataset has on that IP. Highest-yield single call for finding
vhosts you did not know about — in practice it surfaced **3 vhosts on the target IP that both
CT and direct `dig` had missed**. Run this on every interesting IP before concluding you have
the full vhost list.

## Oracle 3 — DNSDumpster main search (host table + banners)

The old CSRF `<form>` POST is gone; the site is htmx now. Current shape:

1. `GET https://dnsdumpster.com/` — warm cookies. **There is no `csrfmiddlewaretoken` in the
   HTML any more**, so don't waste a step scraping one.
2. `POST https://dnsdumpster.com/htmld/` with body `target=<domain>` and header
   `HX-Request: true`.

Returns ~45 KB: host → IP → ASN → ASN-name table, a "Services / Banners" chart
(`cloudflare` / `awselb/2.0` / `Microsoft-HTTPAPI/2.0` counts), and a per-host "Open Services"
column. Free tier caps at **50 results** per domain.

Parse tolerantly — strict `<td>` regexes are brittle. Grep hostnames and IPs anywhere in the
body and read a context window around each hit instead.

## Oracle 4 — hackertarget (passive DNS, no key)

- `https://api.hackertarget.com/hostsearch/?q=<apex>` → `host,ip` lines. Finds hosts that
  **CT missed**: CT only lists names that received a certificate, DNS lists names that resolve.
  Always run both and union the results.
- `https://api.hackertarget.com/dnslookup/?q=<apex>` → A / MX / NS / TXT / SOA. TXT records
  often carry `google-site-verification=`, `MS=ms…`, and SPF includes that hint at other
  services in the estate.
- `https://api.hackertarget.com/aslookup/?q=<ip>` → ASN + CIDR + owner. Cheap way to attribute
  a range (e.g. `AS17451 BIZNET-AS-AP`, Indonesia) and to decide whether sibling IPs are even
  the same operator.

## Interpreting proxy results against a firewalled target

This is the part that gets misread. When you point a CORS proxy at a firewalled host, the
proxy's **own** status code tells you *where* the failure happened:

| Signal | Meaning |
|---|---|
| `522` / `520` (Cloudflare "connection timed out" / "unknown error") | Proxy edge reached the target's edge, **origin never answered**. Confirms a firewall/origin drop — positive evidence, not a proxy failure. |
| `408 Request Timeout` | Same class: origin silent. |
| `401` from corsproxy.io | The *proxy service* wants an API key. Says nothing about the target. |
| `429` | The proxy service is rate-limiting you. Back off or drop it. |
| `Name or service not known` / `No address associated with hostname` | The **proxy host** is dead. Not a target signal. |
| `SSL: CERTIFICATE_VERIFY_FAILED` (self-signed) | The proxy is MITM-ing TLS. Discard that proxy entirely. |
| `422` from `r.jina.ai` with `page.goto: Timeout … exceeded` | Jina's real browser timed out reaching the host. Strong reachability evidence. |

**Rule:** a spread of `522` / `520` / `408` across several *independent* proxies is stronger
proof of unreachability than any single result, because it rules out "one proxy is broken".
Record the spread, not just one line.

## /24 neighbourhood probe

Before declaring one IP dead, probe siblings in the same /24 — gateway `.1`, a few random
hosts, and the other known hosts. If the whole sampled block times out, the block is filtered
at the network edge rather than per-host, which changes the report from *"this vhost is down"*
to *"this entire range is unreachable"*.

Cheap version: raw `socket.connect()` with a 4–8 s timeout on 80/443. No full port scan needed.

## Negative-proof checklist — "definitively prove no public path exists"

A claim of *no public path* needs **four legs**, observed from **at least two independent
egresses**:

1. **CT negative** — no certificate ever issued for the vhost names. Paginate certspotter with
   `&after=<last-id>`; crt.sh as backup. Note whether a **wildcard** cert exists that could
   still cover them (a single `*.apex` cert means the names *could* be served legitimately).
2. **Port-state negative from a third party** — DNSDumpster nmap shows all-ports-filtered.
3. **Proxy negative** — several independent proxies return origin-timeout-class errors
   (`522`/`520`/`408`), not proxy-side errors.
4. **Archive negative** — Common Crawl / Wayback hold zero captures for the names.

Then state residual uncertainty explicitly: non-standard ports, non-public DNS, and archives
that simply never crawled the host. "Not archived" ≠ "does not exist".

## Pivot after a proven dead end

A firewalled vhost set is rarely the whole estate. Before closing the file:

- **Sibling vhosts on the same IP** (reverse-IP oracle) — they may share the firewall, or may not.
- **Non-firewalled hosts elsewhere in the zone** — Cloudflare-fronted hosts, other ASNs, other
  providers often serve the same application family and *are* reachable.
- **Mesh-VPN estates** — a CNAME to a mesh-VPN host (e.g. `netbird.<apex>`, `*.internal.<apex>`
  returning NODATA) means the whole app family is internal-only. Record that as the finding
  instead of hunting it. In practice one such CNAME exposed 20+ internal app hosts
  (`vault`, `secrets`, `semaphore`, `grafana`, `*-api`, `*-internal`) — a complete internal
  inventory from a single DNS record.
- **Other apexes in the same cert** — CT `dns_names` frequently carries sibling domains
  (`primaqualita.co`, `kairos-it.ca`) that live on completely different, reachable infrastructure.
