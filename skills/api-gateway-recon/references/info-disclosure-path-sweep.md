# Bulk info-disclosure / misconfig path sweep (read-only, ≤1 req/s)

Worked run: MediaMarkt/Saturn YesWeHack, ~31 reachable non-Cloudflare hosts, taxonomy #18/#19/#20
(info-disclosure / misconfig / dir-traversal). Reproduce the method, not the hosts.

## Curated path list (40 common + 7 IIS-specific)

```
/.git/HEAD /.git/config /.env /.env.local /config.json /config.yaml /.svn/entries
/backup.zip /backup.tar.gz /db.sql /dump.sql /robots.txt /sitemap.xml
/.well-known/security.txt /server-status /server-info
/actuator /actuator/health /actuator/env /actuator/heapdump
/api-docs /swagger-ui/index.html /swagger.json /openapi.json /v3/api-docs
/graphql /console /phpinfo.php /web.config /WEB-INF/web.xml
/trace /debug /metrics /health /status /version /changelog.txt
/Thumbs.db /.DS_Store /admin /login
# IIS-specific add-ons:
/web.config.bak /iisstart.htm /trace.axd /elmah.axd /bin/ /appsettings.json
```

## Harness shape

- One shell loop: `for host; for path; curl -sS -m 12 -k --max-filesize 262144 -D hdr -o body -w
  '%{http_code}|%{content_type}|%{size_download}' "$url"; sleep 1; done`. Fixed `sleep 1` enforces
  the pacing rule with no cleverness. Run it **backgrounded with notify-on-complete** — a 31×47 grid
  is ~1350 requests ≈ 20–40 min (some hosts add `-m 12` timeouts).
- Log every line as `host|path|code|ctype|size` to a progress file the moment it returns, so you can
  analyse incrementally while the sweep runs.
- Save each raw body+header to `raw/<host>__<path>.{hdr,body}` — the signature scan needs the bodies.

## The one false positive that matters: SPA 200 catch-all

A front-end server answers `200 text/html` with the **identical byte size** for *every* path, so
`/.git/HEAD`, `/.env`, `/backup.zip` all look like hits. Rule: **same size + text/html + 200 across
all paths ⇒ SPA shell, not a finding.** Cluster hosts by their constant 200-size (e.g. 789 / 7590 /
4897 / 3539 / 1589 / 767 B in this run) and treat each cluster as one catch-all, not N findings.

A real file breaks the constant: `robots.txt` (`text/plain`, 61B), a real `sitemap.xml` (2513B; or a
genuinely huge one capped by `--max-filesize`), `/graphql` returning `application/json`.

## Verify with a signature scan over the raw bodies (never trust the status code)

```
grep -rI "Index of"                 # directory listing
grep -rI "ref: refs"                # real .git/HEAD
grep -rI "repositoryformatversion"  # real .git/config
grep -rIE "at java\.|Traceback|Exception in thread"
grep -rIE "password=|AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|api[_-]?key|secret[_-]?key"
```

Also dump every non-HTML/non-JSON content-type body and every JSON body — the JSON ones here were
only auth/error envelopes (`{"error":"GraphQL query is missing."}`, `{"message":"Unauthorized",...}`),
i.e. real endpoints, not leaks.

## Verdict taxonomy (report each as an explicit negative unless a signature scan hit)

| Verdict | Tell | Example hosts (this estate) |
|---|---|---|
| SPA catch-all | identical 200 size for all paths | store, vorteile, *.tracking, smartbarservice, gbs-workflows-predev, datahub-qa, careers |
| 302 auth gate | all paths 302 → login | cloud, cloud-auth, prospekte |
| 403 WAF | blanket 403 | tarife, tarife-api2, pvn |
| No surface | all 404 (incl. IIS paths) | app, rast, pickup, relaunch, qrmaker, b2c-bonus, avd, sasviya.dev |
| Public only | robots.txt / sitemap.xml only | news-de, link-themenwelten, edi, prod-edi |
| LB health probe | 4-byte `text/plain: GOOD` on /admin & /health | datahub-qa |
| App login page | Spring Security OAuth2 `/login` (leaks provider id) | fraud-dev |
| Auth-gated UI | 302 → login, `/api-docs` & `/metrics` 401 | grafana.prod.mpl |

## Outcome

**No LEAK found** across all 31 hosts. The deliverable is the per-host verdict table + the negative
signature scan + the (non-leak) endpoint observations (live `/graphql` on store → see
`preauth-graphql-and-spa-endpoints.md`; OAuth2 provider id `fifa` on fraud-dev `/login`). Reporting a
clean estate is a valid result — do not inflate SPA shells into findings.
