#!/usr/bin/env python3
"""js_taint_scan.py — static DOM-XSS taint / sink / source scanner for MINIFIED JS bundles.

Built for webpack/rollup output where line numbers are meaningless: every finding is reported as a
BYTE OFFSET (plus a computed line number for convenience). Use it to triage hundreds of sinks down to
the handful whose enclosing function actually reads a URL-controllable source.

Usage:
    python3 js_taint_scan.py <bundle.js> [more.js ...] [-o outdir] [--window 400] [--ctx 260]

Outputs (in outdir, default ./js_taint_out):
    sinks_<name>.txt   human-readable: every sink with its src-proximity flag + context
    taint_<name>.json  machine-readable: same data for downstream tooling
    summary.txt        per-file sink/source counts

Verdict workflow:
    1. Read summary.txt — a bundle with 0 eval(/document.write/setTimeout("…")/window.open has already
       lost most of the DOM-XSS class. Record that as a hard negative.
    2. In sinks_<name>.txt, read only the entries whose src-proximity is NOT 'NONE'.
    3. For each, read the ENCLOSING FUNCTION (grep backwards to the nearest `function`/`=>` boundary)
       and write CLEAN(reason) or TAINTED(full path). A sink with no source in its window is NOT
       automatically clean — check whether the value arrives via closure/parameter from a caller.
"""
import argparse, json, os, re, sys
from collections import Counter

SINKS = [
    (r'\.innerHTML\s*=', 'innerHTML='),
    (r'\.outerHTML\s*=', 'outerHTML='),
    (r'document\.write(?:ln)?\s*\(', 'document.write'),
    (r'insertAdjacentHTML\s*\(', 'insertAdjacentHTML'),
    (r'new\s+Function\s*\(', 'new Function'),
    (r'(?<![\w.])eval\s*\(', 'eval('),
    (r'setTimeout\s*\(\s*["\']', 'setTimeout("'),
    (r'setInterval\s*\(\s*["\']', 'setInterval("'),
    (r'location\.href\s*=', 'location.href='),
    (r'location\.assign\s*\(', 'location.assign'),
    (r'location\.replace\s*\(', 'location.replace'),
    (r'window\.open\s*\(', 'window.open'),
    (r'\.html\s*\(', 'jQuery.html('),
    (r'\.append\s*\(', '.append('),
    (r'\.prepend\s*\(', '.prepend('),
    (r'\.after\s*\(', '.after('),
    (r'\.before\s*\(', '.before('),
    (r'\.replaceWith\s*\(', '.replaceWith('),
    (r'\.wrap\s*\(', '.wrap('),
    (r'\.src\s*=', '.src='),
    (r'\.href\s*=', '.href='),
    (r'\.action\s*=', '.action='),
    (r'document\.cookie\s*=', 'document.cookie='),
    (r'localStorage\.setItem', 'localStorage.setItem'),
    (r'sessionStorage\.setItem', 'sessionStorage.setItem'),
]

SOURCES = [
    r'location\.search', r'location\.hash', r'location\.pathname', r'location\.href',
    r'document\.referrer', r'window\.name', r'URLSearchParams', r'\.searchParams',
    r'document\.URL', r'document\.documentURI', r'history\.(?:push|replace)State',
    r'decodeURIComponent', r'unescape\s*\(', r'atob\s*\(', r'JSON\.parse',
    r'event\.data', r'(?<![\w.])e\.data', r'postMessage', r'getQueryParam', r'getParam',
    r'window\.location',
]

# Sinks whose absence is itself a reportable hard negative.
HIGH_SIGNAL_ABSENCES = ['eval(', 'document.write', 'new Function', 'window.open',
                        'setTimeout("', 'setInterval("', 'location.assign', 'location.replace']


def build_line_index(txt):
    starts = [0] + [m.end() for m in re.finditer(r'\n', txt)]
    def off2line(o):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= o:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1
    return off2line, len(starts)


def scan(path, window=400, ctx=260):
    txt = open(path, 'rb').read().decode('utf-8', errors='replace')
    off2line, nlines = build_line_index(txt)
    src_res = [re.compile(p) for p in SOURCES]

    sinks, seen = [], set()
    for pat, name in SINKS:
        for m in re.finditer(pat, txt):
            key = (name, m.start())
            if key in seen:
                continue
            seen.add(key)
            lo = max(0, m.start() - window)
            hi = min(len(txt), m.end() + window)
            win = txt[lo:hi]
            hits = sorted({p for p, r in zip(SOURCES, src_res) if r.search(win)})
            s, e = max(0, m.start() - ctx), min(len(txt), m.end() + ctx)
            sinks.append({
                'name': name, 'offset': m.start(), 'line': off2line(m.start()),
                'src_proximity': hits if hits else None,
                'context': txt[s:e].replace('\n', '\\n'),
            })

    counts = Counter(s['name'] for s in sinks)
    return {
        'file': os.path.basename(path), 'size': len(txt), 'lines': nlines,
        'sinks': sinks, 'sink_counts': dict(counts),
        'high_signal_absences': [h for h in HIGH_SIGNAL_ABSENCES if h not in counts],
        'source_counts': dict(Counter(
            p for p, r in zip(SOURCES, src_res) for _ in re.finditer(r.pattern, txt))),
    }


def render(res):
    out = [f"\n{'=' * 100}", f"{res['file']}  ({res['size']} chars, {res['lines']} lines)",
           f"{'=' * 100}"]
    out.append("SINK COUNTS: " + json.dumps(res['sink_counts']))
    out.append("HIGH-SIGNAL ABSENCES (report as hard negatives): " +
               (', '.join(res['high_signal_absences']) or 'none'))
    out.append("SOURCE COUNTS: " + json.dumps(res['source_counts']))
    for s in res['sinks']:
        flag = ', '.join(s['src_proximity']) if s['src_proximity'] else 'NONE'
        out.append(f"\n--- [{s['name']}] @offset {s['offset']} (line {s['line']}) | src-proximity: {flag}")
        out.append(f"    ...{s['context']}...")
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('bundles', nargs='+')
    ap.add_argument('-o', '--outdir', default='./js_taint_out')
    ap.add_argument('--window', type=int, default=400)
    ap.add_argument('--ctx', type=int, default=260)
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    summary = []
    for p in a.bundles:
        if not os.path.exists(p):
            print(f"!! missing {p}", file=sys.stderr)
            continue
        res = scan(p, a.window, a.ctx)
        name = os.path.splitext(os.path.basename(p))[0]
        open(os.path.join(a.outdir, f'sinks_{name}.txt'), 'w').write(render(res))
        json.dump(res, open(os.path.join(a.outdir, f'taint_{name}.json'), 'w'), indent=1)
        summary.append(
            f"{res['file']:<20} {res['size']:>9} B  sinks={len(res['sinks']):>4}  "
            f"absences={len(res['high_signal_absences'])}")
        print(summary[-1])
    open(os.path.join(a.outdir, 'summary.txt'), 'w').write('\n'.join(summary) + '\n')
    print(f"\nWrote {len(summary)} report(s) to {a.outdir}/")


if __name__ == '__main__':
    main()
