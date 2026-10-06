#!/usr/bin/env python3
"""NVD Switch Lab - a hands-on look at NVD API 2.0 compatibility.

Everything here uses only the Python standard library. No pip install, no
server, no config file. Works on Windows, macOS and Linux with Python 3.8+.

  python3 lab.py doctor                      check your setup
  python3 lab.py query --cve CVE-2024-3400   query the bundled NVD sample
  python3 lab.py query --source nist --cve CVE-2024-3400
  python3 lab.py compare --cve CVE-2024-3400 --open
  python3 lab.py scoreboard --open
  python3 lab.py verify-cpe "cpe:2.3:a:nodejs:node.js:22.22.0:*:*:*:*:*:*:*"

Sources:
  local-nvd    bundled snapshot of NIST NVD          (offline)
  local-vc     bundled snapshot of VulnCheck compat  (offline)
  nist         live https://services.nvd.nist.gov    (no key needed)
  vulncheck    live VulnCheck NVD-compatible API     (needs a free key)

This product uses the NVD API but is not endorsed or certified by the NVD.
"""

import argparse
import json
import os
import sqlite3
import sys
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "data", "corpus.sqlite")
OUT_DIR = os.path.join(HERE, "out")

NIST_BASE = "https://services.nvd.nist.gov/rest/json"
# Production compat endpoint — live 2026-10-05 (ThreatCon).
VC_BASE = os.environ.get("VC_BASE", "https://api.vulncheck.com/rest/json")

SOURCES = {
    "local-nvd": {"kind": "local", "row": "nvd", "label": "NIST NVD (bundled)"},
    "local-vc": {"kind": "local", "row": "vulncheck", "label": "VulnCheck (bundled)"},
    "nist": {"kind": "remote", "base": NIST_BASE, "label": "NIST NVD (live)"},
    "vulncheck": {"kind": "remote", "base": VC_BASE, "label": "VulnCheck (live)"},
}


# --------------------------------------------------------------------------
# the one seam that matters: every source returns the same NVD 2.0 envelope
# --------------------------------------------------------------------------

def fetch(source, params):
    """Return an NVD 2.0 response envelope from any source.

    This is the whole point of the lab. The caller does not care which source
    it is talking to, because the shape that comes back is identical.
    """
    cfg = SOURCES.get(source)
    if cfg is None:
        raise LabError("unknown source %r (choose from: %s)"
                     % (source, ", ".join(sorted(SOURCES))))
    if cfg["kind"] == "local":
        return fetch_local(cfg["row"], params)
    return fetch_remote(cfg["base"], params)


class LabError(Exception):
    """An error we can explain to a human without a traceback."""


def envelope(vulns, params, total=None):
    per = int(params.get("resultsPerPage", 2000))
    start = int(params.get("startIndex", 0))
    return {
        "resultsPerPage": len(vulns),
        "startIndex": start,
        "totalResults": total if total is not None else len(vulns),
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "vulnerabilities": vulns,
    }


def open_db():
    if not os.path.exists(DB_PATH):
        raise LabError("bundled data not found at %s\n"
                     "        The lab bundle looks incomplete - re-extract the zip."
                     % DB_PATH)
    return sqlite3.connect(DB_PATH)


def fetch_local(row_source, params):
    """Serve an NVD-shaped response out of the bundled SQLite corpus.

    Prints a brief status line so the screen is not silent during a read.

    Supports the subset of NVD 2.0 parameters the compat API supports in v1:
    cveId, cveIds, pubStartDate/pubEndDate, hasKev, vulnStatuses,
    resultsPerPage, startIndex. Note there is deliberately no keywordSearch.
    """
    label = {"nvd": "NIST NVD (bundled)", "vulncheck": "VulnCheck (bundled)"}.get(
        row_source, row_source)
    print("reading %s..." % label)
    db = open_db()
    where = ["source = ?"]
    args = [row_source]

    if params.get("cveId"):
        where.append("id = ?")
        args.append(params["cveId"].upper())
    if params.get("cveIds"):
        ids = [x.strip().upper() for x in params["cveIds"].split(",") if x.strip()]
        if len(ids) > 100:
            raise LabError("cveIds accepts at most 100 ids (you gave %d)" % len(ids))
        where.append("id IN (%s)" % ",".join("?" * len(ids)))
        args.extend(ids)
    if params.get("pubStartDate"):
        where.append("published >= ?")
        args.append(params["pubStartDate"])
    if params.get("pubEndDate"):
        where.append("published <= ?")
        args.append(params["pubEndDate"])
    if "hasKev" in params:
        where.append("has_kev = 1")
    if params.get("vulnStatuses"):
        sts = [s.strip() for s in params["vulnStatuses"].split(",") if s.strip()]
        where.append("vuln_status IN (%s)" % ",".join("?" * len(sts)))
        args.extend(sts)

    clause = " AND ".join(where)
    total = db.execute("SELECT COUNT(*) FROM cve WHERE " + clause, args).fetchone()[0]
    per = int(params.get("resultsPerPage", 2000))
    start = int(params.get("startIndex", 0))
    rows = db.execute(
        "SELECT doc FROM cve WHERE " + clause + " ORDER BY id LIMIT ? OFFSET ?",
        args + [per, start],
    ).fetchall()
    db.close()

    if total == 0 and row_source == "vulncheck":
        raise LabError(
            "the bundled VulnCheck snapshot is empty.\n"
            "        This bundle shipped NVD-only. Use --source vulncheck with a\n"
            "        free API key, or ask the facilitator for the full bundle.")
    return envelope([{"cve": json.loads(r[0])} for r in rows], params, total)


def fetch_remote(base, params):
    import urllib.error
    import urllib.parse
    import urllib.request

    endpoint = params.pop("_endpoint", "cves")
    url = "%s/%s/2.0?%s" % (base, endpoint, urllib.parse.urlencode(params))
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")

    key = os.environ.get("VC_API_KEY", "").strip()
    if key and base != NIST_BASE:
        # apiKey is NVD's own header name. That the compat API accepts it
        # verbatim is exactly why an existing NVD client needs no code change.
        req.add_header("apiKey", key)
    elif base != NIST_BASE:
        raise LabError(
            "no API key set for the VulnCheck endpoint.\n"
            "        Get a free key at https://vulncheck.com/community, then:\n"
            "          macOS/Linux:  export VC_API_KEY=your-key-here\n"
            "          Windows:      set VC_API_KEY=your-key-here")

    print("→ GET %s" % url)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            body = r.read()
            elapsed = time.time() - t0
            print("← %d in %.2fs  (%d bytes)\n" % (r.status, elapsed, len(body)))
            return json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as e:
        elapsed = time.time() - t0
        print("← %d in %.2fs\n" % (e.code, elapsed))
        raise LabError(explain_http(e, url))
    except urllib.error.URLError as e:
        raise LabError("could not reach %s\n        %s\n"
                     "        If you are offline, use the bundled sources: "
                     "--source local-nvd / local-vc" % (url, e.reason))


def explain_http(e, url):
    """Plain-language diagnosis instead of a stack trace.

    These cases are ported from .claude/scripts/vc-nvd.sh, which already
    learned them the hard way.
    """
    try:
        body = e.read()[:300].decode("utf-8", "replace")
    except Exception:
        body = ""
    if e.code == 401:
        return ("401 Unauthorized from %s\n"
                "        The API key was rejected. Check VC_API_KEY." % url)
    if e.code == 403 and "<html" in body.lower():
        return ("403 from the edge (HTML, not JSON) at %s\n"
                "        This endpoint is IP-restricted and you are not on an\n"
                "        allowlisted network. Use --source local-vc instead." % url)
    if e.code == 403:
        return ("403 from the application at %s\n"
                "        Key is valid but not entitled to this route, or you hit a\n"
                "        rate limit. Wait 30 seconds and retry." % url)
    if e.code == 404:
        return ("404 Not Found at %s\n"
                "        Check the path. The compat API mirrors NVD exactly:\n"
                "        /rest/json/cves/2.0 - not /v3/nvd/cves/2.0." % url)
    if e.code == 429:
        return "429 rate limited at %s\n        Wait 30 seconds and retry." % url
    if e.code == 503:
        return ("503 from %s\n        The upstream is having a moment. This is the\n"
                "        failure mode the talk is about. Retry, or use --source "
                "local-nvd." % url)
    return "HTTP %s from %s\n        %s" % (e.code, url, body.replace("\n", " "))


# --------------------------------------------------------------------------
# CPE helpers - the numbers the workshop actually turns on
# --------------------------------------------------------------------------

def nvd_cpes(cve):
    """Concrete CPE criteria from the standard NVD `configurations` field."""
    out = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("criteria"):
                    out.append(m["criteria"])
    return out


def vc_cpes(cve):
    """Concrete CPEs from VulnCheck's additive `vcVulnerableCPEs` field.

    This is NOT an NVD field. A pure drop-in consumer that only reads
    `configurations` will never see it - which is the honest version of the
    story: compatibility is free, this extra coverage costs you three lines.
    """
    return list(cve.get("vcVulnerableCPEs") or [])


def products(cpes):
    """Distinct vendor:product pairs.

    Raw CPE counts overstate coverage, because one CVE can enumerate hundreds
    of versions of a single package. Distinct products is the honest metric
    and the more useful one if you are matching an inventory.
    """
    out = set()
    for c in cpes:
        parts = c.split(":")
        if len(parts) > 4:
            out.add("%s:%s" % (parts[3], parts[4]))
    return out


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_doctor(args):
    ok = True
    print("NVD Switch Lab - setup check\n")

    v = sys.version_info
    good = v >= (3, 8)
    ok &= good
    print("%s Python %d.%d.%d %s" % ("[ok]  " if good else "[FAIL]",
                                     v.major, v.minor, v.micro,
                                     "" if good else "- need 3.8 or newer"))

    for mod in ("sqlite3", "urllib.request", "json", "webbrowser"):
        try:
            __import__(mod)
            print("[ok]   module %s" % mod)
        except ImportError:
            ok = False
            print("[FAIL] module %s is missing" % mod)

    if os.path.exists(DB_PATH):
        mb = os.path.getsize(DB_PATH) / 1024.0 / 1024.0
        try:
            db = open_db()
            counts = dict(db.execute(
                "SELECT source, COUNT(*) FROM cve GROUP BY source").fetchall())
            cap = dict(db.execute("SELECT key, value FROM meta").fetchall()).get(
                "captured_utc", "unknown")
            db.close()
            print("[ok]   bundled data %.1f MB - captured %s" % (mb, cap))
            print("       NVD records:       %d" % counts.get("nvd", 0))
            if counts.get("vulncheck"):
                print("       VulnCheck records: %d" % counts["vulncheck"])
            else:
                print("[warn] VulnCheck records: 0 - offline comparison unavailable")
        except Exception as e:
            ok = False
            print("[FAIL] bundled data unreadable: %s" % e)
    else:
        ok = False
        print("[FAIL] bundled data missing at %s" % DB_PATH)

    print("[%s] VC_API_KEY %s" % (
        "ok  " if os.environ.get("VC_API_KEY") else "info",
        "is set" if os.environ.get("VC_API_KEY")
        else "not set - only needed for the live VulnCheck source"))

    print("\n%s" % ("Ready. Start with:  python3 lab.py query --cve CVE-2024-3400"
                    if ok else
                    "Not ready - fix the [FAIL] lines above, or ask the facilitator."))
    return 0 if ok else 1


def cmd_query(args):
    params = {}
    if args.cve:
        params["cveId"] = args.cve
    if args.cve_ids:
        params["cveIds"] = args.cve_ids
    if args.pub_start:
        params["pubStartDate"] = args.pub_start
    if args.pub_end:
        params["pubEndDate"] = args.pub_end
    if args.has_kev:
        params["hasKev"] = ""
    if args.status:
        params["vulnStatuses"] = args.status
    params["resultsPerPage"] = args.limit

    data = fetch(args.source, params)

    print("source        : %s" % SOURCES[args.source]["label"])
    print("format        : %s   version: %s" % (data.get("format"), data.get("version")))
    print("totalResults  : %s" % data.get("totalResults"))
    print("resultsPerPage: %s   startIndex: %s\n"
          % (data.get("resultsPerPage"), data.get("startIndex")))

    if args.raw:
        print(json.dumps(data, indent=2)[:args.raw_bytes])
        return 0

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        print("no records matched")
        return 0
    print("%-18s %-20s %-6s %-6s %s" % ("CVE", "STATUS", "CPEs", "+VC", "CWEs"))
    print("-" * 64)
    for v in vulns:
        c = v.get("cve") or {}
        print("%-18s %-20s %-6d %-6d %d" % (
            c.get("id", "?"), (c.get("vulnStatus") or "-")[:20],
            len(nvd_cpes(c)), len(vc_cpes(c)), len(c.get("weaknesses") or [])))
    print("\n%d record(s) shown. 'CPEs' is the standard NVD configurations field; "
          "'+VC' is vcVulnerableCPEs." % len(vulns))
    return 0


def cmd_compare(args):
    print("[1/2] %s" % SOURCES[args.left]["label"])
    left = fetch(args.left, {"cveId": args.cve} if args.cve else
                 {"cveIds": args.cve_ids, "resultsPerPage": 100})
    print("[2/2] %s" % SOURCES[args.right]["label"])
    right = fetch(args.right, {"cveId": args.cve} if args.cve else
                  {"cveIds": args.cve_ids, "resultsPerPage": 100})
    lmap = {v["cve"]["id"]: v["cve"] for v in left.get("vulnerabilities") or []}
    rmap = {v["cve"]["id"]: v["cve"] for v in right.get("vulnerabilities") or []}
    shared = sorted(set(lmap) & set(rmap))
    if not shared:
        raise LabError("no CVEs in common between %s and %s" % (args.left, args.right))

    rows, diffs = [], 0
    for cid in shared:
        a, b = lmap[cid], rmap[cid]
        fields = {}
        for f in ("vulnStatus", "published", "lastModified"):
            fields[f] = (a.get(f), b.get(f))
        fields["configurations (CPE count)"] = (len(nvd_cpes(a)), len(nvd_cpes(b)))
        fields["metrics (keys)"] = (
            ",".join(sorted((a.get("metrics") or {}).keys())),
            ",".join(sorted((b.get("metrics") or {}).keys())))
        fields["weaknesses (count)"] = (
            len(a.get("weaknesses") or []), len(b.get("weaknesses") or []))
        fields["references (count)"] = (
            len(a.get("references") or []), len(b.get("references") or []))
        differing = [k for k, (x, y) in fields.items() if x != y]
        diffs += len(differing)
        rows.append({
            "id": cid, "fields": fields, "differing": differing,
            "extra_left": sorted(set(a) - set(b)),
            "extra_right": sorted(set(b) - set(a)),
            "vc_cpes": len(vc_cpes(b)) or len(vc_cpes(a)),
            "vc_products": len(products(vc_cpes(b) or vc_cpes(a))),
            "nvd_cpes": len(nvd_cpes(a)),
        })

    print("compared %d CVE(s): %s  vs  %s" % (
        len(shared), SOURCES[args.left]["label"], SOURCES[args.right]["label"]))
    print("standard NVD field differences: %d" % diffs)
    if diffs == 0:
        print("\n  -> Every standard NVD field is identical across all %d CVEs." % len(shared))
        print("     That is the compatibility claim, measured rather than asserted.")
    extra = sorted({f for r in rows for f in r["extra_right"]})
    if extra:
        print("\nfields present only in %s: %s"
              % (SOURCES[args.right]["label"], ", ".join(extra)))

    path = write_compare_html(rows, args, diffs)
    print("\nwrote %s" % path)
    if args.open:
        webbrowser.open(Path(path).as_uri())
    return 0


def cmd_scoreboard(args):
    db = open_db()
    have_vc = db.execute(
        "SELECT COUNT(*) FROM cve WHERE source='vulncheck'").fetchone()[0]
    db.close()
    if not have_vc:
        raise LabError("the bundled VulnCheck snapshot is empty, so there is nothing "
                     "to score against.\n        Ask the facilitator for the full "
                     "bundle, or run: python3 lab.py compare --right vulncheck")

    nvd = fetch("local-nvd", {"resultsPerPage": 5000})
    vc = fetch("local-vc", {"resultsPerPage": 5000})
    nmap = {v["cve"]["id"]: v["cve"] for v in nvd["vulnerabilities"]}
    vmap = {v["cve"]["id"]: v["cve"] for v in vc["vulnerabilities"]}

    buckets = {}
    db = open_db()
    for cid, b in db.execute("SELECT id, bucket FROM cve WHERE source='nvd'"):
        buckets[cid] = b
    db.close()

    stats = {}
    for cid in sorted(set(nmap) & set(vmap)):
        b = buckets.get(cid, "recent")
        s = stats.setdefault(b, {"n": 0, "nvd_zero": 0, "filled": 0,
                                 "nvd_cpes": 0, "vc_cpes": 0,
                                 "nvd_products": set(), "vc_products": set()})
        ncpe, vcpe = nvd_cpes(nmap[cid]), vc_cpes(vmap[cid])
        s["n"] += 1
        s["nvd_cpes"] += len(ncpe)
        s["vc_cpes"] += len(vcpe)
        s["nvd_products"] |= products(ncpe)
        s["vc_products"] |= products(vcpe)
        if not ncpe:
            s["nvd_zero"] += 1
            if vcpe:
                s["filled"] += 1

    print("CPE coverage across the bundled corpus\n")
    print("%-10s %6s %10s %10s %12s %12s" % (
        "bucket", "CVEs", "NVD CPEs", "VC CPEs", "NVD blank", "VC fills"))
    print("-" * 66)
    for b in ("recent", "kev", "anchor"):
        s = stats.get(b)
        if not s:
            continue
        print("%-10s %6d %10d %10d %12s %12s" % (
            b, s["n"], s["nvd_cpes"], s["vc_cpes"],
            "%d (%d%%)" % (s["nvd_zero"], 100 * s["nvd_zero"] / s["n"]),
            "%d (%d%%)" % (s["filled"],
                           100 * s["filled"] / s["nvd_zero"]) if s["nvd_zero"] else "-"))
    print("\nDistinct vendor:product pairs (the honest coverage metric):")
    for b in ("recent", "kev", "anchor"):
        s = stats.get(b)
        if s:
            print("  %-8s NVD %5d   VulnCheck %5d"
                  % (b, len(s["nvd_products"]), len(s["vc_products"])))

    path = write_scoreboard_html(stats)
    print("\nwrote %s" % path)
    if args.open:
        webbrowser.open(Path(path).as_uri())
    return 0


def cmd_verify_cpe(args):
    """Check a CPE against the live CPE dictionary.

    Worth doing: a CPE that is not in the official dictionary still tells you
    what is affected, but it will not match an inventory keyed on NVD's
    dictionary. Knowing which kind you have is the point of this step.
    """
    params = {"cpeMatchString": args.cpe, "resultsPerPage": 5, "_endpoint": "cpes"}
    base = SOURCES[args.source]["base"]
    data = fetch_remote(base, dict(params))
    total = data.get("totalResults", 0)
    print("source : %s" % SOURCES[args.source]["label"])
    print("cpe    : %s" % args.cpe)
    print("matches: %s\n" % total)
    if total:
        for p in (data.get("products") or [])[:5]:
            c = p.get("cpe") or {}
            titles = c.get("titles") or [{}]
            print("  %s" % c.get("cpeName"))
            print("    %s  deprecated=%s"
                  % (titles[0].get("title", "-"), c.get("deprecated")))
        print("\n  -> In the dictionary. This CPE will match inventory keyed on NVD.")
    else:
        print("  -> NOT in the official CPE dictionary.")
        print("     It still identifies affected software, but it will not match")
        print("     an inventory that only accepts dictionary CPEs. Worth knowing")
        print("     before you rely on it for asset matching.")
    return 0


# --------------------------------------------------------------------------
# HTML output - self-contained, no external requests, light + dark
# --------------------------------------------------------------------------

CSS = """
:root{--bg:#fbfbfa;--fg:#1a1a18;--mut:#6b6b64;--line:#e3e3de;--card:#fff;
--add:#1a7f4b;--addbg:#e8f6ee;--same:#6b6b64;--samebg:#f2f2ef;--warn:#9a5b00}
@media (prefers-color-scheme:dark){:root{--bg:#16161a;--fg:#ececef;--mut:#9a9aa4;
--line:#2c2c33;--card:#1d1d22;--add:#4ade80;--addbg:#14321f;--same:#9a9aa4;
--samebg:#232329;--warn:#fbbf24}}
*{box-sizing:border-box}
body{margin:0;padding:2.5rem 1.5rem;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1040px;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 .3rem;letter-spacing:-.01em}
h2{font-size:1.05rem;margin:2.2rem 0 .7rem;font-weight:600}
.sub{color:var(--mut);margin:0 0 2rem;font-size:.92rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:1.1rem 1.25rem;margin:0 0 1rem}
.hd{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;
margin-bottom:.8rem}
.cve{font:600 1.02rem/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.tag{font-size:.74rem;padding:.16rem .5rem;border-radius:999px;font-weight:600;
letter-spacing:.02em;text-transform:uppercase}
.t-same{background:var(--samebg);color:var(--same)}
.t-add{background:var(--addbg);color:var(--add)}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.88rem}
th,td{text-align:left;padding:.42rem .6rem;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:.78rem;text-transform:uppercase;
letter-spacing:.04em}
td.v{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.84rem}
.eq{color:var(--mut)}
.big{font:700 2rem/1 inherit;letter-spacing:-.02em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.8rem}
.note{color:var(--mut);font-size:.86rem;margin-top:.5rem}
.bar{height:8px;border-radius:99px;background:var(--samebg);overflow:hidden;margin-top:.4rem}
.bar>span{display:block;height:100%;background:var(--add)}
footer{margin:3rem 0 0;padding-top:1rem;border-top:1px solid var(--line);
color:var(--mut);font-size:.8rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}
"""

ATTRIB = ("This product uses the NVD API but is not endorsed or certified by the NVD. "
          "Generated locally by lab.py - no data left your machine.")


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def page(title, body):
    return ("<!doctype html><html><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><style>%s</style></head><body><div class=wrap>%s"
            "<footer>%s</footer></div></body></html>"
            % (esc(title), CSS, body, esc(ATTRIB)))


def write_html(name, html):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def write_compare_html(rows, args, diffs):
    lbl_l = SOURCES[args.left]["label"]
    lbl_r = SOURCES[args.right]["label"]
    b = ["<h1>Same query, two sources</h1>",
         "<p class=sub>%s &nbsp;vs&nbsp; %s &mdash; %d CVE(s), "
         "<strong>%d</strong> standard-field difference(s)</p>"
         % (esc(lbl_l), esc(lbl_r), len(rows), diffs)]

    if diffs == 0:
        b.append("<div class=card><div class=big>0</div>"
                 "<div>differences across every standard NVD field</div>"
                 "<p class=note>Identical <code>configurations</code>, "
                 "<code>metrics</code>, <code>weaknesses</code>, "
                 "<code>vulnStatus</code> and reference counts. A client reading "
                 "these fields cannot tell the two apart &mdash; which is the "
                 "entire compatibility claim.</p></div>")

    for r in rows:
        same = not r["differing"]
        tag = ("<span class='tag t-same'>identical</span>" if same
               else "<span class='tag t-add'>%d differ</span>" % len(r["differing"]))
        extra = ("<span class='tag t-add'>+%s</span>"
                 % esc(", ".join(r["extra_right"])) if r["extra_right"] else "")
        b.append("<div class=card><div class=hd><span class=cve>%s</span>"
                 "<span>%s %s</span></div>" % (esc(r["id"]), tag, extra))
        b.append("<div class=scroll><table><tr><th>field</th><th>%s</th>"
                 "<th>%s</th></tr>" % (esc(lbl_l), esc(lbl_r)))
        for k, (x, y) in r["fields"].items():
            cls = "" if x != y else " class=eq"
            b.append("<tr><td>%s</td><td class=v%s>%s</td><td class=v%s>%s</td></tr>"
                     % (esc(k), cls, esc(x), cls, esc(y)))
        b.append("</table></div>")
        if r["vc_cpes"]:
            b.append("<p class=note><strong>vcVulnerableCPEs:</strong> %d concrete "
                     "CPEs across %d distinct vendor:product pair(s), versus %d in "
                     "NVD's <code>configurations</code>. This is an additive field, "
                     "not an NVD one &mdash; reading it is a deliberate three-line "
                     "change, not something you get for free.</p>"
                     % (r["vc_cpes"], r["vc_products"], r["nvd_cpes"]))
        b.append("</div>")
    return write_html("compare.html", page("NVD Switch - compare", "".join(b)))


def write_scoreboard_html(stats):
    tot = {"n": 0, "nvd_zero": 0, "filled": 0, "nvd_cpes": 0, "vc_cpes": 0}
    for s in stats.values():
        for k in tot:
            tot[k] += s[k]
    pct = (100 * tot["filled"] / tot["nvd_zero"]) if tot["nvd_zero"] else 0

    b = ["<h1>CPE coverage, side by side</h1>",
         "<p class=sub>Bundled corpus of %d CVEs, compared field by field.</p>"
         % tot["n"],
         "<div class=grid>",
         "<div class=card><div class=big>%d%%</div><div>of these CVEs have "
         "<em>no</em> CPE in NVD</div><div class=bar><span style='width:%d%%'></span>"
         "</div></div>" % (100 * tot["nvd_zero"] / tot["n"] if tot["n"] else 0,
                           100 * tot["nvd_zero"] / tot["n"] if tot["n"] else 0),
         "<div class=card><div class=big>%d%%</div><div>of those gaps VulnCheck "
         "fills</div><div class=bar><span style='width:%d%%'></span></div></div>"
         % (pct, pct),
         "<div class=card><div class=big>%d</div><div>CPEs in NVD's "
         "<code>configurations</code></div></div>" % tot["nvd_cpes"],
         "<div class=card><div class=big>%d</div><div>CPEs in "
         "<code>vcVulnerableCPEs</code></div></div>" % tot["vc_cpes"],
         "</div>",
         "<h2>By bucket</h2><div class=card><div class=scroll><table>"
         "<tr><th>bucket</th><th>CVEs</th><th>NVD CPEs</th><th>VC CPEs</th>"
         "<th>NVD blank</th><th>VC fills the gap</th>"
         "<th>distinct products (NVD &rarr; VC)</th></tr>"]
    for name in ("recent", "kev", "anchor"):
        s = stats.get(name)
        if not s:
            continue
        b.append("<tr><td>%s</td><td>%d</td><td class=v>%d</td><td class=v>%d</td>"
                 "<td class=v>%d (%d%%)</td><td class=v>%s</td>"
                 "<td class=v>%d &rarr; %d</td></tr>"
                 % (esc(name), s["n"], s["nvd_cpes"], s["vc_cpes"],
                    s["nvd_zero"], 100 * s["nvd_zero"] / s["n"],
                    ("%d (%d%%)" % (s["filled"], 100 * s["filled"] / s["nvd_zero"]))
                    if s["nvd_zero"] else "&mdash;",
                    len(s["nvd_products"]), len(s["vc_products"])))
    b.append("</table></div>")
    b.append("<p class=note><strong>Read the last column, not the CPE counts.</strong> "
             "One CVE can enumerate hundreds of versions of a single package, so raw "
             "CPE totals overstate coverage. Distinct vendor:product pairs is the "
             "metric that matters if you are matching an inventory. The "
             "<code>kev</code> bucket is included on purpose: NVD enriches "
             "known-exploited CVEs well, and those rows show little or no "
             "difference.</p></div>")
    return write_html("scoreboard.html", page("NVD Switch - scoreboard", "".join(b)))


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("doctor", help="check your Python, data and key setup")

    q = sub.add_parser("query", help="run an NVD 2.0 query against any source")
    q.add_argument("--source", default="local-nvd", choices=sorted(SOURCES))
    q.add_argument("--cve", help="single CVE id, e.g. CVE-2024-3400")
    q.add_argument("--cve-ids", help="comma-separated ids, max 100")
    q.add_argument("--pub-start", help="e.g. 2026-09-01T00:00:00.000")
    q.add_argument("--pub-end", help="e.g. 2026-09-15T23:59:59.000")
    q.add_argument("--has-kev", action="store_true", help="only CISA KEV CVEs")
    q.add_argument("--status", help="vulnStatuses, e.g. 'Awaiting Analysis'")
    q.add_argument("--limit", type=int, default=20, help="resultsPerPage")
    q.add_argument("--raw", action="store_true", help="print raw JSON")
    q.add_argument("--raw-bytes", type=int, default=4000)

    c = sub.add_parser("compare", help="diff the same query across two sources")
    c.add_argument("--cve", help="single CVE id")
    c.add_argument("--cve-ids", help="comma-separated ids, max 100")
    c.add_argument("--left", default="local-nvd", choices=sorted(SOURCES))
    c.add_argument("--right", default="local-vc", choices=sorted(SOURCES))
    c.add_argument("--open", action="store_true", help="open the report in a browser")

    s = sub.add_parser("scoreboard", help="CPE coverage across the whole corpus")
    s.add_argument("--open", action="store_true")

    v = sub.add_parser("verify-cpe", help="check a CPE against the CPE dictionary")
    v.add_argument("cpe")
    v.add_argument("--source", default="nist",
                   choices=["nist", "vulncheck"])

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 0
    if args.cmd == "compare" and not (args.cve or args.cve_ids):
        raise LabError("compare needs --cve or --cve-ids")

    return {
        "doctor": cmd_doctor, "query": cmd_query, "compare": cmd_compare,
        "scoreboard": cmd_scoreboard, "verify-cpe": cmd_verify_cpe,
    }[args.cmd](args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LabError as e:
        print("\n%s\n" % e, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
