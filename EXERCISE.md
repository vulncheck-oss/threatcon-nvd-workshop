# NVD Switch Lab

A hands-on look at what it takes to move a tool off the NIST NVD API — and what you gain when you do.

Everything here runs on the Python standard library. No `pip install`, no server.
The bundled data means Exercise 1 works even if the conference wifi fails.
Exercise 2 needs network (no key). Exercises 3–6 need network plus a free API
key — see the section below before starting.

**Time:** about 60 minutes (Exercise 1 is fully offline; Exercise 2 needs network only; Exercises 3–6 need network plus a free API key). **You need:** Python 3.8 or newer.

---

## Context — status codes and what they mean for CPE

NVD's enrichment status is worth keeping in front of you during the exercises. The `vulnStatus` field is in every record:

| NVD status | What it means | CPE present? |
|---|---|---|
| Analyzed | NVD reviewed and enriched | Yes |
| Modified | Updated after initial analysis | Usually yes |
| Awaiting Analysis | In the queue | Not yet |
| Deferred | NVD explicitly chose not to analyze | No |
| Received | Acknowledged, not even queued | No |
| Rejected | Withdrawn | No (correct) |

**Deferred is not a backlog problem.** CVEs in Deferred status will not receive NVD CPE enrichment unless the policy changes. The exercises let you see this in real data — Exercise 1 has a query for it.

**The enrichment fields in the compat endpoint — how they differ.**

The VulnCheck-compatible endpoint returns three CPE fields in the same response. Understanding what each one is before you start saves confusion in Exercise 4:

| Field | Structure | Notes |
|---|---|---|
| `configurations` | Structured match statements (nodes, `cpeMatch`, version ranges) | NVD's native field — unchanged from NIST |
| `vcConfigurations` | Same structure as `configurations` | Same format, different source; scanners that read `configurations` can read this with no code change |
| `vcVulnerableCPEs` | Flat list of CPE strings | Simpler to parse; does not carry version-range logic |

Neither source covers every CVE — no structured CPE data exists yet for a meaningful share of 2026 records regardless of which endpoint you use. Exercise 4 makes that concrete.

---

## Before you start — get a free API key

Exercises 3–6 require a VulnCheck community key. Getting one takes about
90 seconds. Do this now so the key is ready when you need it.

1. Go to **https://vulncheck.com/community** and create an account.
2. In the dashboard, go to **API Tokens** and generate a token.
3. Set it in your terminal:

```
export VC_API_KEY=your-token-here      # macOS / Linux
set VC_API_KEY=your-token-here         # Windows Command Prompt
$env:VC_API_KEY="your-token-here"      # Windows PowerShell
```

Verify it works:

```
curl -s "https://api.vulncheck.com/rest/json/cves/2.0?cveId=CVE-2024-3400" \
  -H "apiKey: $VC_API_KEY" | python3 -m json.tool | head -8
```

If you see JSON, you are ready. If you see a 401, check that the variable is set in the same terminal you are running the lab in.

> **Windows note:** curl commands in this lab use `$VC_API_KEY` (bash syntax).
> In Command Prompt use `%VC_API_KEY%`; in PowerShell use `$env:VC_API_KEY`, or
> just use the `python3` equivalents — they work on all three.

> **No account yet?** Exercises 1 and 2 need no key (Exercise 2 still needs
> network) — start there and sign up while those are running.

---

## Setup

**Step 1 — extract `threatcon-nvd-workshop.zip`.** Zip extraction is built into every major
platform — no extra software needed on macOS or Windows:

- **macOS:** double-click the zip in Finder (built-in Archive Utility), or in Terminal:
  `unzip threatcon-nvd-workshop.zip`
- **Windows 10/11:** right-click the zip → **Extract All** (built in, no extra software).
- **Linux:** `unzip threatcon-nvd-workshop.zip` in a terminal — most distros ship `unzip`
  already; if the command isn't found, `sudo apt install unzip` (or your distro's equivalent).
  Most desktop file managers also extract a zip on double-click.

Open a terminal in the extracted folder for the rest of this guide.

**Reading this file.** No operating system renders `.md` files as formatted text out of the
box — opening `EXERCISE.md` directly shows the raw markdown source. If you have VS Code, open
it there and press `Cmd/Ctrl+Shift+V` for a rendered preview. Otherwise, any plain text editor
or terminal (`cat EXERCISE.md` / `less EXERCISE.md`) works fine — this guide is written to stay
readable even unrendered.

**Step 2 — check Python is installed and new enough.** This lab needs 3.8 or newer:

```
python3 --version          # macOS / Linux
py -3 --version            # Windows
```

You want to see `Python 3.8.0` or higher.

- **Command not found** (`command not found` on macOS/Linux, `'python3' is not recognized` on
  Windows) — Python isn't installed. macOS: `brew install python3`. Windows: install from
  [python.org](https://python.org) and check "Add Python to PATH" during setup. Linux:
  `sudo apt install python3` (or your distro's equivalent).
- **Version below 3.8** — use the same install command above; it installs the current version.

**Step 3 — run the lab's own check.** This goes further than Step 2 — it also checks the
standard-library modules the lab needs, that the bundled database is present, and whether
`VC_API_KEY` is already set:

```
python3 lab.py doctor
```

- **macOS/Linux:** the bundle also includes a launcher — `./run.sh` (the leading `./` is
  required; a bare `run.sh` will not be found).
- **Windows:** double-click `run.cmd`, or use `py -3 lab.py doctor`. `run.cmd` is Windows-only —
  do not try to run it on macOS or Linux.

You want every line to read `[ok]`.

---

## Exercise 1 — Build a query (offline, no key)

The bundled corpus is 260 real CVEs captured from NVD, stored as NVD 2.0
records. Query it the same way you would query the live API.

**By CVE id** — API parameter: `cveId`:

```
python3 lab.py query --cve CVE-2024-3400
```

Look at the envelope: `format`, `version`, `totalResults`, `resultsPerPage`, `startIndex`. Every
NVD 2.0 response has these, and pagination is built on them. `cveId` is a standard NVD 2.0
parameter — it works identically whether you query NIST or the compat endpoint.

**By list of ids** — API parameter: `cveIds` (comma-separated, up to 100 per request):

```
python3 lab.py query --cve-ids CVE-2021-44228,CVE-2023-4966,CVE-2026-48932
```

This is the batch form — one request for many CVEs instead of one request per CVE. It matters
beyond this exercise: Exercise 3's `compare --cve-ids ...` reuses this exact shape to check
multiple CVEs against the switched endpoint at once. Note `cveIds` is a VulnCheck compat-API
extension, not a NIST parameter — NIST's real API only accepts one `cveId` per request, so this
query shape works here and against the live VulnCheck endpoint, not against `--source nist`.

**By publication window** — API parameters: `pubStartDate` / `pubEndDate`:

```
python3 lab.py query --pub-start 2026-09-01T00:00:00.000 --pub-end 2026-09-15T23:59:59.000 --limit 10
```

This is how a real ingestion job stays current — pull what published in a window instead of
re-querying the whole corpus every time. Compare `totalResults` here against the first query's
`totalResults`: this window is the slice a production sync job would actually pull on a given
run. `pubStartDate`/`pubEndDate` are standard NVD 2.0 parameters, same format NIST expects — this
one also works identically against `--source nist`.

**By status** — API parameter: `vulnStatuses` (comma-separated):

```
python3 lab.py query --status "Awaiting Analysis" --limit 10
python3 lab.py query --status Deferred --limit 10
```

Look at the `CPEs` column for those two queries. How many Deferred records have anything in it?
That is what the status means in practice. `vulnStatuses` is a VulnCheck compat-API extension —
NIST's real API has no status filter, so this shape also only works here and against the live
VulnCheck endpoint.

Add `--raw` to any query to see the untouched JSON.

> **What Exercise 1 shows.** By id, by batch, by date range, by status — these four query
> shapes are what every real NVD integration already uses. Two (`cveId`, `pubStartDate`/
> `pubEndDate`) are standard NVD parameters portable to any NVD-speaking client; two (`cveIds`,
> `vulnStatuses`) are VulnCheck compat-API conveniences layered on top. Exercise 3 does not
> introduce new syntax; it points these same calls at a different host.

---

## Exercise 2 — Same code, live NVD (needs network, no key)

Point the lab at the real NIST API:

```
python3 lab.py query --source nist --cve CVE-2024-3400
```

Only `--source` changed — same command, now hitting the live NIST API over the network instead
of the bundled corpus. Same shape comes back.

Or with curl (no key needed):

```
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400" \
  | python3 -m json.tool | head -15
```

Same CVE, zero authentication — NIST's API is open to anyone.

Confirm the bundled snapshot is faithful:

```
python3 lab.py compare --cve CVE-2024-3400 --left local-nvd --right nist
```

Expect `standard NVD field differences: 0`. The local corpus is a real NVD snapshot — not a mock.

> **What Exercise 2 shows.** The bundled corpus is not a fixture — it is a verified snapshot of
> the real NVD API. That is what makes Exercise 3's host switch a legitimate test of production
> behavior, not a staged demo.

---

## Exercise 3 — The switch (needs network + API key)

Run `mytool.py` as shipped — it queries NIST NVD:

```
python3 mytool.py CVE-2024-3400
```

Now switch the endpoint:

```
python3 mytool.py CVE-2024-3400 --url https://api.vulncheck.com/rest/json/cves/2.0
```

**What changed in the command:** the hostname. The path is identical
(`/rest/json/cves/2.0`), the header name is identical (`apiKey`), the response
schema is identical. Your parser does not know.

See it with curl — run both and compare:

```
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400" \
  | python3 -m json.tool | head -10

curl -s "https://api.vulncheck.com/rest/json/cves/2.0?cveId=CVE-2024-3400" \
  -H "apiKey: $VC_API_KEY" | python3 -m json.tool | head -10
```

Same fields, same values — only the JSON key order differs (non-normative per
RFC 8259; any typed deserializer ignores it).

**Both auth header formats work.** VulnCheck accepts NVD's `apiKey` header verbatim. `Authorization: Bearer` also works — no header change required:

```
curl -s -o /dev/null -w "apiKey header:  %{http_code}\n" \
  "https://api.vulncheck.com/rest/json/cves/2.0?cveId=CVE-2024-3400" \
  -H "apiKey: $VC_API_KEY"

curl -s -o /dev/null -w "Bearer header:  %{http_code}\n" \
  "https://api.vulncheck.com/rest/json/cves/2.0?cveId=CVE-2024-3400" \
  -H "Authorization: Bearer $VC_API_KEY"
```

Expected: both return `200`.

Prove it across the corpus:

```
python3 lab.py compare --cve-ids CVE-2021-44228,CVE-2024-3400,CVE-2023-4966 --right vulncheck --open
```

> **Worth noting.** Compatibility buys you exactly compatibility. Every standard NVD field comes back the same — which is the point, because it means the migration is not a project. It also means you are not automatically getting more data. That is Exercise 4.
>
> There is a second reason the switch matters beyond compatibility: reliability, measured. NVD has no public SLA; a 2026 federal audit found its enrichment backlog grew from 13,000 to over 27,000 unprocessed vulnerabilities between February 2024 and the end of 2025, on top of five NIST-documented service disruptions in 2024 alone — including a six-day processing halt in May. VulnCheck commits to 99.9% monthly availability and has measured 99.98% over the last 90 days on real production API traffic, published live at status.vulncheck.com.

---

## Exercise 4 — Who adds what (needs network + API key)

This is the core exercise. Run your tool against a recent CVE that NVD has not analyzed:

```
python3 mytool.py CVE-2026-48932
```

`CPEs from configurations: 0`. NVD's field is empty — Deferred or Awaiting Analysis.

Now open `mytool.py`, find the block marked `EXERCISE 4`, and uncomment the three lines:

```python
extra = cve.get("vcVulnerableCPEs") or []
print("\nCPEs from vcVulnerableCPEs: %d" % len(extra))
for c in extra[:5]:
    print("  %s" % c)
```

`vcVulnerableCPEs` only exists in the VulnCheck response — run the plain command again
and the new block still prints 0, because the request is still going to NIST. Point it
at the compat endpoint the same way you did in Exercise 3:

```
python3 mytool.py CVE-2026-48932 --url https://api.vulncheck.com/rest/json/cves/2.0
```

Now you see CPE strings in `vcVulnerableCPEs` that are absent from `configurations`.

Now add the second field — `vcConfigurations` — and compare what you get. Open `mytool.py` and add:

```python
vc_cfgs = cve.get("vcConfigurations") or []
print("\nvcConfigurations nodes: %d" % len(vc_cfgs))
if vc_cfgs:
    import json
    print(json.dumps(vc_cfgs[0], indent=2))
```

**The difference between the two fields:**

`vcVulnerableCPEs` gives you a flat list of CPE strings — straightforward to parse, but you lose version-range logic. A tool that reads it gets a list of affected CPEs but has to do its own version reasoning.

`vcConfigurations` gives you the full match-statement structure — the same format NVD uses in `configurations`. It contains `nodes`, `cpeMatch` arrays with `versionStartIncluding`/`versionEndExcluding`, and logical operators. A tool that already reads `configurations` can read `vcConfigurations` with zero code changes and get the version-range logic for free.

Both come back in the same response. Neither requires a second API call.

See the gap across the whole corpus:

```
python3 lab.py scoreboard --open
```

> **Read the distinct-products column, not the CPE counts.** One CVE can enumerate hundreds of versions of a single package — raw CPE totals overstate coverage. Distinct `vendor:product` pairs is the number that matters for inventory matching.
>
> Note the `kev` bucket: for known-exploited CVEs, NVD coverage is excellent and the two sources look nearly identical. That bucket is in the corpus on purpose — not every CVE is poorly enriched.

---

## Exercise 5 — Cursor-based pagination (needs network + API key)

NVD only has offset pagination: `startIndex=0`, `startIndex=100`, and so on. For a full sync of 394,000+ CVEs, deep offsets are slow — the database skips every record before your position on every request.

VulnCheck added cursor-based pagination. It is backward-compatible: `startIndex` still works exactly as before.

**Seed the cursor from page 1, then chain it:**

```python
python3 -c "
import urllib.request, json, base64, os

token = os.environ['VC_API_KEY']
base = 'https://api.vulncheck.com/rest/json/cves/2.0'

# Page 1 — get the last record's position
with urllib.request.urlopen(
    urllib.request.Request(f'{base}?resultsPerPage=5', headers={'apiKey': token})
) as r:
    page1 = json.loads(r.read())

last = page1['vulnerabilities'][-1]['cve']
cursor = base64.urlsafe_b64encode(
    json.dumps([last['lastModified'], last['id']]).encode()
).rstrip(b'=').decode()

print('Page 1 last:', last['id'], '—', last['lastModified'])
print('Cursor:     ', cursor)
print()

# Page 2 — pass cursor directly, no arithmetic
with urllib.request.urlopen(
    urllib.request.Request(f'{base}?resultsPerPage=5&cursor={cursor}', headers={'apiKey': token})
) as r:
    page2 = json.loads(r.read())

print('nextCursor:', page2.get('nextCursor'))
print()
for v in page2['vulnerabilities']:
    print(' ', v['cve']['id'], '—', v['cve']['lastModified'])
"
```

The response includes `nextCursor` — pass it directly as `cursor=` on the next request. No state to track beyond the token itself.

**Why it matters:** a sync tool that resumes from `startIndex=350000` must skip 350,000 records on every call. Cursor resumes from a stable position at constant cost regardless of depth.

---

## Exercise 6 — Rate limits and speed (needs network; the VulnCheck half needs an API key)

**Run this exercise last.** It deliberately trips NVD's rate limit.

**NVD unauthenticated:** 5 requests per 30-second window:

```python
python3 -c "
import urllib.request, urllib.error, time

cves = ['CVE-2024-3400','CVE-2021-44228','CVE-2023-4966',
        'CVE-2024-23897','CVE-2026-48932','CVE-2023-38408']
base = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

for i, cve_id in enumerate(cves, 1):
    try:
        t = time.time()
        with urllib.request.urlopen(f'{base}?cveId={cve_id}', timeout=10) as r:
            r.read()
        print(f'  req {i}: 200  ({time.time()-t:.2f}s)')
    except urllib.error.HTTPError as e:
        print(f'  req {i}: {e.code}  — rate limited')
        break
"
```

Request 6 returns 429. With an NVD API key the limit rises to 50 per 30 seconds — enough for lookup workloads, not for a nightly full sync.

**VulnCheck:** 1,000 requests per minute on the community tier:

```python
python3 -c "
import urllib.request, time, os

token = os.environ['VC_API_KEY']
cves = ['CVE-2024-3400','CVE-2021-44228','CVE-2023-4966','CVE-2024-23897',
        'CVE-2026-48932','CVE-2023-38408','CVE-2023-20273','CVE-2024-1709',
        'CVE-2024-6387','CVE-2023-41993']
base = 'https://api.vulncheck.com/rest/json/cves/2.0'

for i, cve_id in enumerate(cves, 1):
    t = time.time()
    req = urllib.request.Request(f'{base}?cveId={cve_id}', headers={'apiKey': token})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()
    print(f'  req {i}: 200  ({time.time()-t:.2f}s)')

print()
print('All succeeded. Community tier: 1,000 req/min.')
"
```

All 10 succeed. The ceiling is where most production sync jobs never come close.

> **In context.** NVD was designed to serve the research community, not production pipelines. The rate limit reflects that — it is not an oversight.

---

## Appendix — Verify a CPE before you trust it

A CPE that is not in the official dictionary still tells you what is affected,
but it will not match an inventory keyed on NVD's dictionary. Check:

```
python3 lab.py verify-cpe "cpe:2.3:o:paloaltonetworks:pan-os:10.2.0:*:*:*:*:*:*:*"
```

Then take a CPE from `vcVulnerableCPEs` in Exercise 4 and check that one. Look at the `deprecated` flag too.

Know whether a CPE is dictionary-backed before you wire it into asset matching — regardless of which source produced it.

---

## Where to go next

| Want to | Do this |
|---|---|
| Free API key | https://vulncheck.com/community |
| Query offline | `python3 lab.py query --source local-nvd ...` — no network at all |
| See every option | `python3 lab.py --help`, or `python3 lab.py query --help` |
| Try cursor pagination | Exercise 5 — chains pages without offset arithmetic |
| See the rate-limit gap | Exercise 6 — do last, it trips NVD's limit on purpose |
| Check CPE dictionary coverage | Appendix — verify-cpe against any CPE string |

The community tier is a point-lookup tier: look up a CVE by id, use the NVD-compatible endpoints, download full index backups. Cross-index search by vendor, product, or version is a commercial capability.

Questions during the conference: find us at the VulnCheck open office hours.

---

*This product uses the NVD API but is not endorsed or certified by the NVD.*
