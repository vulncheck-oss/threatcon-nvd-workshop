#!/usr/bin/env python3
"""A deliberately small NVD client - the thing you are going to switch.

This stands in for whatever consumes NVD in your environment: an ingestion
job, a scanner enrichment step, a triage script. It is small because the
point of the exercise is that the size of the change does not depend on the
size of your tool.

Run it as-is (queries NIST NVD):
    python3 mytool.py CVE-2024-3400

Exercise 3 - repoint it with --url. No file edit required:
    python3 mytool.py CVE-2024-3400 --url https://api.vulncheck.com/rest/json/cves/2.0

Exercise 4 - read the extra field. Uncomment the marked block at the bottom,
then run against the VulnCheck endpoint (--url, as in Exercise 3) - the field
only comes back from there, so the NIST-pointed command still prints 0.

Get a free API key at https://vulncheck.com/community

This product uses the NVD API but is not endorsed or certified by the NVD.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VC_URL   = "https://api.vulncheck.com/rest/json/cves/2.0"

API_KEY = os.environ.get("VC_API_KEY", "")


def get_cve(cve_id, base_url):
    url = base_url + "?" + urllib.parse.urlencode({"cveId": cve_id})
    req = urllib.request.Request(url)
    # Only attach the key when the target is not NIST. VC_API_KEY is a
    # VulnCheck key - NIST does not recognize it, and sending it anyway
    # turns the baseline NIST call into an error instead of a clean miss.
    if API_KEY and base_url != NIST_URL:
        # Same header name NVD uses. This is why the switch is not a rewrite.
        req.add_header("apiKey", API_KEY)
    print("→ GET %s" % url)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            body = r.read()
            elapsed = time.time() - t0
            print("← %d in %.2fs  (%d bytes)" % (r.status, elapsed, len(body)))
            return json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as e:
        print("← %d  (%s)" % (e.code, e.reason))
        print("\nRequest failed: %s" % e)
        sys.exit(1)
    except urllib.error.URLError as e:
        print("\nRequest failed: %s" % e.reason)
        sys.exit(1)


def cpes_from_configurations(cve):
    """Read CPEs the standard NVD way."""
    found = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                found.append(match["criteria"])
    return found


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cve_id", nargs="?", default="CVE-2024-3400",
                    help="CVE to look up (default: CVE-2024-3400)")
    ap.add_argument("--url", default=NIST_URL, metavar="URL",
                    help="API base URL (default: NIST NVD)")
    args = ap.parse_args()

    data = get_cve(args.cve_id, args.url)

    print()
    print("--- response ---")
    print("endpoint     : %s" % args.url)
    print("totalResults : %s" % data.get("totalResults"))
    print("format       : %s %s" % (data.get("format"), data.get("version")))

    records = data.get("vulnerabilities") or []
    if not records:
        print("\nno record for %s" % args.cve_id)
        return

    cve = records[0]["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    print("\n%s  [%s]" % (cve["id"], cve.get("vulnStatus")))
    print("%s" % desc[:160])

    cpes = cpes_from_configurations(cve)
    print("\nCPEs from configurations: %d" % len(cpes))
    for c in cpes[:5]:
        print("  %s" % c)
    if len(cpes) > 5:
        print("  ... and %d more" % (len(cpes) - 5))

    # ------------------------------------------------------------ EXERCISE 4
    # Uncomment these three lines. They read an additive field that only the
    # VulnCheck endpoint returns. Note what happens on a recent CVE where the
    # block above printed zero.
    #
    # extra = cve.get("vcVulnerableCPEs") or []
    # print("\nCPEs from vcVulnerableCPEs: %d" % len(extra))
    # for c in extra[:5]:
    #     print("  %s" % c)
    # -----------------------------------------------------------------------


if __name__ == "__main__":
    main()
