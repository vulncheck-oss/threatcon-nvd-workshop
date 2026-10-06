# NVD Switch Lab

A hands-on look at what it takes to move a tool off the National Vulnerability
Database (NVD) API — and what you gain when you do. Built for VulnCheck's
ThreatCon 1 workshop (October 2026).

## Quick start

1. Clone this repo.
2. Open a terminal in the cloned folder.
3. Run the setup check:
   - macOS/Linux: `./run.sh`
   - Windows: double-click `run.cmd`
4. Follow `EXERCISE.md` for the full set of exercises.

Needs Python 3.8 or newer, standard library only — no `pip install`, no server.
A free VulnCheck API key (https://vulncheck.com/community) unlocks the live
exercises; the first two work offline.

## What's here

- `EXERCISE.md` — the full guide
- `lab.py` — query / compare / scoreboard tool over a bundled 260-CVE corpus
- `mytool.py` — a minimal NVD client you repoint from NIST to VulnCheck
- `data/corpus.sqlite` — bundled NVD + VulnCheck snapshot for offline exercises

## License

Apache-2.0 — see `LICENSE`.

---

*This product uses the NVD API but is not endorsed or certified by the NVD.*
