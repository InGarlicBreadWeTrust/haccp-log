# Privacy

`haccp-log` handles **no network** and collects **no data** of its own. This page
states exactly what the tool does — and does not — with the data it touches.

## In one line
It reads and writes locally on your disk only, and it phones home to no one.

## What the tool does NOT do
- **No telemetry, no analytics, no crash reporting, no usage tracking.** Nothing
   in the code measures or reports what you do.
- **No network of any kind.** No sockets, no HTTP/HTTPS, no background sync;
   `pyproject.toml` declares zero runtime dependencies and no socket is opened.
- **It never uploads your data.** A log file cannot leave your machine — the tool
   has no network capability.

## What the tool DOES touch
Only the files you give it:
- the log it builds/appends from the measurements you enter, and
- a human-readable report/markdown only if you explicitly ask for one, written to a
  path you choose.
Nothing is transformed, aggregated, or retained for any purpose beyond the run.
The tool does not remember between runs or index your data.

## Data sensitivity here is medium — but *integrity*, not confidentiality, is the point
A HACCP log is itself a record of food-safety events (temperatures, hold times,
monitoring, corrective actions) that may name the person on duty. The headline
property of this tool is that it is **tamper-evident** via its SHA-256 hash chain,
so a record cannot be quietly altered. That protects integrity; it does not *hide*
the contents.

## Your controls
- Store logs on an **encrypted volume** and `chmod 600` the log file if it
   contains identifiable staff or incident detail (integrity ≠ confidentiality).
- Treat **reports as sensitive** and keep them under access control (do not commit
   to a public repository).
- Protect the **write path**: an attacker who overwrites the whole log from a stale
   copy also resets the chain — keep a trusted periodic copy and always verify the
   chain before relying on a log.
- Retention is yours: delete the file and the data is gone; the tool keeps no copy,
   backup, or cache.

## Data sharing
None. The tool contacts no third party, has no accounts or API keys, and retains no
data itself — your log lives only in the file you create on your own machine.

---

## Independent privacy audit (2026-10-21)

**Performed by:** `InGarlicBreadWeTrust` · **Type:** static source + dependency
review · **Result:** no privacy leakage; posture strong.

- No telemetry / analytics / crash reporting / background sync (no network, no
   external service).
- No network I/O anywhere; zero runtime dependencies.
- No data leaves the machine; the log file is created only by an explicit append to
   a user-named path.
- Integrity is enforced by a SHA-256 hash chain from a documented
   `GENESIS = "0"*64`, verified on every chain-walk.

**Recommendation (not a vulnerability):** store logs on an **encrypted volume** and
   restrict permissions, and note that the chain is tamper-*evident*, not
   confidential. No code change required.
