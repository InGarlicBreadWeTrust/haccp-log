# Security posture of `haccp-log`

`haccp-log` is an **offline** food-safety / HACCP log. Its headline security
property is **integrity**: every record is joined to the previous one by a
SHA-256 hash, so the log is tamper-evident. It is otherwise a pure-stdlib, no-
network tool. This page is the threat model plus how that integrity guarantee
holds.

## Threat model

| Input / asset | Trusted? | Why it is safe |
| --- | --- | --- |
| Log records on disk | No (tamper-detectable) | Each record is hashed against its predecessor; any change after the fact breaks the chain and is detected on load. |
| `--input` / `--output` paths | Yes | Resolved on the local disk; never executed, never sent anywhere. |
| Measurement values (temps, times) | No risk | Numbers compared in fixed-point (no floats) against the danger zone; can't cause code execution or a numeric footgun. |

## Design principles

1. **Tamper-evident chain.** Starting from `GENESIS = "0" * 64`, each record's
   SHA-256 digest includes its predecessor's digest, so an attacker cannot
   insert, delete, or alter a record without breaking every chain link after it.
   Verification recomputes the chain and fails on the first broken link.
2. **No code execution.** No `eval`, `exec`, `compile`, `subprocess`,
   `os.system`, `pickle`, `marshal`, or `ctypes`. A log file is data, hashed and
   compared as a string — never run.
3. **No network, no telemetry.** No sockets, no HTTP, no third-party runtime
   dependencies. A tampered or spoofed record cannot be pushed anywhere because
   the tool has no network capability.
4. **Deterministic, exact math.** Time-temperature comparison uses fixed-int
   seconds, not floats, so the `> 7200 s` danger-zone boundary is exact and cannot
   drift by a rounding error.
5. **No hardcoded secrets.** No credentials or API keys in the source.

## Recommendations for this tool specifically

- Integrity ≠ confidentiality. The hash chain proves a record wasn't changed; it
  does not *hide* the records. Store the log on an **encrypted volume**, and
  restrict the file to `chmod 600` if it contains identifiable staff or incident
  detail.
- Protect your write path: an attacker who can *recreate* the whole log from a
  point in the past (a full overwrite) also resets the chain. Keep periodic
  trusted copies and verify the chain before relying on a log in any
  investigation or audit.

## Reporting a vulnerability

Open an issue labelled `security`. Provide the version (`python -m haccp --version`),
the file or command that triggered it, and a redacted example.

---

## Independent security audit (2026-10-21)

**Performed by:** `InGarlicBreadWeTrust` · **Type:** static source + dependency
review · **Result:** no vulnerabilities found.

**Method:** static review of every `.py` source, the `pyproject.toml` build
config, and the dependency graph; grep for the runtime-risk surface
(`subprocess`, `os.system`, `eval`/`exec`/`compile`, `pickle`/`marshal`,
`ctypes`, sockets/network).

**Findings for `haccp-log`:**
- No `subprocess`, `os.system`, `exec`, `eval`, `compile`, `pickle`, `marshal`,
  or `ctypes` present.
- No network I/O (no sockets, no HTTP, no telemetry); zero runtime dependencies.
- No hardcoded secrets or credentials.
- No build-time backdoor: stock `setuptools` build-meta, no custom hooks.
- Integrity is enforced by a **SHA-256 hash chain** seeded from a documented
  `GENESIS = "0"*64` and verified on every chain-walk; the danger-zone test is
  **strict** (`low < c < high`, fixed-int, no float drift).

**Verdict:** strong posture. No vulnerability found; the standing
recommendation is to protect the write path (trusted periodic copies) and to
note that the chain is tamper-*evident*, not confidential (use disk encryption).
No code changes required.
