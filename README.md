# TRACE — Transparent Reconnaissance & Attack Correlation Engine

> ⚠️ **Authorized use only.** TRACE sends real test payloads at the target — it
> is not a passive scanner. Run it **only** against systems you own or have
> explicit written authorization to test. See [Responsible use](#responsible-use).

TRACE is an explainable attack-surface triage engine. Instead of running one
fixed checklist against every target, it **activates modules based on what it
discovers mid-scan**: a WordPress site unlocks one set of modules, a pure JSON
API unlocks another, a SPA unlocks a third (crawled with a real headless
Chromium via Playwright). Every scan's decision graph is exportable
(`--export-graph`) and shows exactly which module triggered which, and why —
no part of the correlation is a black box.

The engine is deliberately **deterministic and explainable**: no LLM deciding
what counts as a vulnerability, no opaque scoring. Every decision is traceable
back to the fact that produced it.

## The differentiator: confirmation by real effect, not by signature

Most scanners declare a finding from a *response pattern* — a status code, a
keyword in the body, a header being present — which is where their false-positive
rate comes from. TRACE requires an **observable effect** before it declares
anything critical. Concrete, not hypothetical:

- **Write IDOR** — a `200` on the write is not enough. The module then tries to
  **log in as the victim** using the password it just set. A successful login is
  the proof; the `200` alone never is.
- **Weak JWT secret** — recomputes HMAC-SHA256 locally against a short wordlist
  and compares it **byte-for-byte** against the token's real signature. It does
  not infer anything from the header's `alg`.
- **SSRF** — confirmed via an out-of-band callback with a unique per-test token,
  so it holds even for *blind* SSRF where the response never reveals what was
  fetched.
- **Known-vulnerable component (CVE)** — cross-references the detected version
  against the NVD, with version-range parsing and a fallback to deprecated /
  wildcard CPEs. It is not a static table of ten products.
- **Auditable causal chain** — each scan can write an audit trail to partitioned
  Parquet with SHA-256 hashing (optional `audit` extra), so you can prove after
  the fact exactly what ran and when.

## Coverage

**80 modules** across **11 packs** (`trace --list-packs`), covering
**A01, A02, A03, A05, A06, A07 and A10** of the OWASP Top 10 (2021).

It deliberately does **not** claim coverage of A04 (Insecure Design), A08
(Software & Data Integrity) or A09 (Logging & Monitoring Failures) — those
require business context an external scanner cannot assess on its own. Claiming
otherwise would be the exact kind of false positive TRACE is built to avoid.

| Pack | OWASP | What it does |
|---|---|---|
| `recon` | — | Surface recon and initial target classification |
| `wordpress` | A06 | WordPress scanner: plugin/theme detection, exposure, CVE matching |
| `sqli` | A03 | SQL injection triage (crawler + SQL heuristics + correlation) |
| `injection` | A03 | Full injection family: SQLi, reflected XSS, SSTI, LDAP, command injection |
| `bac` | A01 | Broken Access Control / IDOR (authenticated crawler, OpenAPI provisioning, correlation) |
| `authentication` | A07 | Authentication and token-validation flaws (e.g. JWT) |
| `crypto` | A02 | Cryptographic failures and weak transport/secret protection |
| `misconfig` | A05 | Insecure configuration and missing defensive HTTP controls |
| `ssrf` | A10 | Server-Side Request Forgery detection and related surfaces |
| `privilege` | A01 | Vertical privilege-escalation probing |
| `vulnerability` | A06 | Correlates detected components/versions against public vulnerability data (NVD) |

**77 automated tests** across 7 files. Much of the engine has been validated
against real targets (VAmPI, DVWA), with a purpose-built vulnerable target
written on the spot whenever reproducing a specific bug before fixing it was
cleaner than hunting for one in the wild.

## How it works

TRACE runs as a fact-driven wave scheduler, not a linear script:

1. Each module declares, via a `@discovery_module` decorator, what facts it
   **requires** to run and what facts it **produces** — so the engine, not a
   hardcoded order, decides eligibility.
2. **Wave 0** runs only root modules (always eligible). Each finding emits facts
   (`cms.wordpress.detected = True`, `tech.elementor.version = ...`) into a
   `KnowledgeStore`.
3. New facts make new modules eligible; the next wave runs those. This repeats
   until no new module becomes eligible and the scan stabilizes.
4. The full chain — which fact unlocked which module, with what confidence — is
   recorded and can be exported as a standalone HTML decision graph.

State lives in SQLite (`~/.trace/trace.db` by default), so an interrupted scan
**resumes** where it left off, and findings carry a lifecycle across runs
(new / seen again / reopened / closed).

## Installation

```bash
git clone https://github.com/trace-for-hackers/TRACE/
cd trace
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

This installs the core (recon, classic injection, BAC/IDOR, misconfiguration,
vulnerable components, SSRF, authentication flaws) and exposes the `trace`
command on your PATH. Requires Python **3.11+**.

### Optional extras

Each extra maps to a feature with **graceful degradation** already implemented:
without it, TRACE still runs — it just skips that one feature, with a clear
warning, instead of crashing the whole scan.

```bash
pip install -e ".[report]"        # client-facing PDF report (--client-report)
pip install -e ".[audit]"         # session recorded to Parquet with SHA-256 hashing
pip install -e ".[observability]" # traces/metrics via OpenTelemetry (see Observability stack below)
pip install -e ".[js-crawler]"    # SPA discovery (Angular/React/Vue)
pip install -e ".[tls]"           # TLS certificate parsing
pip install -e ".[all]"           # everything at once
```

`js-crawler` needs one extra step, once, after install:

```bash
python3 -m playwright install chromium
```

## Usage

```bash
trace https://target.com                                   # full scan
trace https://target.com --pack wordpress                  # WordPress pack only
trace --list-packs                                         # list available packs
trace https://target.com --report report.html              # interactive technical report
trace https://target.com --export-graph graph.html         # standalone scan decision graph
trace https://target.com \
      --client-report out/ --client-name "Acme Ltd"        # client-facing PDF report
```

Run `trace --help` for the full flag list. A few worth knowing:

- `--identity` / `--identity-header` — register a session cookie or auth header
  per identity, which is what unlocks the BAC/IDOR modules.
- `--openapi-spec` — point TRACE at an OpenAPI spec (local or URL) to drive
  authenticated API resource provisioning for access-control testing.
- `--callback-host` — an address the **target** can reach back to; enables
  out-of-band SSRF confirmation (including blind SSRF).
- `--cookie` — a session cookie for a shared anonymous session (e.g. reaching
  login-gated pages during crawling).
- `--confirm-intrusive` — **off by default.** Intrusive modules (SQLi, XSS,
  SSTI, LDAP, command injection) stay disabled until you explicitly confirm you
  are authorized to send active payloads.
- `--targets file.txt` — queue multiple targets, one URL per line.

## Reporting

TRACE produces three report tiers:

- **Technical HTML** (`--report`) — severity chart, findings table, console log,
  and the decision chain, for someone fixing the issues.
- **Standalone decision graph** (`--export-graph`) — the fact/module graph as a
  self-contained HTML page, for understanding *why* a finding was reached.
- **Client report** (`--client-report`) — a PDF + Markdown + JSON deliverable in
  business language, with an OWASP/CWE taxonomy, severity ordering, a
  "how TRACE confirmed this" evidence section per finding, and an optional,
  off-by-default LGPD mapping (`--include-lgpd`). It is deliberately worded as an
  *"Automated & Validated Vulnerability Assessment"*, never as a "pentest" — it
  reflects exactly what the tool does.

## Observability stack (optional)

With the `observability` extra installed, TRACE emits OpenTelemetry traces and
metrics over OTLP — module runs, HTTP requests, findings, wave durations and
errors. The repo ships a `docker-compose.yml` that stands up a local Grafana
stack to receive and visualize them, so you can watch a scan unfold in real time
instead of reading the console.

```bash
docker compose up -d
```

| Service | Port | Role |
|---|---|---|
| Grafana | 3000 | Dashboards / UI — `http://localhost:3000` |
| Grafana Alloy | 4317 (gRPC) · 4318 (HTTP) | OTLP collector — the endpoint TRACE exports to |
| Tempo | 3200 | Distributed-tracing backend (local storage) |
| Loki | 3100 | Logs backend |
| Prometheus | 9090 | Metrics backend |

Alloy receives the OTLP stream on 4317/4318, batches it, and forwards it to
Tempo; Grafana reads from the stack. Telemetry is **privacy-first by default** —
`observability.py` records only low-cardinality operational attributes (host,
scheme, a hashed target id), never full URLs, query strings, headers, cookies
or request/response bodies. It's also a no-op when the OTEL packages aren't
installed or `OTEL_SDK_DISABLED=true` is set.

The stack's config lives at the repo root next to the compose file
(`tempo.yaml`, `prometheus.yml`, `config.alloy`), bind-mounted into each service.

> **Status, stated honestly:** the tracing path (TRACE → Alloy → Tempo, viewed
> in Grafana) is the wired-up one. Prometheus and Loki are included in the stack
> but not yet connected as scrape/query sources — `prometheus.yml` ships with an
> empty `scrape_configs` and Alloy currently routes all OTLP signals to Tempo.
> They're there to grow into, not finished dashboards.

## Known limitations (stated, not hidden)

- Static-HTML parameter discovery (`crawler.py`) does **not** execute
  JavaScript — SPAs need the `js-crawler` extra enabled explicitly.
- The API-based BAC/IDOR modules depend on a registered identity and an OpenAPI
  spec. Without both, they stay correctly **ineligible** rather than producing a
  false "nothing found".
- NVD CVE matching: the matching logic (CPE parsing, version-range comparison,
  deprecated-CPE fallback) is unit-tested as pure logic. Live NVD queries hit the
  public API over the network and need connectivity to run end-to-end — they were
  not exercised against the live API inside the offline dev environment.
- TRACE does not cover complex business logic or chained manual exploitation by a
  human operator — that still requires a specialist. It is triage, not a
  replacement for a pentester.

## Responsible use

For use **only** against targets you own or have explicit, written authorization
to test. TRACE sends real test payloads at the target (it is not passive
reconnaissance); running it without authorization may constitute unauthorized
access to a third party's systems. The intrusive modules are off by default and
require `--confirm-intrusive` precisely so this is a deliberate, owned decision.

## License

Proprietary — see `pyproject.toml`. © Guilherme.
