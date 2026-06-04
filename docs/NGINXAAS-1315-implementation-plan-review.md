# Code Review: NGINXAAS-1315 Implementation Plan

This document contains a review of the implementation plan for NGINXAAS-1315
("nginx-agent: add certificate metric exporter"). Address all **Critical** and
**Bug** items before beginning implementation. **Medium** and **Minor** items
should be resolved or explicitly accepted as known trade-offs.

---

## Overall Verdict

The "self-contained receiver" design is architecturally sound and the OTel
patterns are correct. All API references were verified against the actual
codebase. However, there are two critical gaps and several bugs that must be
fixed before execution.

---

## Critical Issues (blockers)

### 1. Missing control-plane `ingested.yaml` change

The plan has no mention of
`internal/clickhouse-writer/ingested/ingested.yaml` in the
**control-plane repo** (`gitlab.com/f5/nginx/one/saas/control-plane`).

Without adding `nginx.certificate.time_to_expiration` to the ingestion
allowlist, the metric will be **silently dropped** by `skipMetric()` in the
control-plane Kafka consumer before it ever reaches ClickHouse or Cloud
Monitoring. This directly blocks the acceptance criterion "metrics are visible
in cloud monitoring."

**Required addition to `internal/clickhouse-writer/ingested/ingested.yaml`:**

```yaml
attributes:
  # Add these new attribute keys (if not already present):
  ssl.certificate.file_path:
    type: string
  ssl.certificate.public_key_algorithm:
    type: string
  ssl.certificate.serial_number:
    type: string
  ssl.certificate.subject.common_name:
    type: string

metrics:
  nginx.certificate.time_to_expiration:
    instrument: gauge
    enabled: true
    attributes:
      - ssl.certificate.file_path
      - ssl.certificate.public_key_algorithm
      - ssl.certificate.serial_number
      - ssl.certificate.subject.common_name
```

**Note:** The attribute key names above must exactly match what `metadata.yaml`
emits as OTLP attribute keys. Verify the generated attribute names from
`mdatagen` before adding them here.

---

### 2. No unit tests for the scraper's business logic

Change 6 only lists mdatagen-generated lifecycle tests and
`otel_collector_plugin_test.go`. There are **no tests for `Scrape()` or
`recordMetrics()`** — the core logic of the receiver.

The established pattern is in `internal/collector/nginxplusreceiver/scraper_test.go`:
mock server → `Start()` → `Scrape()` → golden-file comparison using
`go.opentelemetry.io/collector/pkg/golden` and
`go.opentelemetry.io/collector/pkg/pdatatest/pmetrictest`.

**Required test cases for `certificatereceiver/scraper_test.go`:**

- Certificate with future `NotAfter` → emits positive TTL, correct attribute values
- Certificate with past `NotAfter` (expired) → emits negative TTL
- `mpi.File` entry without `CertificateMeta` set → skipped, no data point emitted
- Multiple cert files in one config → one data point per cert
- `nginxService` is `nil` (e.g., `Start()` was not called) → returns empty
  `pmetric.Metrics`, no error

Because the scraper depends on `NginxService` and `NginxConfigParser` (which
call into real NGINX parsing), use interface mocks for both. The
`ConfigParser` interface already exists in
`internal/datasource/config/nginx_config_parser.go`. Check whether
`NginxService` also has an interface; if not, introduce one or use a struct
with an injectable method.

---

## Bugs

### 3. Default collection interval is 10s; JIRA requires 15s

`config.go` sets:
```go
const defaultCollectInterval = 10 * time.Second
```

The JIRA acceptance criteria says **"every 15 seconds."** Change to:
```go
const defaultCollectInterval = 15 * time.Second
```

Also note: `defaultCollectionInterval` in `otel_collector_plugin.go` is
`1 * time.Minute`. `updateCertificateReceivers()` passes this value to the new
receiver's `CollectionInterval` field. The receiver's own `Config` default
(from `createDefaultConfig()`) takes effect when OTel parses the YAML — verify
which value wins when both are set.

### 4. Wrong UCUM unit in `metadata.yaml`

```yaml
unit: "seconds"   # ← wrong
```

OTel uses UCUM unit codes. The correct value for seconds is `"s"`. Change to:

```yaml
unit: "s"
```

Using `"seconds"` is non-standard and may cause metric validation failures or
warnings in downstream OTel pipelines.

---

## Medium Issues (should fix or explicitly accept)

### 5. Silent failure in `Start()` masks production errors

If `config.ResolveConfig()` fails, `Start()` logs a warning and returns `nil`.
`Scrape()` then silently returns empty metrics indefinitely with no further
indication of failure.

The established pattern in the agent is to return an error from `Start()` when
initialization fails — this causes the OTel Collector to refuse to start and
surfaces the failure explicitly to the operator.

**Recommendation:** Return the error from `Start()` unless silent degradation
is explicitly required (e.g., the component is optional and the rest of the
collector should continue). Document the choice either way.

### 6. "Avoids file I/O" claim in Design Decision 2 is inaccurate

Design Decision 2 states the self-contained approach "avoids duplicate file
I/O." This is misleading. `NginxConfigParser.Parse()` calls `crossplane.Parse()`
which reads the entire NGINX config tree — including all included files and the
cert files (to populate `CertificateMeta`). The per-scrape I/O cost is
**higher** than the original plan (cert files only), not lower.

The self-contained approach is still defensible on simplicity grounds (fewer
coupling points, no `CertPaths` field threading), but Design Decision 2 should
be rewritten to reflect the actual trade-off: simpler data flow at the cost of
a full NGINX config re-parse on each scrape interval.

---

## Minor Issues

### 7. Template naming: verify single vs. multi-instance receiver naming

The template uses `certificate:` (no ID suffix) when there is only one
receiver, and `certificate/<id>:` for multiple. This matches the existing
`nginxreceiver`/`nginxplusreceiver` pattern — but verify before assuming.

The risk: if a second NGINX instance is added later, the OTel component ID for
the first instance changes from `certificate` to `certificate/<id>`, which
changes metric labels. Confirm this is acceptable (it is the existing behavior
for nginx receivers) and matches the template pattern precisely.

### 8. `config.ResolveConfig()` called at `Start()` time

Calling `ResolveConfig()` inside an OTel receiver's `Start()` method couples
the receiver's lifecycle to the agent's config file system at startup. If the
agent config changes after `Start()`, the scraper won't pick it up. Consider
passing `*config.Config` to the receiver at construction time (via the `Config`
struct or via a constructor parameter), which is more testable and more
consistent with how other receivers receive their dependencies. If `Start()`
injection is intentional (e.g., to avoid config being resolved before the file
is written), document why.

---

## Verified-Correct Items

The following were checked against the actual nginx-agent codebase
(project ID: 26945533) and are accurate:

| Claim | Status |
|-------|--------|
| `config.ResolveConfig() (*Config, error)` exists | ✅ |
| `NginxService.Instance(string) *mpi.Instance` exists | ✅ |
| `NginxConfigParser.Parse(ctx, *mpi.Instance) (*model.NginxConfigContext, error)` exists | ✅ |
| `*mpi.FileMeta_CertificateMeta` type assertion is correct (`oneof file_type { CertificateMeta certificate_meta = 6; }`) | ✅ |
| `GetDates().GetNotAfter()` returns `int64` (Unix seconds); `time.Unix(notAfter, 0)` is correct | ✅ |
| `scraperhelper.AddMetricsScraper` is the correct API at v0.150.0 | ✅ |
| `scraper.NewMetrics(cs.Scrape, scraper.WithStart(...), scraper.WithShutdown(...))` matches confirmed factory pattern | ✅ |
| Factory pattern matches `nginxplusreceiver` | ✅ |

---

## Required Changes Summary

| # | Severity | Action |
|---|----------|--------|
| 1 | **Critical** | Add `nginx.certificate.time_to_expiration` + attribute keys to `internal/clickhouse-writer/ingested/ingested.yaml` in the control-plane repo |
| 2 | **Critical** | Add `scraper_test.go` with business-logic tests for `Scrape()` and `recordMetrics()` |
| 3 | **Bug** | Change `defaultCollectInterval` to `15 * time.Second` |
| 4 | **Bug** | Change `unit: "seconds"` to `unit: "s"` in `metadata.yaml` |
| 5 | **Medium** | Decide on `Start()` error handling: propagate error vs. silent degradation; document the choice |
| 6 | **Medium** | Rewrite Design Decision 2 to accurately describe the I/O trade-off |
| 7 | **Minor** | Verify single/multi-instance receiver naming in template matches existing nginx receiver pattern |
| 8 | **Minor** | Consider passing `*config.Config` at construction rather than calling `ResolveConfig()` at `Start()` |
