---
jira: NGINXAAS-1315
difficulty: medium
complexity: medium
priority: medium
---

# Plan: NGINXAAS-1315 — nginx-agent: certificate metric exporter (implementation)

## Goal

Add a new OTel receiver to nginx-agent that periodically scrapes certificate
metadata from the NGINX config and emits a gauge metric
`nginx.certificate.time_to_expiration` (TTL in seconds until expiry) with
attributes: `file_path`, `public_key_algorithm`, `serial_number`,
`subject.common_name`, and a resource attribute `instance.id`.

## Architecture Summary

nginx-agent runs an embedded OpenTelemetry Collector
(`internal/collector/otel_collector_plugin.go`). The collector's config is
rendered from a Go template (`internal/collector/otelcol.tmpl`) and written to
disk. Receiver/exporter/processor factories are registered in
`internal/collector/factories.go`.

When the NGINX config changes, the collector plugin receives a
`NginxConfigUpdateTopic` message containing a `*model.NginxConfigContext`. The
plugin inspects this context to dynamically add/update receivers, then restarts
the collector if the config changed.

Certificate files are already discovered during NGINX config parsing in
`internal/datasource/config/nginx_config_parser.go`. The parser handles
`ssl_certificate`, `proxy_ssl_certificate`, `ssl_client_certificate`, and
`ssl_trusted_certificate` directives and adds each cert as a `*mpi.File` with
`CertificateMeta` (containing `SerialNumber`, `PublicKeyAlgorithm`,
`Subject.CommonName`, `Dates.NotAfter`) into `NginxConfigContext.Files`.

### Key architectural decision: self-contained receiver

Unlike the original plan which piped `CertPaths []string` through the config
context and had the receiver read PEM files directly from disk, this
implementation uses a **self-contained receiver**. The receiver:

1. Resolves the agent config on `Start()` to get its own `NginxConfigParser`
   and `NginxService`
2. On each `Scrape()`, looks up the NGINX instance by `instance_id`, re-parses
   the NGINX config, and extracts certificate metadata from `mpi.File` entries
   that have `CertificateMeta` set

This eliminates the need for:
- A `CertPaths` field on `NginxConfigContext`
- Populating cert paths in the config parser
- Passing cert path lists through the receiver config

The trade-off is that each scrape re-parses the NGINX config (same as the
NGINX Plus receiver pattern). The benefit is a simpler data flow with fewer
coupling points.

---

## Changes — ordered by implementation sequence

---

### Change 1: Create the certificate receiver OTel component

Create the directory `internal/collector/certificatereceiver/` with the
following files.

#### `internal/collector/certificatereceiver/metadata.yaml`

```yaml
type: certificate
scope_name: github.com/nginx/agent/v3/internal/collector/certificatereceiver

status:
  class: receiver
  stability:
    beta: [metrics]
  distributions: [contrib]

resource_attributes:
  instance.id:
    description: The nginx instance id.
    type: string
    enabled: true

attributes:
  file_path:
    description: "The full file path of the certificate."
    type: string
  public_key_algorithm:
    description: "The public key algorithm."
    type: string
  serial_number:
    description: "The serial number of the certificate."
    type: string
  subject.common_name:
    description: "The Common Name of the certificate."
    type: string

metrics:
  nginx.certificate.time_to_expiration:
    enabled: true
    description: "The time (in seconds) until an SSL/TLS certificate expires"
    gauge:
      value_type: int
    unit: "seconds"
    attributes:
      - file_path
      - public_key_algorithm
      - serial_number
      - subject.common_name
```

After creating this file, **run the OTel metadata generator**:

```bash
cd internal/collector/certificatereceiver
go generate ./...
```

This produces `internal/metadata/generated_config.go`,
`generated_metrics.go`, `generated_resource.go`, `generated_status.go`,
`generated_config_test.go`, `generated_metrics_test.go`,
`generated_resource_test.go`, and `testdata/config.yaml`.

It also produces package-level `generated_component_test.go` and
`generated_package_test.go` in the receiver package itself.

#### `internal/collector/certificatereceiver/config.go`

```go
package certificatereceiver

import (
	"time"

	"github.com/nginx/agent/v3/internal/collector/certificatereceiver/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
)

const defaultCollectInterval = 10 * time.Second

type Config struct {
	InstanceID                     string                        `mapstructure:"instance_id"`
	MetricsBuilderConfig           metadata.MetricsBuilderConfig `mapstructure:",squash"`
	scraperhelper.ControllerConfig `mapstructure:",squash"`
}

//nolint:ireturn // must return default controller interface
func createDefaultConfig() component.Config {
	cfg := scraperhelper.NewDefaultControllerConfig()
	cfg.CollectionInterval = defaultCollectInterval

	return &Config{
		ControllerConfig:     cfg,
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
	}
}
```

Note: The config only needs `instance_id`. The receiver discovers certificate
files by re-parsing the NGINX config on each scrape — no `cert_paths` field
needed.

#### `internal/collector/certificatereceiver/factory.go`

```go
package certificatereceiver

import (
	"context"
	"errors"

	"github.com/nginx/agent/v3/internal/collector/certificatereceiver/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/scraper"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
)

//nolint:ireturn // must return metrics receiver interface
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithMetrics(createMetricsReceiver, metadata.MetricsStability))
}

//nolint:ireturn // must return metrics receiver interface
func createMetricsReceiver(
	ctx context.Context,
	params receiver.Settings,
	rConf component.Config,
	metricsConsumer consumer.Metrics,
) (receiver.Metrics, error) {
	cfg, ok := rConf.(*Config)
	if !ok {
		return nil, errors.New("failed to cast to Config in certificate metrics receiver")
	}

	cs := newCertificateScraper(params, cfg)
	csMetrics, csMetricsError := scraper.NewMetrics(
		cs.Scrape,
		scraper.WithStart(cs.Start),
		scraper.WithShutdown(cs.Shutdown),
	)
	if csMetricsError != nil {
		return nil, csMetricsError
	}

	return scraperhelper.NewMetricsController(
		&cfg.ControllerConfig,
		params,
		metricsConsumer,
		scraperhelper.AddMetricsScraper(metadata.Type, csMetrics),
	)
}
```

#### `internal/collector/certificatereceiver/scraper.go`

This is the core logic. On each scrape it re-parses the NGINX config and
extracts TTL from `CertificateMeta` on each file.

```go
package certificatereceiver

import (
	"context"
	"time"

	mpi "github.com/nginx/agent/v3/api/grpc/mpi/v1"
	"github.com/nginx/agent/v3/internal/collector/certificatereceiver/internal/metadata"
	"github.com/nginx/agent/v3/internal/config"
	dconfig "github.com/nginx/agent/v3/internal/datasource/config"
	"github.com/nginx/agent/v3/internal/nginx"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
)

type CertificateScraper struct {
	nginxParser  *dconfig.NginxConfigParser
	nginxService *nginx.NginxService
	cfg          *Config
	mb           *metadata.MetricsBuilder
	rb           *metadata.ResourceBuilder
	logger       *zap.Logger
	settings     receiver.Settings
	agentConfig  *config.Config
}

func newCertificateScraper(
	settings receiver.Settings,
	cfg *Config,
) *CertificateScraper {
	logger := settings.Logger
	logger.Info("Creating certificate scraper")
	mb := metadata.NewMetricsBuilder(cfg.MetricsBuilderConfig, settings)
	rb := mb.NewResourceBuilder()

	return &CertificateScraper{
		settings: settings,
		cfg:      cfg,
		mb:       mb,
		rb:       rb,
		logger:   settings.Logger,
	}
}

func (c *CertificateScraper) Start(ctx context.Context, _ component.Host) error {
	if c.agentConfig == nil {
		agentConfig, err := config.ResolveConfig()
		if err != nil {
			c.logger.Warn("Failed to resolve agent config, certificate scraper will not emit metrics",
				zap.Error(err))
			return nil
		}
		c.agentConfig = agentConfig
	}

	c.nginxParser = dconfig.NewNginxConfigParser(c.agentConfig)
	c.nginxService = nginx.NewNginxService(ctx, c.agentConfig)

	return nil
}

func (c *CertificateScraper) Scrape(ctx context.Context) (pmetric.Metrics, error) {
	if c.nginxService == nil || c.nginxParser == nil {
		return pmetric.NewMetrics(), nil
	}

	instance := c.nginxService.Instance(c.cfg.InstanceID)
	if instance == nil {
		c.logger.Warn("no NGINX instance found", zap.String("instance_id", c.cfg.InstanceID))
		return pmetric.NewMetrics(), nil
	}

	nginxConfigContext, err := c.nginxParser.Parse(ctx, instance)
	if err != nil {
		return pmetric.NewMetrics(), err
	}

	c.rb.SetInstanceID(c.cfg.InstanceID)
	c.recordMetrics(nginxConfigContext.Files)

	return c.mb.Emit(metadata.WithResource(c.rb.Emit())), nil
}

func (c *CertificateScraper) Shutdown(ctx context.Context) error {
	return nil
}

func (c *CertificateScraper) recordMetrics(files []*mpi.File) {
	now := pcommon.NewTimestampFromTime(time.Now())

	for _, f := range files {
		if certMeta, ok := f.GetFileMeta().GetFileType().(*mpi.FileMeta_CertificateMeta); ok {
			ttl := time.Until(time.Unix(certMeta.CertificateMeta.GetDates().GetNotAfter(), 0))
			c.mb.RecordNginxCertificateTimeToExpirationDataPoint(
				now,
				int64(ttl.Seconds()),
				f.GetFileMeta().GetName(),
				certMeta.CertificateMeta.GetPublicKeyAlgorithm(),
				certMeta.CertificateMeta.GetSerialNumber(),
				certMeta.CertificateMeta.GetSubject().GetCommonName(),
			)
		}
	}
}
```

**Important notes on `Start()`:**
- The `agentConfig` field allows injection for testing. If nil, `Start()`
  resolves from the system via `config.ResolveConfig()`.
- If config resolution fails (e.g. in test environments), `Start()` logs a
  warning and returns nil. `Scrape()` will gracefully return empty metrics
  when `nginxService`/`nginxParser` are nil.

**Important notes on `RecordNginxCertificateTimeToExpirationDataPoint`:**
- The attribute argument order matches the alphabetical order in
  `metadata.yaml`: `file_path`, `public_key_algorithm`, `serial_number`,
  `subject.common_name`.
- This is determined by mdatagen. After running `go generate`, check the
  generated method signature and adjust calls accordingly.

---

### Change 2: Add `CertificateReceiver` config type

**File:** `internal/config/types.go`

Add a new type after the existing `ContainerMetricsReceiver` type:

```go
CertificateReceiver struct {
    InstanceID         string        `yaml:"instance_id"         mapstructure:"instance_id"`
    CollectionInterval time.Duration `yaml:"collection_interval" mapstructure:"collection_interval"`
}
```

Note: No `CertPaths` field — the receiver discovers certs itself by re-parsing
the NGINX config.

Add a field to the `Receivers` struct, after `NginxPlusReceivers`:

```go
CertificateReceivers []CertificateReceiver `yaml:"-"`
```

`yaml:"-"` is correct — like `NginxReceivers` and `NginxPlusReceivers`, this
is dynamically configured at runtime, not from the static YAML config file.

**Update `AreReceiversConfigured()`** to include `CertificateReceivers`. Add
to the `return` expression:

```go
len(c.Collector.Receivers.CertificateReceivers) > 0
```

---

### Change 3: Register the certificate receiver factory

**File:** `internal/collector/factories.go`

Add the import:
```go
"github.com/nginx/agent/v3/internal/collector/certificatereceiver"
```

Add to the `receiverList` slice in `createReceiverFactories()`:
```go
certificatereceiver.NewFactory(),
```

Update `internal/collector/factories_test.go` — change expected receiver count
from 7 to 8.

---

### Change 4: Wire the certificate receiver into the collector plugin

**File:** `internal/collector/otel_collector_plugin.go`

**4a.** At the end of `checkForNewReceivers()`, before the
`return reloadCollector` statement, add:

```go
if oc.config.IsFeatureEnabled(pkgConfig.FeatureCertificates) {
    reloadCollector = reloadCollector || oc.updateCertificateReceivers(nginxConfigContext)
}
```

**4b.** Add a new method:

```go
func (oc *Collector) updateCertificateReceivers(nginxConfigContext *model.NginxConfigContext) bool {
    for _, certReceiver := range oc.config.Collector.Receivers.CertificateReceivers {
        if certReceiver.InstanceID == nginxConfigContext.InstanceID {
            return false // Already exists
        }
    }

    oc.config.Collector.Receivers.CertificateReceivers = append(
        oc.config.Collector.Receivers.CertificateReceivers,
        config.CertificateReceiver{
            InstanceID:         nginxConfigContext.InstanceID,
            CollectionInterval: defaultCollectionInterval,
        },
    )

    return true
}
```

Note: Unlike the original plan, this method does not track `CertPaths` changes
because the receiver re-discovers certificates on each scrape. The plugin only
needs to ensure one receiver exists per NGINX instance.

---

### Change 5: Add the certificate receiver to the OTel config template

**File:** `internal/collector/otelcol.tmpl`

**5a.** Add a certificate receiver section in the `receivers:` block. Insert
after the `NginxPlusReceivers` range block and before `TcplogReceivers`:

```
{{- range .Receivers.CertificateReceivers }}
{{- if gt (len $.Receivers.CertificateReceivers) 1 }}
  certificate/{{- .InstanceID -}}:
{{- else }}
  certificate:
{{- end}}
    instance_id: "{{- .InstanceID -}}"
    {{- if .CollectionInterval }}
    collection_interval: {{ .CollectionInterval }}
    {{- end }}
{{- end }}
```

**5b.** Update the pipeline guard condition. Add to the `or` chain:

```
(gt (len $.Receivers.CertificateReceivers) 0)
```

**5c.** In `service.pipelines`, in the `nginx_metrics` receiver case, after
the `NginxPlusReceivers` range, add:

```
            {{- range $.Receivers.CertificateReceivers }}
            {{- if gt (len $.Receivers.CertificateReceivers) 1 }}
        - certificate/{{- .InstanceID -}}
            {{- else }}
        - certificate
            {{- end }}
            {{- end }}
```

---

### Change 6: Tests

1. **`internal/collector/certificatereceiver/` generated tests** — these are
   produced by `mdatagen` and test component lifecycle, config deserialization,
   metrics builder, and resource builder. They run automatically.

2. **`internal/collector/otel_collector_plugin_test.go`** — add test cases for
   `updateCertificateReceivers()`:
   - Adding a new certificate receiver (returns `true`)
   - Same instance already registered (returns `false`)
   - Multiple instances registered (second call adds second entry)

3. **`internal/collector/factories_test.go`** — update expected receiver count
   from 7 to 8.

---

## Verification

After implementing all changes:

```bash
# Generate metadata (from repo root)
cd internal/collector/certificatereceiver && go generate ./...

# Build
go build ./...

# Run all unit tests
make test

# Run specific test packages
go test ./internal/collector/certificatereceiver/...
go test ./internal/collector/...
go test ./internal/config/...
```

## Key Reference Files

| File | Why |
|------|-----|
| `internal/collector/certificatereceiver/` | The certificate receiver package |
| `internal/collector/certificatereceiver/metadata.yaml` | OTel metadata defining the metric and attributes |
| `internal/collector/otel_collector_plugin.go` | Where receivers are dynamically wired |
| `internal/collector/otelcol.tmpl` | Go template for OTel YAML config |
| `internal/collector/factories.go` | Where receiver factories are registered |
| `internal/config/types.go` | Agent config type definitions |
| `internal/model/config.go` | NginxConfigContext definition |
| `internal/datasource/config/nginx_config_parser.go` | Where cert files are discovered and CertificateMeta populated |
| `internal/nginx/nginx_service.go` | NginxService used by the scraper to look up instances |
| `api/grpc/mpi/v1/files.pb.go` | Proto: `CertificateMeta`, `FileMeta_CertificateMeta` |
| `pkg/config/features.go` | Feature flag constants (`FeatureCertificates`) |

## Design Decisions

1. **Self-contained receiver.** The receiver resolves the agent config in
   `Start()` and re-parses the NGINX config on each `Scrape()`. This avoids
   threading `CertPaths` through `NginxConfigContext` → collector plugin →
   receiver config → template. The trade-off is a full NGINX config re-parse
   (via `crossplane.Parse()`) on each scrape interval, which is heavier than
   reading only cert files but acceptable at 15s intervals given the simpler
   data flow and fewer coupling points.

2. **Uses existing `CertificateMeta` proto.** Rather than reading PEM files
   from disk and parsing them with `crypto/x509`, the scraper leverages the
   `CertificateMeta` already populated on `mpi.File` entries by the NGINX
   config parser. This reuses existing cert-loading infrastructure
   (`pkg/files/file_helpers.go:FileMetaWithCertificate`). Note: this means
   `NginxConfigParser.Parse()` performs the full config tree traversal
   (including all included files) on each scrape. The design trades I/O
   efficiency for architectural simplicity — no extra `CertPaths` field
   threading or separate cert-only parsing path is needed.

3. **Receiver, not exporter.** Uses a scraper-style OTel receiver (not an
   exporter). The receiver actively polls; it does not passively receive data.
   This matches `hostmetricsreceiver` and `containermetricsreceiver`.

4. **Gate on FeatureCertificates.** The certificate receiver is only created
   when the `certificates` feature flag is active. This is the same flag that
   gates cert metadata collection in the config parser.

5. **TTL can be negative.** Expired certificates produce negative TTL values.
   This is intentional — it tells users how long ago the cert expired.

6. **One receiver per NGINX instance.** Each NGINX instance gets its own
   certificate receiver keyed by `InstanceID`. The plugin only registers a
   receiver once (no updates needed since the receiver re-discovers certs on
   each scrape).

7. **`Start()` returns error on config resolution failure.** If
   `config.ResolveConfig()` fails, `Start()` propagates the error, causing the
   OTel Collector to refuse to start. This surfaces the failure explicitly
   rather than silently degrading to empty metrics forever. For testing, an
   `AgentConfig` field on the receiver's `Config` struct allows injection at
   construction time, bypassing `ResolveConfig()`.

8. **Interface-based dependencies for testability.** The scraper depends on
   `instanceProvider` and `configParser` interfaces (defined in the receiver
   package). In production, these are satisfied by `*nginx.NginxService` and
   `*dconfig.NginxConfigParser`. In tests, lightweight mocks are injected
   directly.

## Differences from Original Plan

| Original plan | This implementation |
|---------------|---------------------|
| Add `CertPaths []string` to `NginxConfigContext` | Not needed — receiver discovers certs itself |
| Populate `CertPaths` in nginx config parser | Not needed |
| `CertificateReceiver` config has `CertPaths []string` | Config only has `InstanceID` + `CollectionInterval` |
| Scraper reads PEM files from disk with `os.ReadFile` + `x509.ParseCertificate` | Scraper uses `CertificateMeta` from already-parsed `mpi.File` entries |
| `updateCertificateReceivers()` diffs `CertPaths` and updates | Only checks existence by `InstanceID`; no path diffing needed |
| Template renders `cert_paths:` list | Template only renders `instance_id` + `collection_interval` |
| Uses `scraper.Settings` | Uses `receiver.Settings` (compatible with factory pattern) |

## Cross-Repository Dependency

The `nginx.certificate.time_to_expiration` metric must be added to the
control-plane repo's ingestion allowlist before it will be visible in Cloud
Monitoring:

**Repo:** `gitlab.com/f5/nginx/one/saas/control-plane`
**File:** `internal/clickhouse-writer/ingested/ingested.yaml`

Without this change, the metric will be silently dropped by `skipMetric()` in
the Kafka consumer. The required entry:

```yaml
metrics:
  nginx.certificate.time_to_expiration:
    instrument: gauge
    enabled: true
    attributes:
      - file_path
      - public_key_algorithm
      - serial_number
      - subject.common_name
```

**Note:** The attribute key names must exactly match what the receiver emits as
OTLP attribute keys (see `metadata.yaml`).
