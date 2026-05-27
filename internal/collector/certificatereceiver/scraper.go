// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.
package certificatereceiver

import (
	"context"
	"time"

	mpi "github.com/nginx/agent/v3/api/grpc/mpi/v1"
	"github.com/nginx/agent/v3/internal/collector/certificatereceiver/internal/metadata"
	dconfig "github.com/nginx/agent/v3/internal/datasource/config"
	"github.com/nginx/agent/v3/internal/nginx"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/nginx/agent/v3/internal/config"
)

type CertificateScraper struct {
	nginxParser  *dconfig.NginxConfigParser
	nginxService *nginx.NginxService
	cfg          *Config
	mb           *metadata.MetricsBuilder
	rb           *metadata.ResourceBuilder
	logger       *zap.Logger
	settings     receiver.Settings
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
	agentConfig, err := config.ResolveConfig()
	if err != nil {
		return err
	}
	nginxParser := dconfig.NewNginxConfigParser(agentConfig)
	nginxSvc := nginx.NewNginxService(ctx, agentConfig)
	c.nginxParser = nginxParser
	c.nginxService = nginxSvc

	return nil
}

func (c *CertificateScraper) Scrape(ctx context.Context) (pmetric.Metrics, error) {
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
				certMeta.CertificateMeta.GetSubject().GetCommonName(),
				f.GetFileMeta().GetName(),
			)
		}
	}
}
