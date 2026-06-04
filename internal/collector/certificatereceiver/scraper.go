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
	"github.com/nginx/agent/v3/internal/model"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/nginx/agent/v3/internal/config"
	dconfig "github.com/nginx/agent/v3/internal/datasource/config"
	"github.com/nginx/agent/v3/internal/nginx"
)

// instanceProvider returns an NGINX instance by ID.
type instanceProvider interface {
	Instance(instanceID string) *mpi.Instance
}

// configParser parses an NGINX instance's configuration.
type configParser interface {
	Parse(ctx context.Context, instance *mpi.Instance) (*model.NginxConfigContext, error)
}

type CertificateScraper struct {
	instanceProv instanceProvider
	parser       configParser
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
		if c.cfg.AgentConfig != nil {
			c.agentConfig = c.cfg.AgentConfig
		} else {
			agentConfig, err := config.ResolveConfig()
			if err != nil {
				return err
			}
			c.agentConfig = agentConfig
		}
	}

	if c.parser == nil {
		c.parser = dconfig.NewNginxConfigParser(c.agentConfig)
	}
	if c.instanceProv == nil {
		c.instanceProv = nginx.NewNginxService(ctx, c.agentConfig)
	}

	return nil
}

func (c *CertificateScraper) Scrape(ctx context.Context) (pmetric.Metrics, error) {
	if c.instanceProv == nil || c.parser == nil {
		return pmetric.NewMetrics(), nil
	}

	instance := c.instanceProv.Instance(c.cfg.InstanceID)
	if instance == nil {
		c.logger.Warn("no NGINX instance found", zap.String("instance_id", c.cfg.InstanceID))
		return pmetric.NewMetrics(), nil
	}

	nginxConfigContext, err := c.parser.Parse(ctx, instance)
	if err != nil {
		return pmetric.NewMetrics(), err
	}

	c.rb.SetInstanceID(c.cfg.InstanceID)
	c.recordMetrics(nginxConfigContext.Files)

	return c.mb.Emit(metadata.WithResource(c.rb.Emit())), nil
}

func (c *CertificateScraper) Shutdown(_ context.Context) error {
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
