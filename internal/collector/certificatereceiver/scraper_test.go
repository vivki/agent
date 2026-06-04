// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.
package certificatereceiver

import (
	"context"
	"testing"
	"time"

	mpi "github.com/nginx/agent/v3/api/grpc/mpi/v1"
	"github.com/nginx/agent/v3/internal/collector/certificatereceiver/internal/metadata"
	"github.com/nginx/agent/v3/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

// mockInstanceProvider implements instanceProvider for testing.
type mockInstanceProvider struct {
	instances map[string]*mpi.Instance
}

func (m *mockInstanceProvider) Instance(instanceID string) *mpi.Instance {
	return m.instances[instanceID]
}

// mockConfigParser implements configParser for testing.
type mockConfigParser struct {
	result *model.NginxConfigContext
	err    error
}

func (m *mockConfigParser) Parse(_ context.Context, _ *mpi.Instance) (*model.NginxConfigContext, error) {
	return m.result, m.err
}

func newTestScraper(t *testing.T, cfg *Config) *CertificateScraper {
	t.Helper()
	settings := receivertest.NewNopSettings(component.MustNewType("certificate"))

	return newCertificateScraper(settings, cfg)
}

func TestScrape_FutureExpiry(t *testing.T) {
	futureTime := time.Now().Add(30 * 24 * time.Hour) // 30 days from now

	files := []*mpi.File{
		{
			FileMeta: &mpi.FileMeta{
				Name: "/etc/nginx/ssl/server.crt",
				FileType: &mpi.FileMeta_CertificateMeta{
					CertificateMeta: &mpi.CertificateMeta{
						SerialNumber:       "ABC123",
						PublicKeyAlgorithm: "RSA",
						Subject:            &mpi.X509Name{CommonName: "example.com"},
						Dates:              &mpi.CertificateDates{NotAfter: futureTime.Unix()},
					},
				},
			},
		},
	}

	cfg := &Config{
		InstanceID:           "test-instance",
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
	}
	scraper := newTestScraper(t, cfg)
	scraper.instanceProv = &mockInstanceProvider{
		instances: map[string]*mpi.Instance{
			"test-instance": {InstanceMeta: &mpi.InstanceMeta{InstanceId: "test-instance"}},
		},
	}
	scraper.parser = &mockConfigParser{
		result: &model.NginxConfigContext{
			InstanceID: "test-instance",
			Files:      files,
		},
	}

	metrics, err := scraper.Scrape(context.Background())
	require.NoError(t, err)

	require.Equal(t, 1, metrics.ResourceMetrics().Len())
	rm := metrics.ResourceMetrics().At(0)

	// Verify resource attribute
	instanceID, ok := rm.Resource().Attributes().Get("instance.id")
	require.True(t, ok)
	assert.Equal(t, "test-instance", instanceID.AsString())

	// Verify metric
	require.Equal(t, 1, rm.ScopeMetrics().Len())
	ms := rm.ScopeMetrics().At(0).Metrics()
	require.Equal(t, 1, ms.Len())
	assert.Equal(t, "nginx.certificate.time_to_expiration", ms.At(0).Name())

	dp := ms.At(0).Gauge().DataPoints().At(0)
	ttl := dp.IntValue()
	assert.Positive(t, ttl, "TTL should be positive for future expiry")

	// Verify attributes
	filePath, ok := dp.Attributes().Get("file_path")
	require.True(t, ok)
	assert.Equal(t, "/etc/nginx/ssl/server.crt", filePath.AsString())

	pubKeyAlgo, ok := dp.Attributes().Get("public_key_algorithm")
	require.True(t, ok)
	assert.Equal(t, "RSA", pubKeyAlgo.AsString())

	serialNum, ok := dp.Attributes().Get("serial_number")
	require.True(t, ok)
	assert.Equal(t, "ABC123", serialNum.AsString())

	commonName, ok := dp.Attributes().Get("subject.common_name")
	require.True(t, ok)
	assert.Equal(t, "example.com", commonName.AsString())
}

func TestScrape_ExpiredCert(t *testing.T) {
	pastTime := time.Now().Add(-7 * 24 * time.Hour) // 7 days ago

	files := []*mpi.File{
		{
			FileMeta: &mpi.FileMeta{
				Name: "/etc/nginx/ssl/expired.crt",
				FileType: &mpi.FileMeta_CertificateMeta{
					CertificateMeta: &mpi.CertificateMeta{
						SerialNumber:       "EXPIRED001",
						PublicKeyAlgorithm: "ECDSA",
						Subject:            &mpi.X509Name{CommonName: "expired.example.com"},
						Dates:              &mpi.CertificateDates{NotAfter: pastTime.Unix()},
					},
				},
			},
		},
	}

	cfg := &Config{
		InstanceID:           "test-instance",
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
	}
	scraper := newTestScraper(t, cfg)
	scraper.instanceProv = &mockInstanceProvider{
		instances: map[string]*mpi.Instance{
			"test-instance": {InstanceMeta: &mpi.InstanceMeta{InstanceId: "test-instance"}},
		},
	}
	scraper.parser = &mockConfigParser{
		result: &model.NginxConfigContext{
			InstanceID: "test-instance",
			Files:      files,
		},
	}

	metrics, err := scraper.Scrape(context.Background())
	require.NoError(t, err)

	require.Equal(t, 1, metrics.ResourceMetrics().Len())
	dp := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0)
	assert.Negative(t, dp.IntValue(), "TTL should be negative for expired cert")
}

func TestScrape_NonCertFileSkipped(t *testing.T) {
	files := []*mpi.File{
		{
			FileMeta: &mpi.FileMeta{
				Name:     "/etc/nginx/nginx.conf",
				FileType: nil, // not a certificate
			},
		},
		{
			FileMeta: &mpi.FileMeta{
				Name: "/etc/nginx/ssl/server.crt",
				FileType: &mpi.FileMeta_CertificateMeta{
					CertificateMeta: &mpi.CertificateMeta{
						SerialNumber:       "VALID001",
						PublicKeyAlgorithm: "RSA",
						Subject:            &mpi.X509Name{CommonName: "valid.example.com"},
						Dates:              &mpi.CertificateDates{NotAfter: time.Now().Add(time.Hour).Unix()},
					},
				},
			},
		},
	}

	cfg := &Config{
		InstanceID:           "test-instance",
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
	}
	scraper := newTestScraper(t, cfg)
	scraper.instanceProv = &mockInstanceProvider{
		instances: map[string]*mpi.Instance{
			"test-instance": {InstanceMeta: &mpi.InstanceMeta{InstanceId: "test-instance"}},
		},
	}
	scraper.parser = &mockConfigParser{
		result: &model.NginxConfigContext{
			InstanceID: "test-instance",
			Files:      files,
		},
	}

	metrics, err := scraper.Scrape(context.Background())
	require.NoError(t, err)

	// Only the cert file should produce a data point
	require.Equal(t, 1, metrics.ResourceMetrics().Len())
	ms := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 1, ms.Len())
	assert.Equal(t, 1, ms.At(0).Gauge().DataPoints().Len())
}

func TestScrape_MultipleCerts(t *testing.T) {
	files := []*mpi.File{
		{
			FileMeta: &mpi.FileMeta{
				Name: "/etc/nginx/ssl/cert1.crt",
				FileType: &mpi.FileMeta_CertificateMeta{
					CertificateMeta: &mpi.CertificateMeta{
						SerialNumber:       "CERT1",
						PublicKeyAlgorithm: "RSA",
						Subject:            &mpi.X509Name{CommonName: "one.example.com"},
						Dates:              &mpi.CertificateDates{NotAfter: time.Now().Add(10 * 24 * time.Hour).Unix()},
					},
				},
			},
		},
		{
			FileMeta: &mpi.FileMeta{
				Name: "/etc/nginx/ssl/cert2.crt",
				FileType: &mpi.FileMeta_CertificateMeta{
					CertificateMeta: &mpi.CertificateMeta{
						SerialNumber:       "CERT2",
						PublicKeyAlgorithm: "ECDSA",
						Subject:            &mpi.X509Name{CommonName: "two.example.com"},
						Dates:              &mpi.CertificateDates{NotAfter: time.Now().Add(60 * 24 * time.Hour).Unix()},
					},
				},
			},
		},
	}

	cfg := &Config{
		InstanceID:           "test-instance",
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
	}
	scraper := newTestScraper(t, cfg)
	scraper.instanceProv = &mockInstanceProvider{
		instances: map[string]*mpi.Instance{
			"test-instance": {InstanceMeta: &mpi.InstanceMeta{InstanceId: "test-instance"}},
		},
	}
	scraper.parser = &mockConfigParser{
		result: &model.NginxConfigContext{
			InstanceID: "test-instance",
			Files:      files,
		},
	}

	metrics, err := scraper.Scrape(context.Background())
	require.NoError(t, err)

	require.Equal(t, 1, metrics.ResourceMetrics().Len())
	ms := metrics.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 1, ms.Len())
	assert.Equal(t, 2, ms.At(0).Gauge().DataPoints().Len(), "Should emit one data point per certificate")
}

func TestScrape_NilInstanceProvider(t *testing.T) {
	cfg := &Config{
		InstanceID:           "test-instance",
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
	}
	scraper := newTestScraper(t, cfg)
	// instanceProv and parser are nil (Start() was never called)

	metrics, err := scraper.Scrape(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, metrics.ResourceMetrics().Len(), "Should return empty metrics when not initialized")
}

func TestScrape_InstanceNotFound(t *testing.T) {
	cfg := &Config{
		InstanceID:           "nonexistent-instance",
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
	}
	scraper := newTestScraper(t, cfg)
	scraper.instanceProv = &mockInstanceProvider{
		instances: make(map[string]*mpi.Instance), // empty
	}
	scraper.parser = &mockConfigParser{}

	metrics, err := scraper.Scrape(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, metrics.ResourceMetrics().Len(), "Should return empty metrics when instance not found")
}
