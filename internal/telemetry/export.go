// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// exportLifetime accounts for synchronous export work, including cancellation
// callbacks. Its zero acknowledgement cannot precede a response-body read.
type exportLifetime struct {
	ctx      context.Context
	mu       sync.Mutex
	inflight int
	zero     chan struct{}
	shutdown chan struct{}
}

func newExportLifetime(ctx context.Context) exportLifetime {
	zero := make(chan struct{})
	close(zero)
	return exportLifetime{ctx: ctx, zero: zero, shutdown: make(chan struct{})}
}

func (l *exportLifetime) begin(ctx context.Context) (context.Context, func(), error) {
	l.mu.Lock()
	if err := l.ctx.Err(); err != nil {
		l.mu.Unlock()
		return nil, nil, err
	}
	if l.inflight == 0 {
		l.zero = make(chan struct{})
	}
	l.inflight++
	l.mu.Unlock()
	child, cancel := context.WithCancel(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(l.ctx, func() {
		cancel()
		close(callbackDone)
	})
	finish := func() {
		if !stop() {
			<-callbackDone
		}
		cancel()
		l.mu.Lock()
		l.inflight--
		if l.inflight == 0 {
			close(l.zero)
		}
		l.mu.Unlock()
	}
	if err := l.ctx.Err(); err != nil {
		finish()
		return nil, nil, err
	}
	return child, finish, nil
}

func (l *exportLifetime) wait(ctx context.Context) error {
	l.mu.Lock()
	zero := l.zero
	l.mu.Unlock()
	for _, ack := range []<-chan struct{}{zero, l.shutdown} {
		select {
		case <-ack:
		case <-ctx.Done():
			return errors.New("telemetry: export shutdown was not acknowledged")
		}
	}
	return nil
}

type resourceSpan struct {
	sdktrace.ReadOnlySpan
	resource *resource.Resource
}

func (s resourceSpan) Resource() *resource.Resource { return s.resource }

type traceDelegate struct {
	life     exportLifetime
	exporter sdktrace.SpanExporter
	resource *resource.Resource
	pending  *atomic.Int64
	failures *atomic.Uint64
}

func (d *traceDelegate) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	ctx, finish, err := d.life.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if len(spans) > 128 {
		return errors.New("telemetry: trace batch exceeds its bound")
	}
	bounded := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, span := range spans {
		bounded[i] = resourceSpan{ReadOnlySpan: span, resource: d.resource}
	}
	err = d.exporter.ExportSpans(ctx, bounded)
	if err != nil {
		d.failures.Add(1)
	} else {
		d.pending.Store(0)
	}
	return err
}

func (d *traceDelegate) Shutdown(ctx context.Context) error {
	err := d.exporter.Shutdown(ctx)
	close(d.life.shutdown)
	return err
}

type metricDelegate struct {
	sdkmetric.Exporter
	life     exportLifetime
	resource *resource.Resource
	failures *atomic.Uint64
}

func (d *metricDelegate) Export(ctx context.Context, input *metricdata.ResourceMetrics) error {
	ctx, finish, err := d.life.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	envelope := *input
	envelope.Resource = d.resource
	if err := d.Exporter.Export(ctx, &envelope); err != nil {
		d.failures.Add(1)
		return err
	}
	return nil
}

func (d *metricDelegate) Shutdown(ctx context.Context) error {
	err := d.Exporter.Shutdown(ctx)
	close(d.life.shutdown)
	return err
}

type generation struct {
	endpoint     string
	traces       *sdktrace.TracerProvider
	meters       *sdkmetric.MeterProvider
	tracer       trace.Tracer
	hold         metric.Float64Histogram
	spanExport   *traceDelegate
	metricExport *metricDelegate
	cancel       context.CancelFunc
	transport    *http.Transport
	closed       atomic.Bool
}

func (c *Controller) newGeneration(ctx context.Context, value string) (*generation, error) {
	e, err := parseEndpoint(value)
	if err != nil || value == "" {
		return nil, err
	}
	client, transport := newHTTPClient(c.cfg.Listeners, c.tlsConfig)
	spanExporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(e.signalURL("traces")),
		otlptracehttp.WithHeaders(map[string]string{}),
		otlptracehttp.WithHTTPClient(client),
		otlptracehttp.WithCompression(otlptracehttp.NoCompression),
		otlptracehttp.WithEncoding(otlptracehttp.EncodingProtobuf),
		otlptracehttp.WithMaxRequestSize(1<<20),
		otlptracehttp.WithMaxResponseSize(64<<10),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: true, InitialInterval: 100 * time.Millisecond, MaxInterval: time.Second, MaxElapsedTime: 5 * time.Second}),
	)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errors.New("telemetry: trace exporter construction failed")
	}
	metricExporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(e.signalURL("metrics")),
		otlpmetrichttp.WithHeaders(map[string]string{}),
		otlpmetrichttp.WithHTTPClient(client),
		otlpmetrichttp.WithCompression(otlpmetrichttp.NoCompression),
		otlpmetrichttp.WithMaxRequestSize(1<<20),
		otlpmetrichttp.WithMaxResponseSize(64<<10),
		otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: true, InitialInterval: 100 * time.Millisecond, MaxInterval: time.Second, MaxElapsedTime: 5 * time.Second}),
	)
	if err != nil {
		_ = spanExporter.Shutdown(ctx)
		transport.CloseIdleConnections()
		return nil, errors.New("telemetry: metric exporter construction failed")
	}
	g, err := c.generationWithExporters(value, spanExporter, metricExporter)
	if err != nil {
		_ = spanExporter.Shutdown(ctx)
		_ = metricExporter.Shutdown(ctx)
		transport.CloseIdleConnections()
		return nil, err
	}
	g.transport = transport
	return g, nil
}

func (c *Controller) generationWithExporters(value string, spans sdktrace.SpanExporter, metrics sdkmetric.Exporter) (*generation, error) {
	version := c.cfg.Version
	if len(version) > 128 {
		version = "unknown"
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", "mitmproxy-go"),
		attribute.String("service.version", version),
		attribute.String("telemetry.sdk.name", "opentelemetry"),
		attribute.String("telemetry.sdk.language", "go"),
		attribute.String("telemetry.sdk.version", otel.Version()),
	)
	genCtx, cancel := context.WithCancel(context.Background())
	g := &generation{endpoint: value, cancel: cancel}
	g.spanExport = &traceDelegate{life: newExportLifetime(genCtx), exporter: spans, resource: res, pending: &c.sinceExport, failures: &c.exportFailures}
	g.metricExport = &metricDelegate{Exporter: metrics, life: newExportLifetime(genCtx), resource: res, failures: &c.exportFailures}
	bsp := sdktrace.NewBatchSpanProcessor(g.spanExport,
		sdktrace.WithMaxQueueSize(1024), sdktrace.WithMaxExportBatchSize(128),
		sdktrace.WithBatchTimeout(time.Second), sdktrace.WithExportTimeout(5*time.Second),
	)
	g.traces = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(bsp), sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{AttributeValueLengthLimit: 256, AttributeValueDepthLimit: 1, AttributeCountLimit: 32, EventCountLimit: 0, LinkCountLimit: 0, AttributePerEventCountLimit: 0, AttributePerLinkCountLimit: 0}),
		sdktrace.WithResource(res),
	)
	g.tracer = g.traces.Tracer("github.com/zchee/mitmproxy-go/internal/telemetry")
	reader := sdkmetric.NewPeriodicReader(g.metricExport, sdkmetric.WithInterval(30*time.Second), sdkmetric.WithTimeout(5*time.Second), sdkmetric.WithMaxExportBatchSize(128))
	g.meters = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res), sdkmetric.WithCardinalityLimit(16))
	var err error
	g.hold, err = c.registerMetrics(g.meters)
	if err != nil {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = g.traces.Shutdown(cleanup)
		_ = g.meters.Shutdown(cleanup)
		return nil, err
	}
	return g, nil
}

func (g *generation) stop(ctx, grace context.Context) error {
	if g == nil {
		return nil
	}
	// Both signals share the same absolute graceful cutoff; cancellation
	// releases active response reads and rejects fresh SDK drain exports.
	_ = g.traces.ForceFlush(grace)
	_ = g.meters.ForceFlush(grace)
	g.cancel()
	traceErr := g.traces.Shutdown(ctx)
	metricErr := g.meters.Shutdown(ctx)
	spanAck := g.spanExport.life.wait(ctx)
	metricAck := g.metricExport.life.wait(ctx)
	if g.transport != nil {
		g.transport.CloseIdleConnections()
	}
	if spanAck != nil || metricAck != nil {
		return errors.Join(spanAck, metricAck, traceErr, metricErr)
	}
	g.closed.Store(true)
	return nil
}
