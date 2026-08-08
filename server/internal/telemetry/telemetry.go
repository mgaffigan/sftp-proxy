// Package telemetry configures the process-wide trace export pipeline.
package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const instrumentationName = "sftp-proxy"

// Runtime owns the trace provider used by the proxy. Call Shutdown before the
// process exits to flush completed spans.
type Runtime struct {
	provider *sdktrace.TracerProvider
	once     sync.Once
	err      error
}

// New configures trace export from standard OpenTelemetry environment
// variables. When OTEL_TRACES_EXPORTER is unset, spans are exported to stdout.
func New(ctx context.Context) (*Runtime, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	exporter, err := newExporter(ctx)
	if err != nil {
		return nil, err
	}

	resource, err := resourceFor(ctx)
	if err != nil {
		return nil, err
	}
	options := []sdktrace.TracerProviderOption{sdktrace.WithResource(resource)}
	if exporter != nil {
		options = append(options, sdktrace.WithBatcher(exporter))
	}
	provider := sdktrace.NewTracerProvider(options...)
	otel.SetTracerProvider(provider)
	return &Runtime{provider: provider}, nil
}

func newExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	switch strings.ToLower(os.Getenv("OTEL_TRACES_EXPORTER")) {
	case "", "console":
		return stdouttrace.New()
	case "none":
		return nil, nil
	case "otlp":
		if protocol := otlpProtocol(); protocol != "" && protocol != "http/protobuf" {
			return nil, fmt.Errorf("OTLP trace protocol %q is not supported; use http/protobuf", protocol)
		}
		return otlptracehttp.New(ctx)
	default:
		return nil, fmt.Errorf("OTEL_TRACES_EXPORTER %q is not supported", os.Getenv("OTEL_TRACES_EXPORTER"))
	}
}

func otlpProtocol() string {
	if protocol := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"); protocol != "" {
		return strings.ToLower(protocol)
	}
	return strings.ToLower(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"))
}

// Tracer returns the application tracer from the configured global provider.
func Tracer() trace.Tracer {
	return otel.Tracer(instrumentationName)
}

// NewHTTPClient copies client with an otelhttp transport unless it is already
// instrumented. The copy retains the caller's cookie jar and transport settings.
func NewHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	if _, ok := copy.Transport.(*otelhttp.Transport); !ok {
		copy.Transport = otelhttp.NewTransport(copy.Transport)
	}
	return &copy
}

func resourceFor(ctx context.Context) (*sdkresource.Resource, error) {
	resource, err := sdkresource.New(ctx,
		sdkresource.WithFromEnv(),
		sdkresource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, err
	}
	for _, value := range resource.Attributes() {
		if value.Key == attribute.Key("service.name") {
			return resource, nil
		}
	}
	return sdkresource.Merge(resource, sdkresource.NewSchemaless(attribute.String("service.name", instrumentationName)))
}

// Shutdown flushes the provider once. Subsequent calls return the first result.
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.once.Do(func() {
		r.err = r.provider.Shutdown(ctx)
	})
	return r.err
}
