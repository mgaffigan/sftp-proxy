package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
)

func TestResourceForServiceName(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	resource, err := resourceFor(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := resourceAttribute(resource.Attributes(), "service.name"); got != instrumentationName {
		t.Fatalf("default service.name = %q, want %q", got, instrumentationName)
	}

	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=from-attributes")
	resource, err = resourceFor(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := resourceAttribute(resource.Attributes(), "service.name"); got != "from-attributes" {
		t.Fatalf("resource service.name = %q, want resource attribute", got)
	}

	t.Setenv("OTEL_SERVICE_NAME", "from-service-name")
	resource, err = resourceFor(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := resourceAttribute(resource.Attributes(), "service.name"); got != "from-service-name" {
		t.Fatalf("resource service.name = %q, want OTEL_SERVICE_NAME", got)
	}
}

func TestNewConfiguresTraceContextPropagation(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	previousProvider := otel.GetTracerProvider()
	runtime, err := New(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = runtime.Shutdown(t.Context())
		otel.SetTracerProvider(previousProvider)
	})

	ctx, span := Tracer().Start(context.Background(), "test")
	defer span.End()
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if carrier.Get("traceparent") == "" {
		t.Fatal("configured propagator did not inject traceparent")
	}
}

func resourceAttribute(attributes []attribute.KeyValue, key string) string {
	for _, value := range attributes {
		if string(value.Key) == key {
			return value.Value.AsString()
		}
	}
	return ""
}
