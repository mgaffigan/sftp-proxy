// Package headers carries the attribution one connection stamps on everything
// done on its user's behalf: the headers of every request the HTTP backend
// makes, and the user metadata of every object the S3 backend stores.
//
// It is deliberately only a carrier. What a user who states none is attributed
// by is config's to decide, and where the values go on the wire is each
// backend's; this package exists so that neither has to import the other, and
// so that vfs — which knows nothing of any storage protocol — does not have to
// carry a value only storage protocols read.
package headers

import (
	"context"
	"maps"
)

type key struct{}

// With returns a context carrying stamp. The map is copied, so a later change
// to the caller's cannot reach a request already in flight.
func With(ctx context.Context, stamp map[string]string) context.Context {
	if len(stamp) == 0 {
		return ctx
	}
	return context.WithValue(ctx, key{}, maps.Clone(stamp))
}

// From reports what ctx carries, or nil when it carries nothing. The map is
// shared by every request made under ctx and must not be modified.
func From(ctx context.Context) map[string]string {
	stamp, _ := ctx.Value(key{}).(map[string]string)
	return stamp
}
