// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build requirefips

package configtls

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTLSCurves pins both the contents and the order of the allowlist. The
// order matters because it is used verbatim as tls.Config.CurvePreferences
// when `curve_preferences` is not set.
func TestTLSCurves(t *testing.T) {
	assert.Equal(t, []tlsCurve{
		{"P256", tls.CurveP256},
		{"P384", tls.CurveP384},
		{"P521", tls.CurveP521},
	}, tlsCurves)
}

// The X25519 curves are not available under FIPS, so they must not resolve.
func TestCurveIDForNameX25519Unavailable(t *testing.T) {
	for _, name := range []string{"X25519", "X25519MLKEM768"} {
		t.Run(name, func(t *testing.T) {
			_, ok := curveIDForName(name)
			assert.False(t, ok)
		})
	}
}
