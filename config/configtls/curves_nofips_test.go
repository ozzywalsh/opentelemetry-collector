// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !requirefips

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
		{"X25519MLKEM768", tls.X25519MLKEM768},
		{"SecP256r1MLKEM768", tls.SecP256r1MLKEM768},
		{"SecP384r1MLKEM1024", tls.SecP384r1MLKEM1024},
		{"X25519", tls.X25519},
		{"P256", tls.CurveP256},
		{"P384", tls.CurveP384},
		{"P521", tls.CurveP521},
	}, tlsCurves)
}

func TestCurveIDForNamePostQuantum(t *testing.T) {
	tests := []struct {
		name     string
		expected tls.CurveID
	}{
		{"X25519MLKEM768", tls.X25519MLKEM768},
		{"SecP256r1MLKEM768", tls.SecP256r1MLKEM768},
		{"SecP384r1MLKEM1024", tls.SecP384r1MLKEM1024},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			curveID, ok := curveIDForName(test.name)
			require := assert.New(t)
			require.True(ok)
			require.Equal(test.expected, curveID)
		})
	}
}
