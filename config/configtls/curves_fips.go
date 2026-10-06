// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build requirefips

package configtls // import "go.opentelemetry.io/collector/config/configtls"

import "crypto/tls"

// tlsCurves lists the supported key exchange mechanisms in preference order.
// The order mirrors crypto/tls defaultCurvePreferences so that leaving
// `curve_preferences` unset matches Go's own default ordering.
var tlsCurves = []tlsCurve{
	// The following X25519 curves are not available in FIPS mode, so we remove them from the slice.
	// See also https://cs.opensource.google/go/go/+/refs/tags/go1.24.6:src/crypto/ecdh/x25519.go
	//{"X25519MLKEM768", tls.X25519MLKEM768},
	//{"X25519", tls.X25519},

	{"P256", tls.CurveP256},
	{"P384", tls.CurveP384},
	{"P521", tls.CurveP521},
}
