// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configtls // import "go.opentelemetry.io/collector/config/configtls"

import "crypto/tls"

// tlsCurve associates the name accepted in `curve_preferences` with its
// crypto/tls identifier.
type tlsCurve struct {
	name string
	id   tls.CurveID
}

// curveIDForName resolves a name from `curve_preferences` to its tls.CurveID.
func curveIDForName(name string) (tls.CurveID, bool) {
	for _, curve := range tlsCurves {
		if curve.name == name {
			return curve.id, true
		}
	}
	return 0, false
}

// allowedCurveIDs returns the supported curve IDs in preference order.
func allowedCurveIDs() []tls.CurveID {
	ids := make([]tls.CurveID, 0, len(tlsCurves))
	for _, curve := range tlsCurves {
		ids = append(ids, curve.id)
	}
	return ids
}

// allowedCurveNames returns the names accepted in `curve_preferences`, in
// preference order. Used to build the error message for an unknown name, so it
// must report the configuration names rather than the tls.CurveID strings
// (which differ: "P256" vs "CurveP256").
func allowedCurveNames() []string {
	names := make([]string, 0, len(tlsCurves))
	for _, curve := range tlsCurves {
		names = append(names, curve.name)
	}
	return names
}
