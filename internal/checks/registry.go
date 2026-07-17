package checks

import "github.com/JosephITA/flyingfish/internal/engine"

// All returns the full passive check catalog in layer order.
func All() []engine.Check {
	var out []engine.Check
	out = append(out, envChecks()...)
	out = append(out, apiChecks()...)
	out = append(out, gatewayChecks()...)
	out = append(out, tunnelChecks()...)
	out = append(out, fabricChecks()...)
	out = append(out, ipamChecks()...)
	out = append(out, cniChecks()...)
	out = append(out, reflectionChecks()...)
	out = append(out, offloadingUsageChecks()...)
	return out
}
