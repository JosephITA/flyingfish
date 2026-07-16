// Package netutil holds small networking helpers used by the checks:
// CIDR overlap math, private-address heuristics, and defensive extraction of
// CIDR-shaped strings from unstructured Liqo resources (schemas drift between
// minors, so we grep values rather than hardcode field paths — spec §8).
package netutil

import (
	"fmt"
	"net"
	"regexp"
)

var cidrRe = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b`)

// Overlaps reports whether two IPv4 CIDRs intersect.
func Overlaps(a, b string) bool {
	_, na, errA := net.ParseCIDR(a)
	_, nb, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return false
	}
	return na.Contains(nb.IP) || nb.Contains(na.IP)
}

// Contains reports whether ip falls inside cidr.
func Contains(cidr, ip string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ip)
	return parsed != nil && n.Contains(parsed)
}

// IsPrivate reports whether the address is RFC1918/link-local (or a name we
// cannot parse, which we treat as public since LB hostnames are common).
func IsPrivate(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()
}

// ExtractCIDRs walks an arbitrary decoded-JSON value and collects every
// CIDR-shaped string found under it.
func ExtractCIDRs(v any) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			for _, m := range cidrRe.FindAllString(t, -1) {
				if _, _, err := net.ParseCIDR(m); err == nil && !seen[m] {
					seen[m] = true
					out = append(out, m)
				}
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// FirstOverlap returns the first pair (a ∈ as, b ∈ bs) that overlaps.
func FirstOverlap(as, bs []string) (string, string, bool) {
	for _, a := range as {
		for _, b := range bs {
			if Overlaps(a, b) {
				return a, b, true
			}
		}
	}
	return "", "", false
}

// HumanList formats a small string list for evidence lines.
func HumanList(label string, items []string) string {
	if len(items) == 0 {
		return label + ": (none)"
	}
	return fmt.Sprintf("%s: %v", label, items)
}
