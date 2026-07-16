package netutil

import (
	"errors"
	"net"
	"syscall"
	"time"
)

// UDPProbeState classifies what a UDP probe observed. Open UDP ports are
// silent by nature, so "silent" is inconclusive (open-or-filtered), while an
// ICMP port-unreachable surfaces as ECONNREFUSED and is a hard "refused".
type UDPProbeState string

const (
	UDPResponded UDPProbeState = "responded"
	UDPRefused   UDPProbeState = "refused"
	UDPSilent    UDPProbeState = "silent"
	UDPError     UDPProbeState = "error"
)

// ProbeUDP sends a few datagrams to addr ("ip:port") on a connected UDP
// socket and reports what came back. WireGuard drops packets that fail
// cryptographic validation without replying, so UDPSilent is the expected
// healthy answer for a Liqo gateway; UDPRefused proves the port is closed.
func ProbeUDP(addr string, timeout time.Duration) (UDPProbeState, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return UDPError, err
	}
	defer conn.Close()

	payload := []byte("flyingfish-udp-probe")
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	for i := 0; i < 3; i++ {
		if _, err := conn.Write(payload); err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				return UDPRefused, nil
			}
			return UDPError, err
		}
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(timeout / 3))
		if _, err := conn.Read(buf); err == nil {
			return UDPResponded, nil
		} else if errors.Is(err, syscall.ECONNREFUSED) {
			return UDPRefused, nil
		}
	}
	return UDPSilent, nil
}
