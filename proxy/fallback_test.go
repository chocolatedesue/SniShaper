package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"snishaper/pkg/tlsfrag"
)

func TestDirectFallbackConfigDefaultsToEnabled(t *testing.T) {
	var cfg DirectFallbackConfig
	if !cfg.IsEnabled() {
		t.Fatal("direct fallback must default to enabled when the field is absent")
	}

	disabled := false
	cfg.Enabled = &disabled
	if cfg.IsEnabled() {
		t.Fatal("direct fallback must be disabled when explicitly set to false")
	}
}

func TestDirectFallbackRuleDropsEvasionKeepsTransport(t *testing.T) {
	orig := Rule{
		Mode:               "mitm",
		Enabled:            true,
		Domain:             "x.example",
		Upstream:           "1.2.3.4",
		Upstreams:          []string{"5.6.7.8"},
		ECHEnabled:         true,
		ECHProfileID:       "legacy-cloudflare",
		ECHDiscoveryDomain: "crypto.cloudflare.com",
		UseCFPool:          true,
		SniFake:            "fake.example",
		SniPolicy:          "fake",
		DNSMode:            "prefer_ipv4",
		NAT64Enabled:       true,
		NAT64ProfileID:     "nat64-1",
	}

	got := directFallbackRule(orig)

	if got.Mode != "direct" || !got.Enabled {
		t.Fatalf("unexpected mode/enabled: %+v", got)
	}
	if got.Upstream != "" || len(got.Upstreams) != 0 || got.UseCFPool || got.ECHEnabled ||
		got.ECHProfileID != "" || got.ECHDiscoveryDomain != "" || got.SniFake != "" || got.SniPolicy != "" {
		t.Fatalf("evasion fields must be dropped: %+v", got)
	}
	if got.DNSMode != "prefer_ipv4" || !got.NAT64Enabled || got.NAT64ProfileID != "nat64-1" {
		t.Fatalf("transport fields must be preserved: %+v", got)
	}
}

// startEchoListener starts a TCP server that echoes everything back.
func startEchoListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln
}

func TestFallbackDialToDirectConnectsToRealTarget(t *testing.T) {
	ln := startEchoListener(t)

	// listenAddr must differ from the target so isSelfTarget does not veto the dial.
	p := &ProxyServer{listenAddr: "127.0.0.1:1"}

	cr := &connectResult{
		effectiveMode: "mitm",
		targetHost:    "127.0.0.1",
		targetAddr:    ln.Addr().String(),
		rule: Rule{
			Mode:       "mitm",
			Upstream:   "10.0.0.1",
			UseCFPool:  true,
			ECHEnabled: true,
			SniFake:    "fake.example",
		},
	}

	if !p.fallbackDialToDirect(cr, "test") {
		t.Fatal("fallbackDialToDirect returned false")
	}
	if cr.effectiveMode != "direct" {
		t.Fatalf("effectiveMode = %q, want direct", cr.effectiveMode)
	}
	if cr.conn == nil {
		t.Fatal("fallback did not produce a connection")
	}
	defer cr.conn.Close()
	if cr.rule.Upstream != "" || cr.rule.ECHEnabled || cr.rule.UseCFPool {
		t.Fatalf("fallback rule still carries evasion fields: %+v", cr.rule)
	}

	if _, err := cr.conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	_ = cr.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cr.conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
}

func TestRelayDirectFallbackReplaysAndTunnels(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	upstreamGot := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		upstreamGot <- string(buf)
		_, _ = conn.Write([]byte("pong"))
		_, _ = io.Copy(io.Discard, conn)
	}()

	// serverSide plays the role of the hijacked client connection.
	clientSide, serverSide := net.Pipe()

	p := &ProxyServer{listenAddr: "127.0.0.1:1"}
	done := make(chan bool, 1)
	go func() {
		done <- p.relayDirectFallback(serverSide, []byte("hello"), "127.0.0.1", ln.Addr().String(), Rule{Mode: "tls-rf"}, "test")
	}()

	buf := make([]byte, 4)
	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read from upstream through tunnel: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("tunnel carried %q, want pong", buf)
	}

	_ = clientSide.Close()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("relayDirectFallback returned false")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relayDirectFallback did not return")
	}

	if got := <-upstreamGot; got != "hello" {
		t.Fatalf("upstream received %q, want the replayed ClientHello bytes", got)
	}
}

func TestParseClientHelloALPN(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	go func() {
		cfg := &tls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}
		// Handshake blocks waiting for a ServerHello we never send; the
		// ClientHello is written first, which is all the test needs.
		_ = tls.Client(clientPipe, cfg).Handshake()
	}()

	_ = serverPipe.SetReadDeadline(time.Now().Add(2 * time.Second))
	record, err := tlsfrag.ReadInitialTLSRecord(serverPipe)
	if err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}

	alpn := tlsfrag.ParseClientHelloALPN(record)
	if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Fatalf("ALPN = %v, want [h2 http/1.1]", alpn)
	}
}

func TestAutoRouterDirectPreferredPin(t *testing.T) {
	ar := NewAutoRouter(AutoRoutingConfig{Mode: AutoRoutingDefault}, nil)
	defer ar.Stop()

	if ar.IsDirectPreferred("example.com") {
		t.Fatal("host should not be pinned before any fallback")
	}

	ar.MarkDirectPreferred("Example.COM")
	if !ar.IsDirectPreferred("example.com") {
		t.Fatal("pin lookup should be case-insensitive")
	}
	if r := ar.Decide("example.com"); r.Mode != "direct" {
		t.Fatalf("pinned host routed as %q, want direct", r.Mode)
	}
}

func TestAutoRouterGetDirectPreferredHosts(t *testing.T) {
	ar := NewAutoRouter(AutoRoutingConfig{Mode: AutoRoutingDefault}, nil)
	defer ar.Stop()

	ar.MarkDirectPreferred("beta.com")
	ar.MarkDirectPreferred("alpha.com")

	hosts := ar.GetDirectPreferredHosts()
	if len(hosts) != 2 || hosts[0] != "alpha.com" || hosts[1] != "beta.com" {
		t.Fatalf("GetDirectPreferredHosts = %v, want sorted [alpha.com beta.com]", hosts)
	}
}

func TestFallbackStatsTracking(t *testing.T) {
	p := &ProxyServer{listenAddr: "127.0.0.1:1"}
	rm := &RuleManager{}
	ar := NewAutoRouter(AutoRoutingConfig{Mode: AutoRoutingDefault}, nil)
	defer ar.Stop()
	rm.autoRouter = ar
	p.rules = rm

	// Record fallbacks
	p.noteFallback("site-a.com", Rule{AutoRouted: true}, "upstream dial failed")
	p.noteFallback("site-b.com", Rule{AutoRouted: true}, "mitm upstream handshake failed")
	p.noteFallback("site-c.com", Rule{AutoRouted: true}, "upstream dial failed")

	stats := p.GetFallbackStats()
	if stats.TotalCount != 3 {
		t.Fatalf("TotalCount = %d, want 3", stats.TotalCount)
	}
	if stats.ByReason["upstream dial failed"] != 2 {
		t.Fatalf("upstream dial failed count = %d, want 2", stats.ByReason["upstream dial failed"])
	}
	if stats.ByReason["mitm upstream handshake failed"] != 1 {
		t.Fatalf("mitm count = %d, want 1", stats.ByReason["mitm upstream handshake failed"])
	}
	if len(stats.RecentEvents) != 3 {
		t.Fatalf("RecentEvents len = %d, want 3", len(stats.RecentEvents))
	}
	if stats.RecentEvents[0].Host != "site-a.com" {
		t.Fatalf("RecentEvents[0].Host = %q, want site-a.com", stats.RecentEvents[0].Host)
	}
	if len(stats.DirectPreferred) != 3 {
		t.Fatalf("DirectPreferred len = %d, want 3", len(stats.DirectPreferred))
	}

	// Test ring buffer bound
	for i := 0; i < 60; i++ {
		p.noteFallback("batch.example", Rule{AutoRouted: false}, "test")
	}
	stats2 := p.GetFallbackStats()
	if stats2.TotalCount != 63 {
		t.Fatalf("TotalCount = %d, want 63", stats2.TotalCount)
	}
	if len(stats2.RecentEvents) > 50 {
		t.Fatalf("RecentEvents exceeds capacity 50: %d", len(stats2.RecentEvents))
	}

	p.ClearFallbackStats()
	cleared := p.GetFallbackStats()
	if cleared.TotalCount != 0 || len(cleared.RecentEvents) != 0 {
		t.Fatalf("cleared stats not empty: %+v", cleared)
	}
}
