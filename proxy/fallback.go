package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// FallbackEvent records a single direct fallback degradation.
type FallbackEvent struct {
	Host      string    `json:"host"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// FallbackStats provides observability into fallback activity.
type FallbackStats struct {
	TotalCount      int64            `json:"total_count"`
	ByReason        map[string]int64 `json:"by_reason"`
	RecentEvents    []FallbackEvent  `json:"recent_events"`
	DirectPreferred []string         `json:"direct_preferred"`
}

type fallbackTracker struct {
	mu           sync.RWMutex
	totalCount   int64
	byReason     map[string]int64
	recentEvents []FallbackEvent
}

func (t *fallbackTracker) record(host, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totalCount++
	if t.byReason == nil {
		t.byReason = make(map[string]int64)
	}
	t.byReason[reason]++
	t.recentEvents = append(t.recentEvents, FallbackEvent{
		Host:      host,
		Reason:    reason,
		Timestamp: time.Now(),
	})
	if len(t.recentEvents) > 50 {
		t.recentEvents = t.recentEvents[len(t.recentEvents)-50:]
	}
}

func (t *fallbackTracker) stats() FallbackStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	byReasonCopy := make(map[string]int64, len(t.byReason))
	for k, v := range t.byReason {
		byReasonCopy[k] = v
	}
	recentCopy := make([]FallbackEvent, len(t.recentEvents))
	copy(recentCopy, t.recentEvents)
	return FallbackStats{
		TotalCount:   t.totalCount,
		ByReason:     byReasonCopy,
		RecentEvents: recentCopy,
	}
}

func (t *fallbackTracker) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totalCount = 0
	t.byReason = make(map[string]int64)
	t.recentEvents = nil
}

// DirectFallbackConfig controls the "degrade to plain direct connection"
// behaviour. It is persisted inside settings.json under the "direct_fallback"
// key. When the field is absent the behaviour defaults to enabled, so existing
// installations get the fix without a migration step.
type DirectFallbackConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// IsEnabled reports whether direct fallback is active (default: true).
func (c DirectFallbackConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// directFallbackRule derives a rule that performs a plain, unmodified
// connection to the real target:
//
//   - no upstream / upstream list (so buildDialCandidates resolves the target
//     host itself instead of an SNI-spoofing relay),
//   - no CF preferred-IP pool,
//   - no ECH, no fake SNI, no SNI policy, no MITM cert verification override.
//
// NAT64 is preserved because it is a transport-layer concern of the local
// network, not part of the upstream evasion strategy.
func directFallbackRule(orig Rule) Rule {
	return Rule{
		Mode:           "direct",
		Enabled:        true,
		DNSMode:        orig.DNSMode,
		NAT64Enabled:   orig.NAT64Enabled,
		NAT64ProfileID: orig.NAT64ProfileID,
	}
}

func (p *ProxyServer) directFallbackEnabled() bool {
	p.mu.RLock()
	rm := p.rules
	p.mu.RUnlock()
	if rm == nil {
		return true
	}
	return rm.GetDirectFallbackConfig().IsEnabled()
}

// GetFallbackStats returns current telemetry and pinned direct-preferred hosts.
func (p *ProxyServer) GetFallbackStats() FallbackStats {
	stats := p.fallbackTracker.stats()
	p.mu.RLock()
	rm := p.rules
	p.mu.RUnlock()
	if rm != nil {
		if ar := rm.GetAutoRouter(); ar != nil {
			stats.DirectPreferred = ar.GetDirectPreferredHosts()
		}
	}
	return stats
}

// ClearFallbackStats resets the accumulated fallback counters and history.
func (p *ProxyServer) ClearFallbackStats() {
	p.fallbackTracker.clear()
}

// dialDirectFallback opens a plain TCP connection to the real target host.
// It returns the connection and the address that succeeded.
func (p *ProxyServer) dialDirectFallback(targetHost, targetAddr string, rule Rule) (net.Conn, string, error) {
	directRule := directFallbackRule(rule)

	port := portFromTargetAddr(targetAddr)
	if port == "" {
		port = "443"
	}
	realAddr := ensureAddrWithPort(targetHost, port)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	candidates := p.buildDialCandidates(ctx, normalizeHost(targetHost), realAddr, directRule, "direct")
	if len(candidates) == 0 {
		candidates = []string{realAddr}
	}

	var lastErr error
	for _, addr := range candidates {
		dialCtx, dialCancel := context.WithTimeout(ctx, 8*time.Second)
		conn, err := p.dialWithRule(dialCtx, "tcp", addr, directRule)
		dialCancel()
		if err == nil {
			return conn, addr, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no direct dial candidates")
	}
	return nil, "", lastErr
}

// noteFallback records a successful degradation and feeds the auto-router's
// "direct preferred" memory so that a misjudged auto-routed domain is not
// retried through the failing strategy on every request.
func (p *ProxyServer) noteFallback(host string, rule Rule, reason string) {
	p.tracef("[Fallback] %s -> direct (%s)", host, reason)
	p.fallbackTracker.record(host, reason)

	p.mu.RLock()
	rm := p.rules
	p.mu.RUnlock()
	if rm == nil {
		return
	}
	rm.emitRouteEvent(host, "fallback:direct")
	if rule.AutoRouted {
		if ar := rm.GetAutoRouter(); ar != nil {
			ar.MarkDirectPreferred(host)
		}
	}
}

// fallbackDialToDirect rewrites a connectResult whose upstream dial failed so
// that it carries a plain direct connection instead. It is used before any
// bytes have been exchanged with the client, so the switch is invisible.
func (p *ProxyServer) fallbackDialToDirect(cr *connectResult, reason string) bool {
	if cr == nil || !p.directFallbackEnabled() {
		return false
	}
	if cr.effectiveMode == "direct" {
		return false
	}

	conn, addr, err := p.dialDirectFallback(cr.targetHost, cr.targetAddr, cr.rule)
	if err != nil {
		p.tracef("[Fallback] direct dial for %s failed: %v", cr.targetHost, err)
		return false
	}

	p.noteFallback(cr.targetHost, cr.rule, reason)
	cr.effectiveMode = "direct"
	cr.rule = directFallbackRule(cr.rule)
	cr.conn = conn
	cr.dialAddr = addr
	cr.dialCandidates = []string{addr}
	return true
}

// relayDirectFallback dials the real target directly and replays the bytes the
// caller already consumed from the client (normally the ClientHello), then
// relays the rest of the connection untouched. It is used after a strategy
// (MITM / TLS-RF) has failed at setup time but before any server response has
// reached the client, so the browser still sees an ordinary direct TLS session.
func (p *ProxyServer) relayDirectFallback(clientConn net.Conn, replay []byte, host, targetAddr string, rule Rule, reason string) bool {
	if !p.directFallbackEnabled() {
		return false
	}

	conn, addr, err := p.dialDirectFallback(host, targetAddr, rule)
	if err != nil {
		p.tracef("[Fallback] direct dial for %s failed: %v", host, err)
		return false
	}

	if len(replay) > 0 {
		if _, err := conn.Write(replay); err != nil {
			conn.Close()
			p.tracef("[Fallback] replay to %s failed: %v", addr, err)
			return false
		}
	}

	p.noteFallback(host, rule, reason)
	p.tracef("[Fallback] %s: degraded to direct via %s", host, addr)
	p.directTunnel(clientConn, conn)
	return true
}
