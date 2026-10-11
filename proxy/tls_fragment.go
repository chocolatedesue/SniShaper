package proxy

import (
	"io"
	"net"
	"time"

	"snishaper/pkg/tlsfrag"
)

// tlsFragmentFirstByteTimeout bounds how long we wait for the upstream's first
// response after sending the fragmented ClientHello before treating it as
// blocked and falling back to direct.
const tlsFragmentFirstByteTimeout = 8 * time.Second

func (p *ProxyServer) handleTLSFragment(clientConn, upstreamConn net.Conn, host, targetAddr string, rule Rule) {
	p.tracef("[TLS-RF] Handling %s via upstream %s", host, rule.Upstream)

	record, err := tlsfrag.ReadInitialTLSRecord(clientConn)
	if err != nil {
		p.tracef("[TLS-RF] Failed to read initial TLS record for %s: %v", host, err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	// SendRecords mutates the record (minor version byte) and may split it.
	// Keep an untouched copy to replay if we must degrade to a direct tunnel.
	pristine := append([]byte(nil), record...)

	_, sniPos, sniLen, _, err := tlsfrag.ParseClientHello(record)
	if err != nil {
		p.tracef("[TLS-RF] Parse ClientHello failed for %s: %v; attempting direct fallback", host, err)
		upstreamConn.Close()
		if p.relayDirectFallback(clientConn, pristine, host, targetAddr, rule, "tls-rf parse client hello failed") {
			return
		}
		clientConn.Close()
		return
	}

	if sniPos <= 0 || sniLen <= 0 {
		if _, err := upstreamConn.Write(record); err != nil {
			p.tracef("[TLS-RF] Initial passthrough write failed for %s: %v", host, err)
			upstreamConn.Close()
			if p.relayDirectFallback(clientConn, pristine, host, targetAddr, rule, "tls-rf passthrough write failed") {
				return
			}
			clientConn.Close()
			return
		}
		p.tracef("[TLS-RF] No SNI in ClientHello for %s, forwarded directly", host)
		p.directTunnel(clientConn, upstreamConn)
		return
	}

	err = tlsfrag.SendRecords(
		upstreamConn,
		record,
		sniPos,
		sniLen,
		tlsfrag.DefaultTLSRFNumRecords,
		tlsfrag.DefaultTLSRFNumSegments,
		tlsfrag.DefaultTLSRFOOB,
		tlsfrag.DefaultTLSRFOOBEx,
		tlsfrag.DefaultTLSRFModMinorVer,
		tlsfrag.DefaultTLSRFSendInterval,
	)
	if err != nil {
		p.tracef("[TLS-RF] Fragmented send failed for %s: %v; attempting direct fallback", host, err)
		upstreamConn.Close()
		if p.relayDirectFallback(clientConn, pristine, host, targetAddr, rule, "tls-rf fragmented send failed") {
			return
		}
		clientConn.Close()
		return
	}

	// Watch the upstream's first response. A middlebox often accepts the
	// fragmented ClientHello and then resets the connection; catching that here
	// lets us replay the untouched ClientHello over a direct connection before
	// the client has seen any server bytes.
	_ = upstreamConn.SetReadDeadline(time.Now().Add(tlsFragmentFirstByteTimeout))
	first := make([]byte, tlsfrag.TlsRecordHeaderLen)
	if _, err := io.ReadFull(upstreamConn, first); err != nil {
		p.tracef("[TLS-RF] Upstream did not answer for %s: %v; attempting direct fallback", host, err)
		upstreamConn.Close()
		if p.relayDirectFallback(clientConn, pristine, host, targetAddr, rule, "tls-rf upstream reset/timeout") {
			return
		}
		clientConn.Close()
		return
	}
	_ = upstreamConn.SetReadDeadline(time.Time{})

	if _, err := clientConn.Write(first); err != nil {
		p.tracef("[TLS-RF] Write first response to client failed for %s: %v", host, err)
		upstreamConn.Close()
		clientConn.Close()
		return
	}

	p.tracef("[TLS-RF] ClientHello sent in original-style fragments for %s", host)
	p.directTunnel(clientConn, upstreamConn)
}
