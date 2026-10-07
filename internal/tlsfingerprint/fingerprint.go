// Package tlsfingerprint replays the stock client's TLS ClientHello so
// the wire-level TLS fingerprint (JA3/JA4) matches Qt 5.15 + OpenSSL 1.1.1.
//
// clienthello.bin is a verbatim ClientHello captured from /usr/bin/BenshuPlayer
// dialing the production server (tcpdump, 2026-10-30). The spec is imported
// via uTLS's FromRaw — no hand-written parameter lists that can drift.
//
// Captured fingerprint:
//
//	JA3 = 0303,4866,4867,4865,...,0-11-10-35-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2
//	supported_versions: TLS1.3 + TLS1.2, no ALPN (HTTP/1.1 only)
package tlsfingerprint

import (
	"context"
	"crypto/x509"
	_ "embed"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

//go:embed clienthello.bin
var rawHello []byte

// Spec returns the ClientHelloSpec parsed from the captured ClientHello.
// The capture's SNI (benshulinux.org) is KEPT as a placeholder — uTLS
// sources the wire SNI from the spec's SNIExtension, so callers must
// overwrite it per connection (see DialTLSContext). The extension ORDER
// (SNI first) matches the real client.
func Spec() (*utls.ClientHelloSpec, error) {
	spec := &utls.ClientHelloSpec{}
	// bluntMimicry=true: unsupported extensions are kept verbatim (RawExtension)
	// instead of failing the import — the whole point is byte-exact replay.
	if err := spec.FromRaw(rawHello, true); err != nil {
		return nil, fmt.Errorf("tlsfingerprint: FromRaw: %w", err)
	}
	return spec, nil
}

// DialTLS opens a raw TCP connection to addr and completes the uTLS
// handshake with the captured fingerprint, returning the live connection.
// Used by the login chain, which writes its requests byte-for-byte (header
// order + Connection: Keep-Alive) to match the stock client exactly.
func DialTLS(serverName, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tconn, err := HandshakeTLS(conn, serverName)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tconn, nil
}

// HandshakeTLS wraps an existing (possibly tunneled) connection with the
// captured uTLS fingerprint.
func HandshakeTLS(conn net.Conn, serverName string) (net.Conn, error) {
	spec, err := Spec()
	if err != nil {
		return nil, err
	}
	for _, ext := range spec.Extensions {
		if sni, ok := ext.(*utls.SNIExtension); ok {
			sni.ServerName = serverName
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, &utls.Config{
		ServerName: serverName,
		RootCAs:    roots,
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("tlsfingerprint: ApplyPreset: %w", err)
	}
	if err := uconn.Handshake(); err != nil {
		return nil, err
	}
	return uconn, nil
}

// DialTLSContext returns a net.Dialer-compatible dial function that
// completes a uTLS handshake with the captured fingerprint. Every
// connection uses serverName as SNI — this client speaks to ONE server,
// so a per-transport constant is exact (mirrors how QNetworkAccessManager
// targets one host). roots may be nil (system pool).
func DialTLSContext(serverName string, roots *x509.CertPool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		spec, err := Spec()
		if err != nil {
			conn.Close()
			return nil, err
		}
		// overwrite the captured SNI placeholder with this connection's target
		for _, ext := range spec.Extensions {
			if sni, ok := ext.(*utls.SNIExtension); ok {
				sni.ServerName = serverName
			}
		}
		if roots == nil {
			if roots, err = x509.SystemCertPool(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("tlsfingerprint: system cert pool: %w", err)
			}
		}
		uconn := utls.UClient(conn, &utls.Config{
			ServerName: serverName,
			RootCAs:    roots,
		}, utls.HelloCustom)
		if err := uconn.ApplyPreset(spec); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tlsfingerprint: ApplyPreset: %w", err)
		}
		if err := uconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return uconn, nil
	}
}
