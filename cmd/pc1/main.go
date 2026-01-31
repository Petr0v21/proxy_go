package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"tunnel-proxy/tunnel"
)

var (
	activeMux atomic.Value // *tunnel.ServerMux
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	go runTunnelServer(":9000")

	go runHTTPProxy("127.0.0.1:8080")
	go runSOCKS5("127.0.0.1:1080")

	select {}
}

func runTunnelServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("tunnel listen error: %v", err)
	}
	log.Printf("Tunnel server listening on %s", addr)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("tunnel accept error: %v", err)
			continue
		}
		// Replace active agent connection (lab: only one)
		if v := activeMux.Load(); v != nil {
			_ = v.(*tunnel.ServerMux).Close()
		}
		m := tunnel.NewServerMux(c)
		activeMux.Store(m)
		log.Printf("Agent connected from %s", c.RemoteAddr())
	}
}

func getMux() (*tunnel.ServerMux, error) {
	v := activeMux.Load()
	if v == nil {
		return nil, errors.New("no agent connected")
	}
	m := v.(*tunnel.ServerMux)
	if !m.Alive() {
		return nil, errors.New("agent not alive")
	}
	return m, nil
}

// -------------------- HTTP CONNECT proxy --------------------

func runHTTPProxy(addr string) {
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           http.HandlerFunc(httpHandler),
	}
	log.Printf("HTTP CONNECT proxy on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Only CONNECT is supported in this lab proxy", http.StatusMethodNotAllowed)
		return
	}

	mux, err := getMux()
	if err != nil {
		http.Error(w, "No agent connected", http.StatusServiceUnavailable)
		return
	}

	target := r.Host // host:port
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	up, err := mux.Dial(ctx, target)
	if err != nil {
		http.Error(w, "Dial via agent failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer up.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(up, clientConn); errCh <- e }()
	go func() { _, e := io.Copy(clientConn, up); errCh <- e }()
	<-errCh
}

// -------------------- SOCKS5 proxy (no auth, CONNECT only) --------------------

func runSOCKS5(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("socks listen error: %v", err)
	}
	log.Printf("SOCKS5 proxy on %s", addr)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("socks accept error: %v", err)
			continue
		}
		go handleSocksConn(c)
	}
}

func handleSocksConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(c)

	// Greeting: VER, NMETHODS, METHODS
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		return
	}
	if h[0] != 0x05 {
		return
	}
	n := int(h[1])
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// Choose no-auth if offered
	chosen := byte(0xFF)
	for _, m := range methods {
		if m == 0x00 {
			chosen = 0x00
			break
		}
	}
	_, _ = c.Write([]byte{0x05, chosen})
	if chosen == 0xFF {
		return
	}

	// Request: VER, CMD, RSV, ATYP
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	cmd := req[1]
	atyp := req[3]
	if cmd != 0x01 {
		_ = socksReply(c, 0x07) // Command not supported
		return
	}

	host, port, err := socksReadAddr(br, atyp)
	if err != nil {
		_ = socksReply(c, 0x08)
		return
	}

	mux, err := getMux()
	if err != nil {
		_ = socksReply(c, 0x01)
		return
	}

	target := net.JoinHostPort(host, port)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	up, err := mux.Dial(ctx, target)
	if err != nil {
		_ = socksReply(c, 0x04) // Host unreachable (approx)
		return
	}
	defer up.Close()

	_ = c.SetDeadline(time.Time{})

	// Success reply: VER REP RSV ATYP BND.ADDR BND.PORT (we send 0.0.0.0:0)
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(up, c); errCh <- e }()
	go func() { _, e := io.Copy(c, up); errCh <- e }()
	<-errCh
}

func socksReply(c net.Conn, rep byte) error {
	// Minimal: 0.0.0.0:0
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func socksReadAddr(r *bufio.Reader, atyp byte) (host string, port string, err error) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // DOMAIN
		l, e := r.ReadByte()
		if e != nil {
			return "", "", e
		}
		b := make([]byte, int(l))
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	default:
		return "", "", errors.New("unsupported atyp")
	}

	pb := make([]byte, 2)
	if _, err = io.ReadFull(r, pb); err != nil {
		return
	}
	p := binary.BigEndian.Uint16(pb)
	port = fmt.Sprintf("%d", p)

	// Trim IPv6 zone if any (safety)
	host = strings.TrimSpace(host)
	return
}
